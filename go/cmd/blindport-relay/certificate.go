package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/blindport/blindport/internal/relayauth"
)

type certificateFetcher interface {
	FetchRelayCert(context.Context, []string, []string) (*relayauth.RelayCert, error)
}

type certificateManager struct {
	fetcher certificateFetcher
	hosts   []string
	ips     []string
	log     *slog.Logger
	health  *relayHealth
	current atomic.Pointer[tls.Certificate]
	caRaw   []byte
	caPool  *x509.CertPool
}

func newCertificateManager(ctx context.Context, fetcher certificateFetcher, hosts, ips []string, health *relayHealth, log *slog.Logger) (*certificateManager, error) {
	if len(hosts) == 0 && len(ips) == 0 {
		return nil, fmt.Errorf("no hostnames or IPs given for relay server certificate")
	}
	m := &certificateManager{fetcher: fetcher, hosts: hosts, ips: ips, health: health, log: log}
	issued, err := fetcher.FetchRelayCert(ctx, hosts, ips)
	health.observeAuth(err)
	if err != nil {
		return nil, fmt.Errorf("fetch relay certificate: %w", err)
	}
	cert, ca, pool, err := validateCertificateResponse(issued, hosts, ips, nil, time.Now())
	if err != nil {
		return nil, err
	}
	m.current.Store(cert)
	m.caRaw = ca
	m.caPool = pool
	health.certExpiry.Store(cert.Leaf.NotAfter.Unix())
	return m, nil
}

func (m *certificateManager) tlsConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert := m.current.Load()
			if cert == nil {
				return nil, fmt.Errorf("relay server certificate unavailable")
			}
			return cert, nil
		},
		ClientCAs:  m.caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}
}

func (m *certificateManager) run(ctx context.Context) {
	backoff := time.Second
	for {
		cert := m.current.Load()
		renewAt := cert.Leaf.NotBefore.Add(cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore) * 2 / 3)
		wait := time.Until(renewAt)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		for {
			var next *tls.Certificate
			issued, err := m.fetcher.FetchRelayCert(ctx, m.hosts, m.ips)
			m.health.observeAuth(err)
			if err == nil {
				next, err = validateRenewedCertificateResponse(issued, m.hosts, m.ips, m.caRaw, cert, time.Now())
			}
			if err == nil {
				m.current.Store(next)
				m.health.certExpiry.Store(next.Leaf.NotAfter.Unix())
				m.health.observeAuth(nil)
				m.log.Info("relay server certificate renewed", "not_after", next.Leaf.NotAfter)
				backoff = time.Second
				break
			}
			m.health.observeAuth(err)
			m.log.Warn("relay server certificate renewal failed", "err", err)
			if !sleepContext(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, time.Hour)
		}
	}
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func validateCertificateResponse(response *relayauth.RelayCert, hosts, ips []string, expectedCA []byte, now time.Time) (*tls.Certificate, []byte, *x509.CertPool, error) {
	if response == nil {
		return nil, nil, nil, fmt.Errorf("certificate response is empty")
	}
	caBlock, rest := pem.Decode([]byte(response.CACertPEM))
	if caBlock == nil || caBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, nil, fmt.Errorf("CA response must contain exactly one certificate")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !ca.IsCA {
		return nil, nil, nil, fmt.Errorf("CA response certificate is not a CA")
	}
	if expectedCA != nil && !bytes.Equal(expectedCA, ca.Raw) {
		return nil, nil, nil, fmt.Errorf("relay certificate authority changed")
	}

	pair, err := tls.X509KeyPair([]byte(response.ServerCertPEM), []byte(response.ServerKeyPEM))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load relay X.509 keypair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, nil, nil, fmt.Errorf("relay certificate chain is empty")
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse relay leaf certificate: %w", err)
	}
	if now.Before(pair.Leaf.NotBefore) || !now.Before(pair.Leaf.NotAfter) {
		return nil, nil, nil, fmt.Errorf("relay leaf certificate is not currently valid")
	}
	metadataExpiry, err := time.Parse(time.RFC3339, response.NotAfter)
	if err != nil || !metadataExpiry.Equal(pair.Leaf.NotAfter) {
		return nil, nil, nil, fmt.Errorf("relay certificate expiry metadata does not match leaf")
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	intermediates := x509.NewCertPool()
	for _, raw := range pair.Certificate[1:] {
		certificate, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil {
			return nil, nil, nil, fmt.Errorf("parse relay certificate chain: %w", parseErr)
		}
		intermediates.AddCert(certificate)
	}
	if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: now}); err != nil {
		return nil, nil, nil, fmt.Errorf("verify relay certificate chain: %w", err)
	}
	for _, host := range hosts {
		if err := pair.Leaf.VerifyHostname(host); err != nil {
			return nil, nil, nil, fmt.Errorf("verify relay certificate hostname %q: %w", host, err)
		}
	}
	for _, rawIP := range ips {
		ip := net.ParseIP(rawIP)
		if ip == nil {
			return nil, nil, nil, fmt.Errorf("invalid requested certificate IP %q", rawIP)
		}
		if err := pair.Leaf.VerifyHostname(ip.String()); err != nil {
			return nil, nil, nil, fmt.Errorf("verify relay certificate IP %q: %w", rawIP, err)
		}
	}
	return &pair, ca.Raw, roots, nil
}

func validateRenewedCertificateResponse(response *relayauth.RelayCert, hosts, ips []string, expectedCA []byte, current *tls.Certificate, now time.Time) (*tls.Certificate, error) {
	next, _, _, err := validateCertificateResponse(response, hosts, ips, expectedCA, now)
	if err != nil {
		return nil, err
	}
	if current == nil || current.Leaf == nil {
		return nil, fmt.Errorf("current relay certificate is unavailable")
	}
	if !next.Leaf.NotAfter.After(current.Leaf.NotAfter) {
		return nil, fmt.Errorf("renewed relay certificate does not extend expiry beyond %s", current.Leaf.NotAfter)
	}
	return next, nil
}
