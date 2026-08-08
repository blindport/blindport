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
	cache   *certificateCache
	log     *slog.Logger
	health  *relayHealth
	current atomic.Pointer[tls.Certificate]
	caRaw   []byte
	caPool  *x509.CertPool
}

func newCertificateManager(ctx context.Context, fetcher certificateFetcher, hosts, ips []string, cacheDir string, health *relayHealth, log *slog.Logger) (*certificateManager, error) {
	canonicalHosts, canonicalIPs, err := canonicalCertificateIdentities(hosts, ips)
	if err != nil {
		return nil, err
	}
	m := &certificateManager{
		fetcher: fetcher, hosts: canonicalHosts, ips: canonicalIPs, cache: newCertificateCache(cacheDir), health: health, log: log,
	}
	issued, fetchErr := fetcher.FetchRelayCert(ctx, canonicalHosts, canonicalIPs)
	if fetchErr != nil {
		health.observeAuth(fetchErr)
		if !relayauth.IsKind(fetchErr, relayauth.ErrorInfrastructure) || m.cache == nil {
			return nil, fmt.Errorf("fetch relay certificate: %w", fetchErr)
		}
		cached, cacheErr := m.cache.load(canonicalHosts, canonicalIPs, time.Now())
		if cacheErr != nil {
			return nil, fmt.Errorf("fetch relay certificate: %v; load certificate cache: %w", fetchErr, cacheErr)
		}
		m.current.Store(cached.cert)
		m.caRaw = cached.ca
		m.caPool = cached.pool
		health.certExpiry.Store(cached.cert.Leaf.NotAfter.Unix())
		log.Warn("relay certificate backend unavailable; using cached certificate")
		return m, nil
	}
	cert, ca, pool, err := validateCertificateResponse(issued, canonicalHosts, canonicalIPs, nil, time.Now())
	if err != nil {
		return nil, err
	}
	if m.cache != nil {
		if err := m.cache.store(issued, canonicalHosts, canonicalIPs, time.Now()); err != nil {
			return nil, fmt.Errorf("persist relay certificate cache: %w", err)
		}
	}
	m.current.Store(cert)
	m.caRaw = ca
	m.caPool = pool
	health.certExpiry.Store(cert.Leaf.NotAfter.Unix())
	health.observeAuth(nil)
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
			if err == nil {
				next, err = validateRenewedCertificateResponse(issued, m.hosts, m.ips, m.caRaw, cert, time.Now())
			}
			if err == nil && m.cache != nil {
				err = m.cache.store(issued, m.hosts, m.ips, time.Now())
				if err != nil {
					err = fmt.Errorf("persist relay certificate cache: %w", err)
				}
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
			m.log.Warn("relay server certificate renewal failed")
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
	canonicalHosts, canonicalIPs, err := canonicalCertificateIdentities(hosts, ips)
	if err != nil {
		return nil, nil, nil, err
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
	if pair.Leaf.IsCA {
		return nil, nil, nil, fmt.Errorf("relay leaf certificate must not be a CA")
	}
	if len(pair.Leaf.EmailAddresses) != 0 || len(pair.Leaf.URIs) != 0 {
		return nil, nil, nil, fmt.Errorf("relay leaf certificate must not contain email or URI SANs")
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
	leafHosts, leafIPs, err := canonicalCertificateIdentities(pair.Leaf.DNSNames, certificateIPs(pair.Leaf.IPAddresses))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("canonicalize relay certificate SANs: %w", err)
	}
	if !equalStrings(leafHosts, canonicalHosts) || !equalStrings(leafIPs, canonicalIPs) {
		return nil, nil, nil, fmt.Errorf("relay certificate SANs do not exactly match requested identities")
	}
	return &pair, ca.Raw, roots, nil
}

func certificateIPs(ips []net.IP) []string {
	values := make([]string, 0, len(ips))
	for _, ip := range ips {
		values = append(values, ip.String())
	}
	return values
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
