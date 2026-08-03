package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/relayauth"
)

type testRelayCA struct {
	key  ed25519.PrivateKey
	cert *x509.Certificate
	pem  string
}

func newTestRelayCA(t *testing.T, serial int64) *testRelayCA {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "relay test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testRelayCA{key: key, cert: certificate, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (ca *testRelayCA) issue(t *testing.T, serial int64, hosts, ips []string, notAfter time.Time) *relayauth.RelayCert {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: hosts[0]},
		NotBefore: now.Add(-time.Hour), NotAfter: notAfter.UTC().Truncate(time.Second),
		DNSNames: hosts, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, raw := range ips {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP(raw))
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, public, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return &relayauth.RelayCert{
		CACertPEM:     ca.pem,
		ServerCertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		ServerKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		NotAfter:      template.NotAfter.Format(time.RFC3339),
	}
}

func TestValidateCertificateResponseChecksSANExpiryAndCA(t *testing.T) {
	ca := newTestRelayCA(t, 1)
	now := time.Now().UTC().Truncate(time.Second)
	response := ca.issue(t, 2, []string{"relay.example"}, []string{"203.0.113.10"}, now.Add(time.Hour))
	pair, rawCA, _, err := validateCertificateResponse(response, []string{"relay.example"}, []string{"203.0.113.10"}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if pair.Leaf.SerialNumber.Int64() != 2 {
		t.Fatalf("serial = %s", pair.Leaf.SerialNumber)
	}
	if _, _, _, err := validateCertificateResponse(response, []string{"other.example"}, nil, nil, now); err == nil {
		t.Fatal("missing hostname SAN accepted")
	}
	otherCA := newTestRelayCA(t, 3)
	if _, _, _, err := validateCertificateResponse(response, []string{"relay.example"}, []string{"203.0.113.10"}, otherCA.cert.Raw, now); err == nil {
		t.Fatal("changed CA accepted")
	}
	if _, _, _, err := validateCertificateResponse(response, []string{"relay.example"}, []string{"203.0.113.10"}, rawCA, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired leaf accepted")
	}
}

func TestValidateRenewedCertificateResponseRequiresLaterExpiry(t *testing.T) {
	ca := newTestRelayCA(t, 1)
	now := time.Now().UTC().Truncate(time.Second)
	currentResponse := ca.issue(t, 2, []string{"relay.example"}, nil, now.Add(time.Hour))
	current, rawCA, _, err := validateCertificateResponse(currentResponse, []string{"relay.example"}, nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}

	for _, notAfter := range []time.Time{now.Add(30 * time.Minute), now.Add(time.Hour)} {
		response := ca.issue(t, 3, []string{"relay.example"}, nil, notAfter)
		if _, err := validateRenewedCertificateResponse(response, []string{"relay.example"}, nil, rawCA, current, now); err == nil {
			t.Fatalf("renewal expiring at %s was accepted after current expiry %s", notAfter, current.Leaf.NotAfter)
		}
	}
	extended := ca.issue(t, 4, []string{"relay.example"}, nil, now.Add(2*time.Hour))
	if _, err := validateRenewedCertificateResponse(extended, []string{"relay.example"}, nil, rawCA, current, now); err != nil {
		t.Fatalf("extended renewal rejected: %v", err)
	}
}

type sequenceCertificateFetcher struct {
	mu        sync.Mutex
	responses []*relayauth.RelayCert
	calls     int
}

func (f *sequenceCertificateFetcher) FetchRelayCert(context.Context, []string, []string) (*relayauth.RelayCert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	index := f.calls
	if index >= len(f.responses) {
		index = len(f.responses) - 1
	}
	f.calls++
	return f.responses[index], nil
}

func TestCertificateManagerRenewsDynamicCertificate(t *testing.T) {
	ca := newTestRelayCA(t, 1)
	now := time.Now().UTC().Truncate(time.Second)
	fetcher := &sequenceCertificateFetcher{responses: []*relayauth.RelayCert{
		ca.issue(t, 10, []string{"relay.example"}, nil, now.Add(2*time.Second)),
		ca.issue(t, 11, []string{"relay.example"}, nil, now.Add(time.Hour)),
	}}
	health := newRelayHealth(true, time.Second, time.Minute)
	manager, err := newCertificateManager(context.Background(), fetcher, []string{"relay.example"}, nil, health, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	config := manager.tlsConfig()
	first, err := config.GetCertificate(nil)
	if err != nil || first.Leaf.SerialNumber.Int64() != 10 {
		t.Fatalf("initial certificate = %+v, %v", first, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, _ := config.GetCertificate(nil)
		if current.Leaf.SerialNumber.Int64() == 11 {
			if health.certExpiry.Load() != current.Leaf.NotAfter.Unix() {
				t.Fatal("health certificate expiry was not updated")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("certificate did not renew")
}
