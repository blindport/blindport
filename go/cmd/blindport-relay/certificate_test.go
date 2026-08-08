package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
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
	manager, err := newCertificateManager(context.Background(), fetcher, []string{"relay.example"}, nil, "", health, slog.New(slog.NewTextHandler(os.Stderr, nil)))
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

type staticCertificateFetcher struct {
	response *relayauth.RelayCert
	err      error
	calls    int
}

func (f *staticCertificateFetcher) FetchRelayCert(context.Context, []string, []string) (*relayauth.RelayCert, error) {
	f.calls++
	return f.response, f.err
}

func TestCertificateManagerStoresOnlineCertificateCache(t *testing.T) {
	ca := newTestRelayCA(t, 1)
	now := time.Now().UTC().Truncate(time.Second)
	directory := certificateCacheTestDir(t)
	response := ca.issue(t, 2, []string{"RELAY.example."}, []string{"203.0.113.10"}, now.Add(time.Hour))
	health := newRelayHealth(true, time.Second, time.Minute)
	manager, err := newCertificateManager(context.Background(), &staticCertificateFetcher{response: response}, []string{"relay.EXAMPLE"}, []string{"203.0.113.10"}, directory, health, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if manager.current.Load() == nil {
		t.Fatal("online certificate was not activated")
	}
	info, err := os.Stat(filepath.Join(directory, certificateCacheFileName))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("cache mode = %04o, want 0600", got)
	}
}

func TestCertificateManagerUsesCacheOnlyForInfrastructureFailure(t *testing.T) {
	ca := newTestRelayCA(t, 1)
	now := time.Now().UTC().Truncate(time.Second)
	directory := certificateCacheTestDir(t)
	response := ca.issue(t, 2, []string{"relay.example"}, nil, now.Add(time.Hour))
	cache := newCertificateCache(directory)
	if err := cache.store(response, []string{"relay.example"}, nil, now); err != nil {
		t.Fatal(err)
	}
	infrastructure := &relayauth.Error{Kind: relayauth.ErrorInfrastructure, Err: errors.New("backend unavailable")}
	health := newRelayHealth(true, time.Second, time.Minute)
	manager, err := newCertificateManager(context.Background(), &staticCertificateFetcher{err: infrastructure}, []string{"relay.example"}, nil, directory, health, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if got := manager.current.Load().Leaf.SerialNumber.Int64(); got != 2 {
		t.Fatalf("cached serial = %d, want 2", got)
	}
	if got := health.authState.Load(); got != authInfrastructureFailure {
		t.Fatalf("health auth state = %d, want infrastructure failure", got)
	}
}

func TestCertificateManagerDoesNotFallbackForOnlineFailures(t *testing.T) {
	ca := newTestRelayCA(t, 1)
	now := time.Now().UTC().Truncate(time.Second)
	response := ca.issue(t, 2, []string{"relay.example"}, nil, now.Add(time.Hour))
	for _, test := range []struct {
		name     string
		response *relayauth.RelayCert
		err      error
	}{
		{name: "secret error", err: &relayauth.Error{Kind: relayauth.ErrorSecret, Err: errors.New("bad secret")}},
		{name: "protocol error", err: &relayauth.Error{Kind: relayauth.ErrorProtocol, Err: errors.New("bad response")}},
		{name: "malformed online success", response: &relayauth.RelayCert{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := certificateCacheTestDir(t)
			cache := newCertificateCache(directory)
			if err := cache.store(response, []string{"relay.example"}, nil, now); err != nil {
				t.Fatal(err)
			}
			_, err := newCertificateManager(context.Background(), &staticCertificateFetcher{response: test.response, err: test.err}, []string{"relay.example"}, nil, directory, newRelayHealth(true, time.Second, time.Minute), slog.Default())
			if err == nil {
				t.Fatal("certificate manager unexpectedly loaded the cache")
			}
		})
	}
}

func TestCertificateCacheRejectsMismatchedAndExpiredMaterial(t *testing.T) {
	ca := newTestRelayCA(t, 1)
	now := time.Now().UTC().Truncate(time.Second)
	response := ca.issue(t, 2, []string{"relay.example"}, nil, now.Add(time.Hour))
	expiredResponse := ca.issue(t, 3, []string{"relay.example"}, nil, now.Add(-time.Hour))
	for _, test := range []struct {
		name     string
		envelope certificateCacheEnvelope
	}{
		{name: "identity mismatch", envelope: certificateCacheEnvelope{Version: certificateCacheVersion, Hostnames: []string{"other.example"}, IPs: []string{}, Certificate: responseCopy(response)}},
		{name: "expired", envelope: certificateCacheEnvelope{Version: certificateCacheVersion, Hostnames: []string{"relay.example"}, IPs: []string{}, Certificate: responseCopy(expiredResponse)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := certificateCacheTestDir(t)
			writeCertificateCacheEnvelope(t, directory, test.envelope)
			if _, err := newCertificateCache(directory).load([]string{"relay.example"}, nil, now); err == nil {
				t.Fatal("unsafe cached material was accepted")
			}
		})
	}
}

func TestCertificateCacheRejectsUnsafeFiles(t *testing.T) {
	ca := newTestRelayCA(t, 1)
	now := time.Now().UTC().Truncate(time.Second)
	response := ca.issue(t, 2, []string{"relay.example"}, nil, now.Add(time.Hour))
	t.Run("mode", func(t *testing.T) {
		directory := certificateCacheTestDir(t)
		cache := newCertificateCache(directory)
		if err := cache.store(response, []string{"relay.example"}, nil, now); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, certificateCacheFileName)
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := cache.load([]string{"relay.example"}, nil, now); err == nil {
			t.Fatal("cache with unsafe mode was accepted")
		}
	})
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink permissions are environment-dependent")
	}
	t.Run("symlink", func(t *testing.T) {
		directory := certificateCacheTestDir(t)
		path := filepath.Join(directory, certificateCacheFileName)
		target := filepath.Join(directory, "target")
		payload, err := json.Marshal(certificateCacheEnvelope{Version: certificateCacheVersion, Hostnames: []string{"relay.example"}, IPs: []string{}, Certificate: *response})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("create symlink: %v", err)
		}
		if _, err := newCertificateCache(directory).load([]string{"relay.example"}, nil, now); err == nil {
			t.Fatal("symlink cache was accepted")
		}
	})
}

func TestCertificateManagerRetainsCurrentCertificateWhenCachePersistenceFails(t *testing.T) {
	ca := newTestRelayCA(t, 1)
	now := time.Now().UTC().Truncate(time.Second)
	directory := certificateCacheTestDir(t)
	fetcher := &sequenceCertificateFetcher{responses: []*relayauth.RelayCert{
		ca.issue(t, 10, []string{"relay.example"}, nil, now.Add(2*time.Second)),
		ca.issue(t, 11, []string{"relay.example"}, nil, now.Add(time.Hour)),
	}}
	health := newRelayHealth(true, time.Second, time.Minute)
	manager, err := newCertificateManager(context.Background(), fetcher, []string{"relay.example"}, nil, directory, health, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(directory, certificateCacheFileName), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.run(ctx)
	time.Sleep(2500 * time.Millisecond)
	if got := manager.current.Load().Leaf.SerialNumber.Int64(); got != 10 {
		t.Fatalf("renewed certificate serial = %d, want current serial 10 after cache failure", got)
	}
}

func responseCopy(response *relayauth.RelayCert) relayauth.RelayCert {
	return *response
}

func writeCertificateCacheEnvelope(t *testing.T, directory string, envelope certificateCacheEnvelope) {
	t.Helper()
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, certificateCacheFileName), payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

func certificateCacheTestDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}
