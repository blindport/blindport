package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type enrollmentServer struct {
	t      *testing.T
	server *httptest.Server
	caKey  ed25519.PrivateKey
	caCert *x509.Certificate
	caPEM  string
	mu     sync.Mutex
	calls  int
	serial int64
	issued map[int]clientCertificateV2
}

func newEnrollmentServer(t *testing.T) *enrollmentServer {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test credential CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	harness := &enrollmentServer{
		t: t, caKey: caKey, caCert: caCert,
		caPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		serial: 10, issued: make(map[int]clientCertificateV2),
	}
	harness.server = httptest.NewServer(http.HandlerFunc(harness.handle))
	t.Cleanup(harness.server.Close)
	return harness
}

func (s *enrollmentServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/api/v2/client/certificate" {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Bearer test-token" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var request clientCertificateRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		s.t.Errorf("decode request: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	block, trailing := pem.Decode([]byte(request.CSRPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(trailing) != 0 {
		s.t.Error("invalid CSR PEM")
		http.Error(w, "bad CSR", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		s.t.Errorf("parse CSR: %v", err)
		http.Error(w, "bad CSR", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if existing, ok := s.issued[request.Generation]; ok {
		_ = json.NewEncoder(w).Encode(existing)
		return
	}
	s.serial++
	now := time.Now().UTC().Truncate(time.Second)
	notBefore := now.Add(-time.Minute)
	notAfter := now.Add(2 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(s.serial),
		Subject:      pkix.Name{CommonName: "user:42"},
		Issuer:       s.caCert.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{{Scheme: "urn", Opaque: "blindport:client:" + request.InstanceID}},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		s.t.Errorf("issue certificate: %v", err)
		http.Error(w, "issue failed", http.StatusInternalServerError)
		return
	}
	response := clientCertificateV2{
		InstanceID: request.InstanceID, Generation: request.Generation,
		CACertPEM:     s.caPEM,
		ClientCertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
		Serial:        template.SerialNumber.Text(16),
		NotBefore:     notBefore.Format(time.RFC3339), NotAfter: notAfter.Format(time.RFC3339),
		RenewAfter: now.Add(time.Hour).Format(time.RFC3339),
	}
	s.issued[request.Generation] = response
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *enrollmentServer) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func privateStateDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state")
}

func TestCredentialManagerPersistsStableIdentityAndStartsOffline(t *testing.T) {
	harness := newEnrollmentServer(t)
	stateDir := privateStateDir(t)
	manager, err := openCredentialManager(context.Background(), harness.server.Client(), harness.server.URL, "test-token", stateDir)
	if err != nil {
		t.Fatal(err)
	}
	first := manager.snapshot.stored
	if harness.callCount() != 1 {
		t.Fatalf("enrollment calls = %d, want 1", harness.callCount())
	}
	info, err := os.Stat(filepath.Join(stateDir, credentialStateName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("credential mode = %04o, want 0600", info.Mode().Perm())
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	harness.server.Close()

	reloaded, err := openCredentialManager(context.Background(), harness.server.Client(), harness.server.URL, "test-token", stateDir)
	if err != nil {
		t.Fatalf("offline reload: %v", err)
	}
	defer reloaded.Close()
	if reloaded.snapshot.stored.InstanceID != first.InstanceID || reloaded.snapshot.stored.PrivateKeyPEM != first.PrivateKeyPEM {
		t.Fatal("persisted identity changed across restart")
	}
	if harness.callCount() != 1 {
		t.Fatalf("offline reload contacted backend, calls = %d", harness.callCount())
	}
}

func TestCredentialManagerPersistsPendingIdentityBeforeEnrollment(t *testing.T) {
	harness := newEnrollmentServer(t)
	stateDir := privateStateDir(t)
	original := harness.server
	harness.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pending, err := loadStoredCredential(filepath.Join(stateDir, credentialStateName))
		if err != nil {
			t.Errorf("load pending credential: %v", err)
			http.Error(w, "pending identity missing", http.StatusInternalServerError)
			return
		}
		if _, err := validatePendingCredential(pending); err != nil {
			t.Errorf("validate pending credential: %v", err)
			http.Error(w, "pending identity invalid", http.StatusInternalServerError)
			return
		}
		harness.handle(w, r)
	}))
	defer harness.server.Close()
	original.Close()

	manager, err := openCredentialManager(context.Background(), harness.server.Client(), harness.server.URL, "test-token", stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if manager.snapshot.stored.Generation != 1 {
		t.Fatalf("generation = %d, want 1", manager.snapshot.stored.Generation)
	}
}

func TestCredentialManagerResumesPendingIdentity(t *testing.T) {
	harness := newEnrollmentServer(t)
	stateDir := privateStateDir(t)
	if err := prepareCredentialStateDir(stateDir); err != nil {
		t.Fatal(err)
	}
	key, err := newClientPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	instanceID, err := newInstanceID()
	if err != nil {
		t.Fatal(err)
	}
	pending, err := newPendingCredential(instanceID, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStoredCredential(stateDir, filepath.Join(stateDir, credentialStateName), pending); err != nil {
		t.Fatal(err)
	}

	manager, err := openCredentialManager(context.Background(), harness.server.Client(), harness.server.URL, "test-token", stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if manager.snapshot.stored.InstanceID != instanceID || manager.snapshot.stored.Generation != 1 {
		t.Fatalf("resumed identity = %s/%d", manager.snapshot.stored.InstanceID, manager.snapshot.stored.Generation)
	}
	if !manager.snapshot.key.Equal(key) {
		t.Fatal("pending private key changed during enrollment recovery")
	}
}

func TestCredentialRenewalReusesKeyAndUpdatesDynamicTLSCertificate(t *testing.T) {
	harness := newEnrollmentServer(t)
	manager, err := openCredentialManager(context.Background(), harness.server.Client(), harness.server.URL, "test-token", privateStateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	material := manager.tlsMaterial()
	config, err := material.configForEndpoint("relay.example:5443", "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := config.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	firstSerial := first.Leaf.SerialNumber.String()
	firstKey := manager.snapshot.stored.PrivateKeyPEM

	if err := manager.renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := config.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if second.Leaf.SerialNumber.String() == firstSerial {
		t.Fatal("TLS callback still returns old certificate")
	}
	if manager.snapshot.stored.PrivateKeyPEM != firstKey {
		t.Fatal("renewal rotated the stable private key")
	}
	if manager.snapshot.stored.Generation != 2 || harness.callCount() != 2 {
		t.Fatalf("generation/calls = %d/%d, want 2/2", manager.snapshot.stored.Generation, harness.callCount())
	}
}

func TestCredentialStateLockRejectsSecondProcess(t *testing.T) {
	harness := newEnrollmentServer(t)
	stateDir := privateStateDir(t)
	first, err := openCredentialManager(context.Background(), harness.server.Client(), harness.server.URL, "test-token", stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_, err = openCredentialManager(context.Background(), harness.server.Client(), harness.server.URL, "test-token", stateDir)
	if err == nil || !strings.Contains(err.Error(), "already locked") {
		t.Fatalf("second manager error = %v", err)
	}
}

func TestCredentialStateRejectsExposedDirectoryAndSymlink(t *testing.T) {
	harness := newEnrollmentServer(t)
	exposed := filepath.Join(t.TempDir(), "exposed")
	if err := os.Mkdir(exposed, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openCredentialManager(context.Background(), harness.server.Client(), harness.server.URL, "test-token", exposed); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("exposed directory error = %v", err)
	}

	stateDir := privateStateDir(t)
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(stateDir, credentialStateName)); err != nil {
		t.Fatal(err)
	}
	if _, err := openCredentialManager(context.Background(), harness.server.Client(), harness.server.URL, "test-token", stateDir); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink credential error = %v", err)
	}
}

func TestCredentialStateRejectsCertificateForDifferentKey(t *testing.T) {
	harness := newEnrollmentServer(t)
	original := harness.server
	harness.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request clientCertificateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, wrongKey)
		if err != nil {
			t.Fatal(err)
		}
		wrongCSR, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			t.Fatal(err)
		}
		harness.mu.Lock()
		harness.serial++
		now := time.Now().UTC().Truncate(time.Second)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(harness.serial), Subject: pkix.Name{CommonName: "user:42"},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			URIs: []*url.URL{{Scheme: "urn", Opaque: "blindport:client:" + request.InstanceID}},
		}
		certDER, issueErr := x509.CreateCertificate(rand.Reader, template, harness.caCert, wrongCSR.PublicKey, harness.caKey)
		harness.mu.Unlock()
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		_ = json.NewEncoder(w).Encode(clientCertificateV2{
			InstanceID: request.InstanceID, Generation: request.Generation,
			CACertPEM:     harness.caPEM,
			ClientCertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
			Serial:        template.SerialNumber.Text(16),
			NotBefore:     template.NotBefore.Format(time.RFC3339), NotAfter: template.NotAfter.Format(time.RFC3339),
			RenewAfter: now.Add(30 * time.Minute).Format(time.RFC3339),
		})
	}))
	defer harness.server.Close()
	original.Close()

	_, err := openCredentialManager(context.Background(), harness.server.Client(), harness.server.URL, "test-token", privateStateDir(t))
	if err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("mismatched certificate error = %v", err)
	}
}

func TestExpiredCredentialStillRequiresAValidCertificateChain(t *testing.T) {
	harness := newEnrollmentServer(t)
	manager, err := openCredentialManager(context.Background(), harness.server.Client(), harness.server.URL, "test-token", privateStateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	stored := manager.snapshot.stored
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	other := newEnrollmentServer(t)
	stored.CACertPEM = other.caPEM

	_, err = validateStoredCredential(stored, manager.snapshot.notAfter.Add(time.Hour))
	if err == nil || !strings.Contains(err.Error(), "verify persisted client certificate") {
		t.Fatalf("expired invalid chain error = %v", err)
	}
}

func TestCredentialStateRejectsAdditionalTrustedCAs(t *testing.T) {
	harness := newEnrollmentServer(t)
	manager, err := openCredentialManager(context.Background(), harness.server.Client(), harness.server.URL, "test-token", privateStateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	stored := manager.snapshot.stored
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	other := newEnrollmentServer(t)
	stored.CACertPEM += other.caPEM

	_, err = validateStoredCredential(stored, time.Now())
	if err == nil || !strings.Contains(err.Error(), "one canonical PEM block") {
		t.Fatalf("additional CA error = %v", err)
	}
}

func TestCredentialRenewalRejectsChangedCA(t *testing.T) {
	first := newEnrollmentServer(t)
	manager, err := openCredentialManager(context.Background(), first.server.Client(), first.server.URL, "test-token", privateStateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	original := manager.snapshot.stored
	second := newEnrollmentServer(t)
	manager.backendURL = second.server.URL

	err = manager.renew(context.Background())
	if err == nil || !strings.Contains(err.Error(), "changed the trusted CA") {
		t.Fatalf("changed CA renewal error = %v", err)
	}
	if manager.snapshot.stored.Generation != original.Generation || manager.snapshot.stored.Serial != original.Serial {
		t.Fatal("failed CA-changing renewal replaced the active credential")
	}
}
