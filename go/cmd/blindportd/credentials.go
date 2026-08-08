package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	credentialStateVersion  = 1
	credentialStateName     = "credential.json"
	credentialLockName      = ".credential.lock"
	maxCredentialStateSize  = 512 << 10
	maxCredentialGeneration = 1<<31 - 1
	renewalRetryMaximum     = 30 * time.Minute
)

type storedCredential struct {
	Version       int    `json:"version"`
	InstanceID    string `json:"instance_id"`
	Generation    int    `json:"generation"`
	PrivateKeyPEM string `json:"private_key_pem"`
	CACertPEM     string `json:"ca_cert_pem"`
	ClientCertPEM string `json:"client_cert_pem"`
	Serial        string `json:"serial"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	RenewAfter    string `json:"renew_after"`
}

type clientCertificateRequest struct {
	InstanceID string `json:"instance_id"`
	Generation int    `json:"generation"`
	CSRPEM     string `json:"csr_pem"`
}

type clientCertificateV2 struct {
	InstanceID    string `json:"instance_id"`
	Generation    int    `json:"generation"`
	CACertPEM     string `json:"ca_cert_pem"`
	ClientCertPEM string `json:"client_cert_pem"`
	Serial        string `json:"serial"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	RenewAfter    string `json:"renew_after"`
}

type credentialSnapshot struct {
	stored      storedCredential
	key         ed25519.PrivateKey
	certificate tls.Certificate
	roots       *x509.CertPool
	caCert      *x509.Certificate
	notBefore   time.Time
	notAfter    time.Time
	renewAfter  time.Time
}

type credentialManager struct {
	mu         sync.RWMutex
	renewMu    sync.Mutex
	snapshot   *credentialSnapshot
	stateDir   string
	statePath  string
	lockFile   *os.File
	backendURL string
	token      string
	client     *http.Client
}

// credentialIdentity is read as one snapshot so a provisioning response cannot
// be accepted for an identity generation replaced during its network request.
type credentialIdentity struct {
	instanceID string
	generation int
}

func defaultCredentialStateDir() string {
	if configured := os.Getenv("BLINDPORT_STATE_DIR"); configured != "" {
		return configured
	}
	if stateHome := os.Getenv("XDG_STATE_HOME"); stateHome != "" {
		return filepath.Join(stateHome, "blindport")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "state", "blindport")
}

func openCredentialManager(ctx context.Context, client *http.Client, backendURL, token, stateDir string) (*credentialManager, error) {
	if client == nil {
		return nil, errors.New("credential HTTP client is required")
	}
	if stateDir == "" {
		return nil, errors.New("credential state directory is required")
	}
	absDir, err := filepath.Abs(stateDir)
	if err != nil {
		return nil, fmt.Errorf("resolve credential state directory: %w", err)
	}
	if filepath.Clean(stateDir) != absDir {
		return nil, errors.New("credential state directory must be an absolute canonical path")
	}
	if err := prepareCredentialStateDir(absDir); err != nil {
		return nil, err
	}
	lockFile, err := acquireCredentialLock(filepath.Join(absDir, credentialLockName))
	if err != nil {
		return nil, err
	}
	manager := &credentialManager{
		stateDir:   absDir,
		statePath:  filepath.Join(absDir, credentialStateName),
		lockFile:   lockFile,
		backendURL: strings.TrimRight(backendURL, "/"),
		token:      token,
		client:     client,
	}
	if err := manager.initialize(ctx); err != nil {
		_ = manager.Close()
		return nil, err
	}
	return manager, nil
}

func prepareCredentialStateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create credential state directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect credential state directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("credential state path must be a directory, not a symbolic link")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("credential state directory permissions %04o expose private state", info.Mode().Perm())
	}
	if err := validateStaticConfigOwner(info); err != nil {
		return fmt.Errorf("credential state directory: %w", err)
	}
	return nil
}

func (m *credentialManager) initialize(ctx context.Context) error {
	stored, err := loadStoredCredential(m.statePath)
	if err == nil {
		if stored.Generation == 0 {
			key, validateErr := validatePendingCredential(stored)
			if validateErr != nil {
				return fmt.Errorf("validate pending client identity: %w", validateErr)
			}
			issued, enrollErr := m.enroll(ctx, stored.InstanceID, 1, key)
			if enrollErr != nil {
				return enrollErr
			}
			return m.install(issued)
		}
		snapshot, validateErr := validateStoredCredential(stored, time.Now())
		if validateErr != nil {
			return fmt.Errorf("validate persisted client identity: %w", validateErr)
		}
		m.snapshot = snapshot
		if time.Now().Before(snapshot.notAfter) {
			return nil
		}
		return m.renew(ctx)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	key, err := newClientPrivateKey()
	if err != nil {
		return err
	}
	instanceID, err := newInstanceID()
	if err != nil {
		return err
	}
	pending, err := newPendingCredential(instanceID, key)
	if err != nil {
		return err
	}
	if err := writeStoredCredential(m.stateDir, m.statePath, pending); err != nil {
		return err
	}
	stored, err = m.enroll(ctx, instanceID, 1, key)
	if err != nil {
		return err
	}
	return m.install(stored)
}

func loadStoredCredential(path string) (storedCredential, error) {
	file, err := openStaticConfig(path)
	if err != nil {
		return storedCredential{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return storedCredential{}, fmt.Errorf("inspect credential file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return storedCredential{}, errors.New("credential file must be regular")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return storedCredential{}, fmt.Errorf("credential file permissions %04o expose private key", info.Mode().Perm())
	}
	if err := validateStaticConfigOwner(info); err != nil {
		return storedCredential{}, fmt.Errorf("credential file: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCredentialStateSize+1))
	if err != nil {
		return storedCredential{}, fmt.Errorf("read credential file: %w", err)
	}
	if len(data) > maxCredentialStateSize {
		return storedCredential{}, fmt.Errorf("credential file exceeds %d bytes", maxCredentialStateSize)
	}
	var stored storedCredential
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return storedCredential{}, fmt.Errorf("decode credential file: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return storedCredential{}, fmt.Errorf("decode credential file: %w", err)
	}
	return stored, nil
}

func validateStoredCredential(stored storedCredential, now time.Time) (*credentialSnapshot, error) {
	if stored.Version != credentialStateVersion {
		return nil, fmt.Errorf("unsupported credential state version %d", stored.Version)
	}
	if !isCanonicalInstanceID(stored.InstanceID) || stored.Generation < 1 || stored.Generation > maxCredentialGeneration || stored.Serial == "" {
		return nil, errors.New("credential identity metadata is invalid")
	}
	notBefore, err := time.Parse(time.RFC3339, stored.NotBefore)
	if err != nil {
		return nil, fmt.Errorf("parse credential not_before: %w", err)
	}
	notAfter, err := time.Parse(time.RFC3339, stored.NotAfter)
	if err != nil {
		return nil, fmt.Errorf("parse credential not_after: %w", err)
	}
	renewAfter, err := time.Parse(time.RFC3339, stored.RenewAfter)
	if err != nil {
		return nil, fmt.Errorf("parse credential renew_after: %w", err)
	}
	if !notBefore.Before(renewAfter) || !renewAfter.Before(notAfter) {
		return nil, errors.New("credential renewal timestamps are not ordered")
	}
	keyPair, err := tls.X509KeyPair([]byte(stored.ClientCertPEM), []byte(stored.PrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("load persisted client keypair: %w", err)
	}
	if len(keyPair.Certificate) != 1 {
		return nil, errors.New("persisted client certificate must contain exactly one leaf")
	}
	leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse persisted client certificate: %w", err)
	}
	privateKey, err := parsePrivateKeyPEM(stored.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse persisted client private key: %w", err)
	}
	if !leaf.NotBefore.Equal(notBefore) || !leaf.NotAfter.Equal(notAfter) {
		return nil, errors.New("persisted certificate validity does not match metadata")
	}
	if leaf.SerialNumber.Text(16) != stored.Serial {
		return nil, errors.New("persisted certificate serial does not match metadata")
	}
	expectedURI := "urn:blindport:client:" + stored.InstanceID
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != expectedURI {
		return nil, errors.New("persisted certificate instance identity does not match state")
	}
	caCert, err := parseCACertificatePEM(stored.CACertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse persisted CA certificate: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	verificationTime := now
	if !now.Before(notAfter) {
		verificationTime = notBefore.Add(notAfter.Sub(notBefore) / 2)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: verificationTime,
	}); err != nil {
		return nil, fmt.Errorf("verify persisted client certificate: %w", err)
	}
	keyPair.Leaf = leaf
	return &credentialSnapshot{
		stored: stored, key: privateKey, certificate: keyPair, roots: roots, caCert: caCert,
		notBefore: notBefore, notAfter: notAfter, renewAfter: renewAfter,
	}, nil
}

func newPendingCredential(instanceID string, key ed25519.PrivateKey) (storedCredential, error) {
	keyPEM, err := privateKeyPEM(key)
	if err != nil {
		return storedCredential{}, err
	}
	return storedCredential{
		Version: credentialStateVersion, InstanceID: instanceID, PrivateKeyPEM: keyPEM,
	}, nil
}

func validatePendingCredential(stored storedCredential) (ed25519.PrivateKey, error) {
	if stored.Version != credentialStateVersion {
		return nil, fmt.Errorf("unsupported credential state version %d", stored.Version)
	}
	if !isCanonicalInstanceID(stored.InstanceID) || stored.Generation != 0 {
		return nil, errors.New("pending credential identity metadata is invalid")
	}
	if stored.CACertPEM != "" || stored.ClientCertPEM != "" || stored.Serial != "" ||
		stored.NotBefore != "" || stored.NotAfter != "" || stored.RenewAfter != "" {
		return nil, errors.New("pending credential contains issued certificate data")
	}
	key, err := parsePrivateKeyPEM(stored.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse pending client private key: %w", err)
	}
	return key, nil
}

func parsePrivateKeyPEM(value string) (ed25519.PrivateKey, error) {
	block, trailing := pem.Decode([]byte(value))
	if block == nil || block.Type != "PRIVATE KEY" || len(trailing) != 0 {
		return nil, errors.New("private key must contain one canonical PKCS#8 PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("private key is not Ed25519")
	}
	return key, nil
}

func parseCACertificatePEM(value string) (*x509.Certificate, error) {
	block, trailing := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" || len(trailing) != 0 {
		return nil, errors.New("CA certificate must contain one canonical PEM block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if certificate.PublicKeyAlgorithm != x509.Ed25519 || !certificate.IsCA ||
		certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("CA certificate is not an Ed25519 certificate authority")
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return nil, fmt.Errorf("CA certificate is not self-signed: %w", err)
	}
	return certificate, nil
}

func newClientPrivateKey() (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate client key: %w", err)
	}
	return key, nil
}

func newInstanceID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate client instance id: %w", err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:]), nil
}

func isCanonicalInstanceID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || strings.ToLower(value) != value {
		return false
	}
	raw := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(raw)
	return err == nil && len(decoded) == 16
}

func privateKeyPEM(key ed25519.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal client key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func clientCSRPEM(key ed25519.PrivateKey) (string, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return "", fmt.Errorf("create client CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func (m *credentialManager) enroll(ctx context.Context, instanceID string, generation int, key ed25519.PrivateKey) (storedCredential, error) {
	csrPEM, err := clientCSRPEM(key)
	if err != nil {
		return storedCredential{}, err
	}
	requestBody, err := json.Marshal(clientCertificateRequest{
		InstanceID: instanceID, Generation: generation, CSRPEM: csrPEM,
	})
	if err != nil {
		return storedCredential{}, fmt.Errorf("encode certificate request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.backendURL+"/api/v2/client/certificate", bytes.NewReader(requestBody))
	if err != nil {
		return storedCredential{}, err
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return storedCredential{}, fmt.Errorf("enroll client certificate: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return storedCredential{}, fmt.Errorf("client certificate status %d", resp.StatusCode)
	}
	var issued clientCertificateV2
	if err := decodeBoundedJSON(resp.Body, maxCertificateResponse, &issued); err != nil {
		return storedCredential{}, err
	}
	if issued.InstanceID != instanceID || issued.Generation != generation {
		return storedCredential{}, errors.New("certificate response identity does not match request")
	}
	keyPEM, err := privateKeyPEM(key)
	if err != nil {
		return storedCredential{}, err
	}
	return storedCredential{
		Version: credentialStateVersion, InstanceID: instanceID, Generation: generation,
		PrivateKeyPEM: keyPEM, CACertPEM: issued.CACertPEM,
		ClientCertPEM: issued.ClientCertPEM, Serial: issued.Serial,
		NotBefore: issued.NotBefore, NotAfter: issued.NotAfter, RenewAfter: issued.RenewAfter,
	}, nil
}

func (m *credentialManager) install(stored storedCredential) error {
	snapshot, err := validateStoredCredential(stored, time.Now())
	if err != nil {
		return fmt.Errorf("validate enrolled client identity: %w", err)
	}
	if err := writeStoredCredential(m.stateDir, m.statePath, stored); err != nil {
		return err
	}
	m.mu.Lock()
	m.snapshot = snapshot
	m.mu.Unlock()
	return nil
}

func writeStoredCredential(stateDir, statePath string, stored storedCredential) error {
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("encode credential state: %w", err)
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(stateDir, ".credential-*")
	if err != nil {
		return fmt.Errorf("create temporary credential file: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("protect temporary credential file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temporary credential file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temporary credential file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temporary credential file: %w", err)
	}
	if err := os.Rename(temporaryPath, statePath); err != nil {
		cleanup()
		return fmt.Errorf("replace credential file: %w", err)
	}
	directory, err := os.Open(stateDir)
	if err != nil {
		return fmt.Errorf("open credential directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync credential directory: %w", err)
	}
	return nil
}

func (m *credentialManager) renew(ctx context.Context) error {
	m.renewMu.Lock()
	defer m.renewMu.Unlock()
	m.mu.RLock()
	current := m.snapshot
	m.mu.RUnlock()
	if current == nil {
		return errors.New("client identity is not initialized")
	}
	stored, err := m.enroll(ctx, current.stored.InstanceID, current.stored.Generation+1, current.key)
	if err != nil {
		return err
	}
	renewedCA, err := parseCACertificatePEM(stored.CACertPEM)
	if err != nil {
		return fmt.Errorf("validate renewed CA certificate: %w", err)
	}
	if !bytes.Equal(current.caCert.Raw, renewedCA.Raw) {
		return errors.New("renewed credential changed the trusted CA")
	}
	return m.install(stored)
}

func (m *credentialManager) runRenewal(ctx context.Context, log *slog.Logger) {
	backoff := time.Minute
	for ctx.Err() == nil {
		m.mu.RLock()
		renewAfter := m.snapshot.renewAfter
		notAfter := m.snapshot.notAfter
		m.mu.RUnlock()
		delay := time.Until(renewAfter)
		if delay < 0 {
			delay = 0
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
		if err := m.renew(ctx); err != nil {
			log.Warn("renew client certificate", "err", err, "expires_at", notAfter)
			retry := jitter(backoff)
			if untilExpiry := time.Until(notAfter); untilExpiry > 0 && retry > untilExpiry {
				retry = untilExpiry
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(retry):
			}
			if backoff < renewalRetryMaximum {
				backoff *= 2
				if backoff > renewalRetryMaximum {
					backoff = renewalRetryMaximum
				}
			}
			continue
		}
		backoff = time.Minute
		log.Info("client certificate renewed", "serial", m.serial())
	}
}

func (m *credentialManager) tlsMaterial() *tlsMaterial {
	m.mu.RLock()
	roots := m.snapshot.roots.Clone()
	m.mu.RUnlock()
	return &tlsMaterial{
		rootCAs: roots,
		getClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			m.mu.RLock()
			defer m.mu.RUnlock()
			certificate := m.snapshot.certificate
			return &certificate, nil
		},
	}
}

func (m *credentialManager) serial() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshot.stored.Serial
}

func (m *credentialManager) instanceID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshot.stored.InstanceID
}

func (m *credentialManager) generation() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshot.stored.Generation
}

func (m *credentialManager) identity() credentialIdentity {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return credentialIdentity{instanceID: m.snapshot.stored.InstanceID, generation: m.snapshot.stored.Generation}
}

func (m *credentialManager) hasIdentity(identity credentialIdentity) bool {
	return m.identity() == identity
}

// signMessage signs one enrollment message with the stable client identity key.
func (m *credentialManager) signMessage(message []byte) []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return ed25519.Sign(m.key(), message)
}

func (m *credentialManager) key() ed25519.PrivateKey {
	return m.snapshot.key
}

func (m *credentialManager) Close() error {
	return releaseCredentialLock(m.lockFile)
}
