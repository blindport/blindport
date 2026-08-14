package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blindport/blindport/internal/protocol"
	"github.com/blindport/blindport/internal/proxyproto"
	"github.com/blindport/blindport/internal/tcpproxy"
	"github.com/blindport/blindport/internal/tunnel"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
)

const (
	acmeStateVersion       = 1
	acmeStateSizeLimit     = 1 << 20
	acmeHandshakeTimeout   = 10 * time.Second
	acmeChallengeTimeout   = 10 * time.Second
	acmeOperationTimeout   = 2 * time.Minute
	acmeRetryInitial       = time.Minute
	acmeRetryMaximum       = time.Hour
	acmeReadinessDelay     = 250 * time.Millisecond
	acmeChallengeHeadLimit = 16 << 10
	acmeChallengeKeyLimit  = 1024
)

var acmeChallengeToken = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

type storedACMEAccount struct {
	Version      int                    `json:"version"`
	DirectoryURL string                 `json:"directory_url"`
	Email        string                 `json:"email,omitempty"`
	PrivateKey   string                 `json:"private_key_pem"`
	Registration *registration.Resource `json:"registration,omitempty"`
}

type storedACMECertificate struct {
	Version           int    `json:"version"`
	Domain            string `json:"domain"`
	CertURL           string `json:"cert_url,omitempty"`
	CertStableURL     string `json:"cert_stable_url,omitempty"`
	PrivateKeyPEM     string `json:"private_key_pem"`
	CertificatePEM    string `json:"certificate_pem"`
	IssuerCertificate string `json:"issuer_certificate_pem,omitempty"`
}

type legoUser struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
}

func (u *legoUser) GetEmail() string                        { return u.email }
func (u *legoUser) GetRegistration() *registration.Resource { return u.registration }
func (u *legoUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

type acmeAccount struct {
	operation    chan struct{}
	directoryURL string
	email        string
	stateDir     string
	statePath    string
	httpClient   *http.Client
}

type certificateSnapshot struct {
	certificate *tls.Certificate
	resource    certificate.Resource
}

type acmeDomainManager struct {
	domain           string
	stateDir         string
	statePath        string
	account          *acmeAccount
	log              *slog.Logger
	current          atomic.Pointer[certificateSnapshot]
	proofMu          sync.RWMutex
	proofs           map[string]string
	ready            chan struct{}
	readyOnce        sync.Once
	cancel           context.CancelFunc
	done             chan struct{}
	now              func() time.Time
	readyDelay       time.Duration
	handshakeTimeout time.Duration
	challengeTimeout time.Duration
	retryDelay       func(bool, int) time.Duration
	issue            func(context.Context, *certificate.Resource, challenge.Provider) (*certificate.Resource, error)
	renewalInfo      func(context.Context, *certificateSnapshot) (*certificate.RenewalInfoResponse, error)
	activeStreams    atomic.Int64
}

type acmeRegistry struct {
	mu           sync.RWMutex
	ctx          context.Context
	stateDir     string
	directoryURL string
	email        string
	httpClient   *http.Client
	account      *acmeAccount
	certDir      string
	lockFile     *os.File
	log          *slog.Logger
	managers     map[string]*acmeDomainManager
	factory      func(string) (*acmeDomainManager, error)
	initialized  bool
}

type automaticPlanReconciler struct {
	registry *acmeRegistry
	workers  planReconciler
}

func (r automaticPlanReconciler) Reconcile(plans []workerPlan) error {
	if err := r.registry.Reconcile(plans); err != nil {
		return err
	}
	return r.workers.Reconcile(plans)
}

func newACMERegistry(ctx context.Context, stateDir, directoryURL, email string, httpClient *http.Client, logger *slog.Logger) (*acmeRegistry, error) {
	r, err := newLazyACMERegistry(ctx, stateDir, directoryURL, email, httpClient, logger)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.initializeLocked(); err != nil {
		return nil, err
	}
	return r, nil
}

func newLazyACMERegistry(ctx context.Context, stateDir, directoryURL, email string, httpClient *http.Client, logger *slog.Logger) (*acmeRegistry, error) {
	r := &acmeRegistry{
		ctx: ctx, stateDir: stateDir, directoryURL: directoryURL, email: email,
		httpClient: httpClient, log: logger, managers: make(map[string]*acmeDomainManager),
	}
	r.factory = r.newManager
	return r, nil
}

func (r *acmeRegistry) initializeLocked() error {
	if r.initialized {
		return nil
	}
	if r.httpClient == nil {
		return errors.New("ACME HTTP client is required")
	}
	if r.directoryURL == "" {
		return errors.New("ACME directory URL is required")
	}
	absStateDir, err := filepath.Abs(r.stateDir)
	if err != nil || filepath.Clean(r.stateDir) != absStateDir {
		return errors.New("ACME state directory must be an absolute canonical path")
	}
	r.stateDir = absStateDir
	if err := prepareCredentialStateDir(r.stateDir); err != nil {
		return err
	}
	lockFile, err := acquireCredentialLock(filepath.Join(r.stateDir, ".acme.lock"))
	if err != nil {
		return fmt.Errorf("lock ACME state: %w", err)
	}
	acmeDir := filepath.Join(r.stateDir, "acme")
	certDir := filepath.Join(acmeDir, "certificates")
	if err := prepareACMEDirectory(acmeDir); err != nil {
		_ = releaseCredentialLock(lockFile)
		return err
	}
	if err := prepareACMEDirectory(certDir); err != nil {
		_ = releaseCredentialLock(lockFile)
		return err
	}
	legolog.Logger = log.New(io.Discard, "", 0)
	r.account = &acmeAccount{
		operation: make(chan struct{}, 1), directoryURL: r.directoryURL, email: r.email, stateDir: acmeDir,
		statePath: filepath.Join(acmeDir, "account.json"), httpClient: r.httpClient,
	}
	if err := r.account.validateStored(); err != nil {
		_ = releaseCredentialLock(lockFile)
		return err
	}
	r.certDir = certDir
	r.lockFile = lockFile
	r.initialized = true
	return nil
}

func prepareACMEDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create ACME state directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect ACME state directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("ACME state path must be a directory, not a symbolic link")
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("ACME state directory must have mode 0700, got %04o", info.Mode().Perm())
	}
	if err := validateStaticConfigOwner(info); err != nil {
		return fmt.Errorf("ACME state directory: %w", err)
	}
	return nil
}

func (r *acmeRegistry) Reconcile(plans []workerPlan) error {
	wanted := make(map[string]struct{})
	for _, plan := range plans {
		if plan.TLSMode != tlsModeAutomatic {
			continue
		}
		if plan.Claim == nil || plan.Claim.Kind != protocol.ClaimRelay {
			return errors.New("automatic TLS plan requires a Relay claim")
		}
		wanted[plan.Claim.Domain] = struct{}{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(wanted) > 0 {
		if err := r.initializeLocked(); err != nil {
			return err
		}
	} else if !r.initialized {
		return nil
	}
	for domain := range wanted {
		if _, ok := r.managers[domain]; ok {
			continue
		}
		manager, err := r.factory(domain)
		if err != nil {
			return fmt.Errorf("initialize automatic TLS for %s: %w", domain, err)
		}
		r.managers[domain] = manager
	}
	for domain, manager := range r.managers {
		if _, ok := wanted[domain]; ok {
			continue
		}
		manager.stop()
		delete(r.managers, domain)
	}
	return nil
}

func (r *acmeRegistry) manager(domain string) *acmeDomainManager {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.managers[domain]
}

func (r *acmeRegistry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for domain, manager := range r.managers {
		manager.stop()
		delete(r.managers, domain)
	}
	if r.initialized {
		_ = releaseCredentialLock(r.lockFile)
		r.lockFile = nil
		r.initialized = false
	}
}

func (r *acmeRegistry) newManager(domain string) (*acmeDomainManager, error) {
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: domain}
	if err := protocol.ValidateClaim(claim); err != nil {
		return nil, fmt.Errorf("invalid ACME domain: %w", err)
	}
	managerCtx, cancel := context.WithCancel(r.ctx)
	m := &acmeDomainManager{
		domain: domain, stateDir: r.certDir, statePath: filepath.Join(r.certDir, domain+".json"),
		account: r.account, log: r.log, proofs: make(map[string]string), ready: make(chan struct{}), cancel: cancel,
		done: make(chan struct{}), now: time.Now, readyDelay: acmeReadinessDelay,
		handshakeTimeout: acmeHandshakeTimeout, challengeTimeout: acmeChallengeTimeout, retryDelay: acmeRetryDelay,
	}
	m.issue = func(ctx context.Context, current *certificate.Resource, provider challenge.Provider) (*certificate.Resource, error) {
		return r.account.issue(ctx, domain, current, provider)
	}
	m.renewalInfo = r.account.renewalInfo
	stored, err := loadACMECertificate(m.statePath, domain, m.now())
	if err == nil {
		m.current.Store(stored)
	} else if !errors.Is(err, os.ErrNotExist) {
		cancel()
		return nil, err
	}
	go func() {
		defer close(m.done)
		m.run(managerCtx)
	}()
	return m, nil
}

func (m *acmeDomainManager) stop() {
	if m.cancel != nil {
		m.cancel()
	}
	if m.done != nil {
		<-m.done
	}
	m.proofMu.Lock()
	clear(m.proofs)
	m.proofMu.Unlock()
}

func (m *acmeDomainManager) edgeReady() {
	if m == nil || m.ready == nil {
		return
	}
	m.readyOnce.Do(func() { close(m.ready) })
}

func (a *acmeAccount) issue(ctx context.Context, domain string, current *certificate.Resource, provider challenge.Provider) (*certificate.Resource, error) {
	if err := a.lock(ctx); err != nil {
		return nil, err
	}
	defer a.unlock()
	stored, user, err := a.loadOrCreate()
	if err != nil {
		return nil, err
	}
	config := lego.NewConfig(user)
	config.CADirURL = a.directoryURL
	config.HTTPClient = httpClientWithContext(a.httpClient, ctx)
	config.Certificate.Timeout = acmeOperationTimeout
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("create ACME client: %w", err)
	}
	if err := client.Challenge.SetHTTP01Provider(provider); err != nil {
		return nil, fmt.Errorf("configure HTTP-01: %w", err)
	}
	accountChanged := false
	if user.registration == nil {
		user.registration, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("register ACME account: %w", err)
		}
		stored.Registration = user.registration
		accountChanged = true
	}
	if stored.Email != a.email {
		user.registration, err = client.Registration.UpdateRegistration(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("update ACME account contact: %w", err)
		}
		stored.Email = a.email
		stored.Registration = user.registration
		accountChanged = true
	}
	if accountChanged {
		if err := writePrivateJSON(a.stateDir, a.statePath, stored); err != nil {
			return nil, err
		}
	}
	if current == nil {
		return client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{domain}, Bundle: true})
	}
	return client.Certificate.RenewWithOptions(*current, &certificate.RenewOptions{Bundle: true})
}

func (a *acmeAccount) renewalInfo(ctx context.Context, snapshot *certificateSnapshot) (*certificate.RenewalInfoResponse, error) {
	if err := a.lock(ctx); err != nil {
		return nil, err
	}
	defer a.unlock()
	stored, user, err := a.loadOrCreate()
	if err != nil {
		return nil, err
	}
	config := lego.NewConfig(user)
	config.CADirURL = a.directoryURL
	config.HTTPClient = httpClientWithContext(a.httpClient, ctx)
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}
	if user.registration != nil && stored.Email != a.email {
		user.registration, err = client.Registration.UpdateRegistration(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("update ACME account contact: %w", err)
		}
		stored.Email = a.email
		stored.Registration = user.registration
		if err := writePrivateJSON(a.stateDir, a.statePath, stored); err != nil {
			return nil, err
		}
	}
	return client.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: snapshot.certificate.Leaf})
}

func (a *acmeAccount) lock(ctx context.Context) error {
	select {
	case a.operation <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *acmeAccount) unlock() {
	<-a.operation
}

type operationRoundTripper struct {
	ctx  context.Context
	base http.RoundTripper
}

func (t operationRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	requestCtx, cancel := context.WithCancel(req.Context())
	stop := context.AfterFunc(t.ctx, cancel)
	defer func() {
		stop()
		cancel()
	}()
	return t.base.RoundTrip(req.Clone(requestCtx))
}

func httpClientWithContext(client *http.Client, ctx context.Context) *http.Client {
	copy := *client
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	copy.Transport = operationRoundTripper{ctx: ctx, base: base}
	return &copy
}

func (a *acmeAccount) loadOrCreate() (storedACMEAccount, *legoUser, error) {
	var stored storedACMEAccount
	err := readPrivateJSON(a.statePath, &stored)
	if errors.Is(err, os.ErrNotExist) {
		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			return stored, nil, fmt.Errorf("generate ACME account key: %w", keyErr)
		}
		keyPEM, keyErr := marshalECPrivateKey(key)
		if keyErr != nil {
			return stored, nil, keyErr
		}
		stored = storedACMEAccount{Version: acmeStateVersion, DirectoryURL: a.directoryURL, Email: a.email, PrivateKey: keyPEM}
		if err := writePrivateJSON(a.stateDir, a.statePath, stored); err != nil {
			return stored, nil, err
		}
	} else if err != nil {
		return stored, nil, err
	}
	if stored.Version != acmeStateVersion || stored.DirectoryURL != a.directoryURL {
		return stored, nil, errors.New("persisted ACME account does not match the configured directory")
	}
	key, err := parseECPrivateKey(stored.PrivateKey)
	if err != nil {
		return stored, nil, fmt.Errorf("parse persisted ACME account key: %w", err)
	}
	return stored, &legoUser{email: a.email, key: key, registration: stored.Registration}, nil
}

func (a *acmeAccount) validateStored() error {
	var stored storedACMEAccount
	if err := readPrivateJSON(a.statePath, &stored); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if stored.Version != acmeStateVersion || stored.DirectoryURL != a.directoryURL {
		return errors.New("persisted ACME account does not match the configured directory")
	}
	if _, err := parseECPrivateKey(stored.PrivateKey); err != nil {
		return fmt.Errorf("parse persisted ACME account key: %w", err)
	}
	return nil
}

func (m *acmeDomainManager) Present(domain, token, keyAuth string) error {
	if domain != m.domain || !acmeChallengeToken.MatchString(token) || keyAuth == "" || len(keyAuth) > acmeChallengeKeyLimit {
		return errors.New("ACME challenge does not match the exact managed hostname")
	}
	m.proofMu.Lock()
	m.proofs[token] = keyAuth
	m.proofMu.Unlock()
	return nil
}

func (m *acmeDomainManager) CleanUp(domain, token, _ string) error {
	if domain != m.domain {
		return errors.New("ACME challenge cleanup does not match the exact managed hostname")
	}
	m.proofMu.Lock()
	delete(m.proofs, token)
	m.proofMu.Unlock()
	return nil
}

func (m *acmeDomainManager) run(ctx context.Context) {
	failures := 0
	var scheduled *certificateSnapshot
	var renewAt time.Time
	if m.ready != nil {
		select {
		case <-ctx.Done():
			return
		case <-m.ready:
		}
		if m.readyDelay > 0 && !sleepACMEContext(ctx, m.readyDelay) {
			return
		}
	}
	for ctx.Err() == nil {
		current := m.current.Load()
		usable := m.hasUsableCertificate(m.now())
		if usable {
			if current != scheduled {
				var info *certificate.RenewalInfoResponse
				if m.renewalInfo != nil {
					operationCtx, cancel := context.WithTimeout(ctx, acmeOperationTimeout)
					info, _ = m.renewalInfo(operationCtx, current)
					cancel()
				}
				renewAt = certificateRenewalTime(current.certificate.Leaf, info)
				scheduled = current
			}
			wait := renewAt.Sub(m.now())
			if wait > 0 {
				if !sleepACMEContext(ctx, wait) {
					return
				}
			}
		}
		var resource *certificate.Resource
		if current != nil {
			copy := current.resource
			resource = &copy
		}
		operationCtx, cancel := context.WithTimeout(ctx, acmeOperationTimeout)
		issued, err := m.issue(operationCtx, resource, m)
		cancel()
		if err == nil {
			err = m.install(issued, m.now())
		}
		if err == nil {
			m.log.Info("automatic TLS certificate installed", "domain", m.domain, "not_after", m.current.Load().certificate.Leaf.NotAfter)
			failures = 0
			continue
		}
		failures++
		m.log.Warn("automatic TLS certificate operation failed", "domain", m.domain, "err", err)
		delay := acmeRetryDelay(usable, failures)
		if m.retryDelay != nil {
			delay = m.retryDelay(usable, failures)
		}
		if !sleepACMEContext(ctx, delay) {
			return
		}
	}
}

func (m *acmeDomainManager) hasUsableCertificate(now time.Time) bool {
	current := m.current.Load()
	return current != nil && !now.Before(current.certificate.Leaf.NotBefore) && now.Before(current.certificate.Leaf.NotAfter)
}

func acmeRetryDelay(_ bool, failures int) time.Duration {
	exponent := failures - 1
	if exponent < 0 {
		exponent = 0
	}
	delay := acmeRetryInitial
	for range exponent {
		if delay >= acmeRetryMaximum/2 {
			return acmeRetryMaximum
		}
		delay *= 2
	}
	return min(delay, acmeRetryMaximum)
}

func sleepACMEContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func certificateRenewalTime(leaf *x509.Certificate, info *certificate.RenewalInfoResponse) time.Time {
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	lead := min(30*24*time.Hour, lifetime/3)
	fallback := leaf.NotAfter.Add(-lead)
	jitterWindow := lead / 10
	if jitterWindow > 0 {
		fallback = fallback.Add(-certificateOffset(leaf, jitterWindow))
	}
	if info == nil {
		return fallback
	}
	start := info.SuggestedWindow.Start
	end := info.SuggestedWindow.End
	safetyLead := min(24*time.Hour, lifetime/10)
	safeLatest := leaf.NotAfter.Add(-safetyLead)
	if end.After(safeLatest) {
		end = safeLatest
	}
	if start.Before(leaf.NotBefore) {
		start = leaf.NotBefore
	}
	if !end.After(start) {
		return fallback
	}
	// Use the first half of a valid ARI window to retain recovery time.
	window := end.Sub(start) / 2
	return start.Add(certificateOffset(leaf, window))
}

func certificateOffset(leaf *x509.Certificate, window time.Duration) time.Duration {
	if window <= 0 {
		return 0
	}
	digest := sha256.Sum256(leaf.Raw)
	value := uint64(digest[0])<<56 | uint64(digest[1])<<48 | uint64(digest[2])<<40 | uint64(digest[3])<<32 |
		uint64(digest[4])<<24 | uint64(digest[5])<<16 | uint64(digest[6])<<8 | uint64(digest[7])
	return time.Duration(value % uint64(window))
}

func (m *acmeDomainManager) install(resource *certificate.Resource, now time.Time) error {
	if resource == nil {
		return errors.New("ACME returned an empty certificate")
	}
	stored := storedACMECertificate{
		Version: acmeStateVersion, Domain: m.domain, CertURL: resource.CertURL, CertStableURL: resource.CertStableURL,
		PrivateKeyPEM: string(resource.PrivateKey), CertificatePEM: string(resource.Certificate), IssuerCertificate: string(resource.IssuerCertificate),
	}
	snapshot, err := validateACMECertificate(stored, m.domain, now)
	if err != nil {
		return err
	}
	if err := writePrivateJSON(m.stateDir, m.statePath, stored); err != nil {
		return err
	}
	m.current.Store(snapshot)
	return nil
}

func (m *acmeDomainManager) handleStream(logger *slog.Logger, stream *tunnel.Stream, upstream string) {
	m.handleStreamWithProxy(logger, stream, upstream, false)
}

func (m *acmeDomainManager) handleStreamWithProxy(logger *slog.Logger, stream *tunnel.Stream, upstream string, proxyProtocol bool) {
	m.activeStreams.Add(1)
	defer m.activeStreams.Add(-1)
	defer stream.Close()
	prefix := "domain:" + m.domain + ":"
	switch stream.Destination {
	case prefix + "80":
		timeout := m.challengeTimeout
		if timeout <= 0 {
			timeout = acmeChallengeTimeout
		}
		timer := time.AfterFunc(timeout, func() { _ = stream.Close() })
		m.serveChallenge(stream)
		timer.Stop()
	case prefix + "443":
		m.serveTLSWithProxy(logger, stream, upstream, proxyProtocol)
	}
}

func (m *acmeDomainManager) serveChallenge(stream io.Writer) {
	requestStream, ok := stream.(io.Reader)
	if !ok {
		return
	}
	limited := &io.LimitedReader{R: requestStream, N: acmeChallengeHeadLimit + 1}
	reader := bufio.NewReader(limited)
	req, err := http.ReadRequest(reader)
	if err != nil || limited.N == 0 || reader.Buffered() != 0 {
		writeACMEResponse(stream, http.StatusBadRequest, "")
		return
	}
	defer req.Body.Close()
	host := strings.ToLower(req.Host)
	hostMatches := host == m.domain || host == m.domain+":80"
	token := strings.TrimPrefix(req.URL.Path, "/.well-known/acme-challenge/")
	if req.Method != http.MethodGet || req.ProtoMajor != 1 || req.ProtoMinor != 1 || req.ContentLength > 0 ||
		len(req.TransferEncoding) != 0 || req.Header.Get("Expect") != "" || req.Header.Get("Upgrade") != "" ||
		req.URL.IsAbs() || !hostMatches || !acmeChallengeToken.MatchString(token) || req.URL.Path != http01.ChallengePath(token) ||
		req.URL.RawPath != "" || req.URL.RawQuery != "" || req.URL.Fragment != "" {
		writeACMEResponse(stream, http.StatusNotFound, "")
		return
	}
	m.proofMu.RLock()
	proof, found := m.proofs[token]
	m.proofMu.RUnlock()
	if !found {
		writeACMEResponse(stream, http.StatusNotFound, "")
		return
	}
	writeACMEResponse(stream, http.StatusOK, proof)
}

func writeACMEResponse(w io.Writer, status int, body string) {
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(body), body)
}

func (m *acmeDomainManager) serveTLS(logger *slog.Logger, stream *tunnel.Stream, upstream string) {
	m.serveTLSWithProxy(logger, stream, upstream, false)
}

func (m *acmeDomainManager) serveTLSWithProxy(logger *slog.Logger, stream *tunnel.Stream, upstream string, proxyProtocol bool) {
	snapshot := m.current.Load()
	if snapshot == nil || !m.hasUsableCertificate(m.now()) {
		return
	}
	conn := &streamNetConn{ReadWriteCloser: stream}
	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if strings.ToLower(hello.ServerName) != m.domain {
				return nil, errors.New("TLS SNI does not match the exact managed hostname")
			}
			current := m.current.Load()
			if current == nil || !m.hasUsableCertificate(m.now()) {
				return nil, errors.New("automatic TLS certificate is unavailable")
			}
			return current.certificate, nil
		},
	})
	timeout := m.handshakeTimeout
	if timeout <= 0 {
		timeout = acmeHandshakeTimeout
	}
	timer := time.AfterFunc(timeout, func() { _ = stream.Close() })
	handshakeCtx, cancel := context.WithTimeout(context.Background(), timeout)
	err := tlsConn.HandshakeContext(handshakeCtx)
	cancel()
	timer.Stop()
	if err != nil {
		return
	}
	up, err := net.DialTimeout("tcp", upstream, 5*time.Second)
	if err != nil {
		logger.Warn("dial plaintext upstream after automatic TLS termination", "upstream", upstream)
		return
	}
	if proxyProtocol {
		if err := proxyproto.WriteV2(up, stream.Source, stream.DestinationAddress); err != nil {
			logger.Warn("write PROXY protocol header", "err", err, "upstream", upstream)
			_ = up.Close()
			return
		}
	}
	tcpproxy.Proxy(tlsConn, up)
}

// Tunnel streams do not expose per-stream deadlines. Handshake and challenge
// callers enforce their bounds by closing the stream from a timer.
type streamNetConn struct{ io.ReadWriteCloser }

func (c *streamNetConn) LocalAddr() net.Addr              { return acmeAddr("agent") }
func (c *streamNetConn) RemoteAddr() net.Addr             { return acmeAddr("relay") }
func (c *streamNetConn) SetDeadline(time.Time) error      { return nil }
func (c *streamNetConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamNetConn) SetWriteDeadline(time.Time) error { return nil }

type acmeAddr string

func (a acmeAddr) Network() string { return "blindport" }
func (a acmeAddr) String() string  { return string(a) }

func loadACMECertificate(path, domain string, now time.Time) (*certificateSnapshot, error) {
	var stored storedACMECertificate
	if err := readPrivateJSON(path, &stored); err != nil {
		return nil, err
	}
	return parseACMECertificate(stored, domain, now, true)
}

func validateACMECertificate(stored storedACMECertificate, domain string, now time.Time) (*certificateSnapshot, error) {
	return parseACMECertificate(stored, domain, now, false)
}

func parseACMECertificate(stored storedACMECertificate, domain string, now time.Time, allowExpired bool) (*certificateSnapshot, error) {
	if stored.Version != acmeStateVersion || stored.Domain != domain {
		return nil, errors.New("persisted ACME certificate metadata is invalid")
	}
	pair, err := tls.X509KeyPair([]byte(stored.CertificatePEM), []byte(stored.PrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("load persisted ACME keypair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, errors.New("persisted ACME certificate chain is empty")
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse persisted ACME certificate: %w", err)
	}
	if !pair.Leaf.NotBefore.Before(pair.Leaf.NotAfter) || now.Before(pair.Leaf.NotBefore) || (!allowExpired && !now.Before(pair.Leaf.NotAfter)) {
		return nil, errors.New("persisted ACME certificate is not currently valid")
	}
	if err := pair.Leaf.VerifyHostname(domain); err != nil {
		return nil, fmt.Errorf("persisted ACME certificate does not authorize exact hostname: %w", err)
	}
	if pair.Leaf.IsCA || len(pair.Leaf.IPAddresses) != 0 || len(pair.Leaf.EmailAddresses) != 0 || len(pair.Leaf.URIs) != 0 ||
		len(pair.Leaf.DNSNames) != 1 || pair.Leaf.DNSNames[0] != domain || (pair.Leaf.Subject.CommonName != "" && pair.Leaf.Subject.CommonName != domain) {
		return nil, errors.New("persisted ACME certificate contains names outside the exact managed hostname")
	}
	resource := certificate.Resource{
		Domain: domain, CertURL: stored.CertURL, CertStableURL: stored.CertStableURL,
		PrivateKey: []byte(stored.PrivateKeyPEM), Certificate: []byte(stored.CertificatePEM), IssuerCertificate: []byte(stored.IssuerCertificate),
	}
	return &certificateSnapshot{certificate: &pair, resource: resource}, nil
}

func readPrivateJSON(path string, destination any) error {
	file, err := openStaticConfig(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("ACME state file must be regular with mode 0600")
	}
	if err := validateStaticConfigOwner(info); err != nil {
		return fmt.Errorf("ACME state file: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, acmeStateSizeLimit+1))
	if err != nil {
		return err
	}
	if len(data) > acmeStateSizeLimit {
		return errors.New("ACME state file exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode ACME state: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return fmt.Errorf("decode ACME state: %w", err)
	}
	return nil
}

func writePrivateJSON(directory, path string, value any) error {
	if filepath.Dir(path) != filepath.Clean(directory) {
		return errors.New("ACME state target must be directly inside its private directory")
	}
	if err := validatePrivateStateDirectory(directory); err != nil {
		return err
	}
	if err := validatePrivateStateTarget(path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode ACME state: %w", err)
	}
	data = append(data, '\n')
	if len(data) > acmeStateSizeLimit {
		return errors.New("ACME state exceeds size limit")
	}
	temporary, err := os.CreateTemp(directory, ".acme-*")
	if err != nil {
		return fmt.Errorf("create temporary ACME state: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := func() { _ = temporary.Close(); _ = os.Remove(temporaryPath) }
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Close(); err != nil {
		cleanup()
		return err
	}
	if err := validatePrivateStateTarget(path); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		cleanup()
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func validatePrivateStateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect ACME state directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("ACME state directory must be a nonsymlink directory with mode 0700")
	}
	if err := validateStaticConfigOwner(info); err != nil {
		return fmt.Errorf("ACME state directory: %w", err)
	}
	return nil
}

func validatePrivateStateTarget(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect ACME state target: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("existing ACME state target must be a regular file, not a symbolic link")
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("existing ACME state target must have mode 0600, got %04o", info.Mode().Perm())
	}
	if err := validateStaticConfigOwner(info); err != nil {
		return fmt.Errorf("existing ACME state target: %w", err)
	}
	return nil
}

func marshalECPrivateKey(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

func parseECPrivateKey(value string) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "EC PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected exactly one EC private key")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
