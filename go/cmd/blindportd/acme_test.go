package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/protocol"
	"github.com/blindport/blindport/internal/tunnel"
	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
)

func TestACMEChallengeIsSharedAcrossConcurrentRelayEdges(t *testing.T) {
	manager := &acmeDomainManager{domain: "service.example", proofs: make(map[string]string)}
	if err := manager.Present("service.example", "TOKEN", "TOKEN.PROOF"); err != nil {
		t.Fatal(err)
	}

	request := "GET /.well-known/acme-challenge/TOKEN HTTP/1.1\r\nHost: service.example\r\nConnection: close\r\n\r\n"
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			agentRaw, relayRaw := net.Pipe()
			agent := tunnel.New(agentRaw, func(stream *tunnel.Stream) { manager.handleStream(slog.Default(), stream, "unused:80") })
			relay := tunnel.New(relayRaw, nil)
			go func() { _ = agent.Run() }()
			go func() { _ = relay.Run() }()
			defer agent.Close()
			defer relay.Close()
			stream, err := relay.OpenStream("tcp", "192.0.2.1:1234", "domain:service.example:80")
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := io.WriteString(stream, request); err != nil {
				t.Error(err)
				return
			}
			response, err := io.ReadAll(stream)
			if err != nil || !strings.Contains(string(response), "200 OK") || !strings.HasSuffix(string(response), "TOKEN.PROOF") {
				t.Errorf("challenge response = %q, %v", response, err)
			}
		}()
	}
	workers.Wait()

	if err := manager.Present("other.example", "TOKEN", "SECRET"); err == nil {
		t.Fatal("challenge provider accepted a different hostname")
	}
}

func TestAutomaticTLSTerminatesAndForwardsPlaintext(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	resource, roots := testACMEResource(t, "service.example", now.Add(-time.Hour), now.Add(24*time.Hour), 1)
	dir := privateTempDir(t)
	manager := &acmeDomainManager{
		domain: "service.example", stateDir: dir, statePath: filepath.Join(dir, "service.example.json"),
		proofs: make(map[string]string), now: func() time.Time { return now },
	}
	if err := manager.install(resource, now); err != nil {
		t.Fatal(err)
	}

	origin := listenLocal(t)
	originDone := make(chan error, 1)
	go func() {
		conn, err := origin.Accept()
		if err != nil {
			originDone <- err
			return
		}
		defer conn.Close()
		payload := make([]byte, len("plaintext request"))
		if _, err := io.ReadFull(conn, payload); err != nil {
			originDone <- err
			return
		}
		if string(payload) != "plaintext request" {
			originDone <- &testError{message: "origin did not receive plaintext"}
			return
		}
		_, err = io.WriteString(conn, "origin response")
		originDone <- err
	}()

	agentRaw, relayRaw := net.Pipe()
	agent := tunnel.New(agentRaw, func(stream *tunnel.Stream) { manager.handleStream(slog.Default(), stream, origin.Addr().String()) })
	relay := tunnel.New(relayRaw, nil)
	agent.EnableTCPHalfClose()
	relay.EnableTCPHalfClose()
	go func() { _ = agent.Run() }()
	go func() { _ = relay.Run() }()
	defer agent.Close()
	defer relay.Close()
	stream, err := relay.OpenStream("tcp", "192.0.2.1:1234", "domain:service.example:443")
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(&streamNetConn{ReadWriteCloser: stream}, &tls.Config{
		RootCAs: roots, ServerName: "service.example", MinVersion: tls.VersionTLS12, Time: func() time.Time { return now },
	})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, "plaintext request"); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("origin response"))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "origin response" {
		t.Fatalf("TLS response = %q", response)
	}
	_ = client.Close()
	if err := <-originDone; err != nil {
		t.Fatal(err)
	}
}

func TestAutomaticTLSHandshakeTimeoutClosesBlockedStream(t *testing.T) {
	now := time.Now()
	resource, _ := testACMEResource(t, "service.example", now.Add(-time.Hour), now.Add(time.Hour), 1)
	dir := privateTempDir(t)
	manager := &acmeDomainManager{
		domain: "service.example", stateDir: dir, statePath: filepath.Join(dir, "service.example.json"),
		proofs: make(map[string]string), now: time.Now, handshakeTimeout: 25 * time.Millisecond,
	}
	if err := manager.install(resource, now); err != nil {
		t.Fatal(err)
	}
	agentRaw, relayRaw := net.Pipe()
	agent := tunnel.New(agentRaw, func(stream *tunnel.Stream) { manager.handleStream(slog.Default(), stream, "unused:80") })
	relay := tunnel.New(relayRaw, nil)
	go func() { _ = agent.Run() }()
	go func() { _ = relay.Run() }()
	defer agent.Close()
	defer relay.Close()
	stream, err := relay.OpenStream("tcp", "192.0.2.1:1234", "domain:service.example:443")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := io.ReadAll(stream); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("blocked TLS handshake cleanup took %s", elapsed)
	}
	waitForNoAutomaticStreams(t, manager)
	if err := manager.Present("service.example", "TOKEN", "TOKEN.PROOF"); err != nil {
		t.Fatal(err)
	}
	challenge, err := relay.OpenStream("tcp", "192.0.2.1:1234", "domain:service.example:80")
	if err != nil {
		t.Fatalf("control tunnel closed with timed-out sibling stream: %v", err)
	}
	if _, err := io.WriteString(challenge, "GET /.well-known/acme-challenge/TOKEN HTTP/1.1\r\nHost: service.example\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(challenge)
	if err != nil || !strings.Contains(string(response), "TOKEN.PROOF") {
		t.Fatalf("control tunnel was not reusable after handshake timeout: %q, %v", response, err)
	}
}

func TestACMEChallengeLimitsCleanupAndStreamRelease(t *testing.T) {
	manager := &acmeDomainManager{
		domain: "service.example", proofs: make(map[string]string), challengeTimeout: 25 * time.Millisecond,
	}
	if err := manager.Present("service.example", "TOKEN", "TOKEN.PROOF"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		request string
	}{
		{name: "body rejected", request: "GET /.well-known/acme-challenge/TOKEN HTTP/1.1\r\nHost: service.example\r\nContent-Length: 1\r\n\r\nx"},
		{name: "unframed bytes rejected", request: "GET /.well-known/acme-challenge/TOKEN HTTP/1.1\r\nHost: service.example\r\n\r\nextra"},
		{name: "bracketed DNS host rejected", request: "GET /.well-known/acme-challenge/TOKEN HTTP/1.1\r\nHost: [service.example]:80\r\n\r\n"},
		{name: "encoded token path rejected", request: "GET /.well-known/acme-challenge/%54OKEN HTTP/1.1\r\nHost: service.example\r\n\r\n"},
		{name: "oversized header", request: "GET /.well-known/acme-challenge/TOKEN HTTP/1.1\r\nHost: service.example\r\nX-Fill: " + strings.Repeat("x", acmeChallengeHeadLimit) + "\r\n\r\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := roundTripChallengeStream(t, manager, test.request)
			if strings.Contains(response, "TOKEN.PROOF") {
				t.Fatalf("rejected challenge exposed proof: %q", response)
			}
			waitForNoAutomaticStreams(t, manager)
		})
	}

	agentRaw, relayRaw := net.Pipe()
	agent := tunnel.New(agentRaw, func(stream *tunnel.Stream) { manager.handleStream(slog.Default(), stream, "unused:80") })
	relay := tunnel.New(relayRaw, nil)
	go func() { _ = agent.Run() }()
	go func() { _ = relay.Run() }()
	stream, err := relay.OpenStream("tcp", "192.0.2.1:1234", "domain:service.example:80")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := io.ReadAll(stream); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("stalled challenge cleanup took %s", elapsed)
	}
	_ = agent.Close()
	_ = relay.Close()
	waitForNoAutomaticStreams(t, manager)

	if err := manager.CleanUp("service.example", "TOKEN", "TOKEN.PROOF"); err != nil {
		t.Fatal(err)
	}
	if response := roundTripChallengeStream(t, manager, "GET /.well-known/acme-challenge/TOKEN HTTP/1.1\r\nHost: service.example\r\n\r\n"); strings.Contains(response, "TOKEN.PROOF") {
		t.Fatalf("cleaned challenge remained active: %q", response)
	}
	if err := manager.Present("service.example", "SECOND", "SECOND.PROOF"); err != nil {
		t.Fatal(err)
	}
	manager.stop()
	manager.proofMu.RLock()
	proofCount := len(manager.proofs)
	manager.proofMu.RUnlock()
	if proofCount != 0 {
		t.Fatalf("stopped manager retained %d challenge proofs", proofCount)
	}
}

func TestACMEStatePersistenceRenewalAndSafety(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	dir := privateTempDir(t)
	path := filepath.Join(dir, "service.example.json")
	manager := &acmeDomainManager{domain: "service.example", stateDir: dir, statePath: path, proofs: make(map[string]string)}
	first, _ := testACMEResource(t, "service.example", now.Add(-time.Hour), now.Add(24*time.Hour), 1)
	if err := manager.install(first, now); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("certificate state mode = %v, %v", info, err)
	}
	loaded, err := loadACMECertificate(path, "service.example", now)
	if err != nil || loaded.certificate.Leaf.SerialNumber.Int64() != 1 {
		t.Fatalf("loaded certificate = %+v, %v", loaded, err)
	}
	second, _ := testACMEResource(t, "service.example", now.Add(-time.Hour), now.Add(48*time.Hour), 2)
	if err := manager.install(second, now); err != nil {
		t.Fatal(err)
	}
	if manager.current.Load().certificate.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("hot certificate pointer was not replaced")
	}
	leaf := manager.current.Load().certificate.Leaf
	baseRenewal := leaf.NotAfter.Add(-leaf.NotAfter.Sub(leaf.NotBefore) / 3)
	if got := certificateRenewalTime(leaf, nil); got.After(baseRenewal) || got.Before(baseRenewal.Add(-leaf.NotAfter.Sub(leaf.NotBefore)/30)) {
		t.Fatalf("fallback renewal time = %s outside conservative jitter window", got)
	}

	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadACMECertificate(path, "service.example", now); err == nil {
		t.Fatal("corrupt certificate state was accepted")
	}
	extraIdentity, _ := testACMEResourceWithTemplate(t, "service.example", now.Add(-time.Hour), now.Add(time.Hour), 3, func(template *x509.Certificate) {
		template.URIs = []*url.URL{{Scheme: "spiffe", Host: "other.example"}}
	})
	if err := manager.install(extraIdentity, now); err == nil {
		t.Fatal("certificate with a non-DNS SAN identity was accepted")
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	var stored storedACMECertificate
	if err := readPrivateJSON(link, &stored); err == nil {
		t.Fatal("symlinked ACME state was accepted")
	}
}

func TestWritePrivateJSONRejectsPostStartTampering(t *testing.T) {
	now := time.Now()
	first, _ := testACMEResource(t, "service.example", now.Add(-time.Hour), now.Add(time.Hour), 1)
	second, _ := testACMEResource(t, "service.example", now.Add(-time.Hour), now.Add(2*time.Hour), 2)
	for _, test := range []struct {
		name   string
		tamper func(*testing.T, string)
	}{
		{name: "symlink", tamper: func(t *testing.T, path string) {
			target := filepath.Join(filepath.Dir(path), "attacker-target")
			if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unsafe mode", tamper: func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "nonregular", tamper: func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unsafe directory mode", tamper: func(t *testing.T, path string) {
			if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := privateTempDir(t)
			path := filepath.Join(dir, "service.example.json")
			manager := &acmeDomainManager{domain: "service.example", stateDir: dir, statePath: path, proofs: make(map[string]string)}
			if err := manager.install(first, now); err != nil {
				t.Fatal(err)
			}
			test.tamper(t, path)
			if err := manager.install(second, now); err == nil {
				t.Fatal("post-start state tampering was replaced")
			}
			if test.name == "symlink" {
				contents, err := os.ReadFile(filepath.Join(dir, "attacker-target"))
				if err != nil || string(contents) != "unchanged" {
					t.Fatalf("symlink target changed: %q, %v", contents, err)
				}
			}
		})
	}
}

func TestWritePrivateJSONRejectsOversizedState(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "account.json")
	value := storedACMEAccount{Version: acmeStateVersion, PrivateKey: strings.Repeat("x", acmeStateSizeLimit)}
	if err := writePrivateJSON(dir, path, value); err == nil {
		t.Fatal("oversized ACME state was written")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversized ACME state left a target: %v", err)
	}
}

func TestACMEInitialIssuanceWaitsForEdgeAndUsesBoundedRetries(t *testing.T) {
	now := time.Now()
	resource, _ := testACMEResource(t, "service.example", now.Add(-time.Hour), now.Add(time.Hour), 1)
	dir := privateTempDir(t)
	manager := &acmeDomainManager{
		domain: "service.example", stateDir: dir, statePath: filepath.Join(dir, "service.example.json"),
		proofs: make(map[string]string), ready: make(chan struct{}), now: time.Now, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		retryDelay: func(bool, int) time.Duration { return 5 * time.Millisecond },
	}
	var calls atomic.Int32
	manager.issue = func(_ context.Context, _ *certificate.Resource, _ challenge.Provider) (*certificate.Resource, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("edge not settled")
		}
		return resource, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { manager.run(ctx); close(done) }()
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatalf("issuance started before an edge was ready: calls=%d", calls.Load())
	}
	manager.edgeReady()
	deadline := time.Now().Add(time.Second)
	for manager.current.Load() == nil {
		if time.Now().After(deadline) {
			t.Fatal("initial certificate was not installed after retry")
		}
		time.Sleep(time.Millisecond)
	}
	if calls.Load() != 2 {
		t.Fatalf("issuance calls = %d, want 2", calls.Load())
	}
	cancel()
	<-done
	if got := []time.Duration{acmeRetryDelay(false, 1), acmeRetryDelay(false, 2), acmeRetryDelay(false, 3), acmeRetryDelay(false, 4)}; got[0] != time.Minute || got[1] != 2*time.Minute || got[2] != 4*time.Minute || got[3] != 8*time.Minute {
		t.Fatalf("first-use retry schedule = %v", got)
	}
}

func TestACMEDueRenewalWaitsForEdge(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	dir := privateTempDir(t)
	first, _ := testACMEResource(t, "service.example", now.Add(-48*time.Hour), now.Add(time.Hour), 1)
	second, _ := testACMEResource(t, "service.example", now.Add(-time.Hour), now.Add(48*time.Hour), 2)
	manager := &acmeDomainManager{
		domain: "service.example", stateDir: dir, statePath: filepath.Join(dir, "service.example.json"),
		proofs: make(map[string]string), ready: make(chan struct{}), now: func() time.Time { return now },
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := manager.install(first, now); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	manager.issue = func(_ context.Context, _ *certificate.Resource, _ challenge.Provider) (*certificate.Resource, error) {
		calls.Add(1)
		return second, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { manager.run(ctx); close(done) }()
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatalf("renewal started before an edge was ready: calls=%d", calls.Load())
	}
	manager.edgeReady()
	deadline := time.Now().Add(time.Second)
	for manager.current.Load().certificate.Leaf.SerialNumber.Int64() != 2 {
		if time.Now().After(deadline) {
			t.Fatal("due certificate was not renewed after an edge became ready")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
}

func TestACMEManagerStopCancelsOperation(t *testing.T) {
	managerCtx, cancel := context.WithCancel(context.Background())
	manager := &acmeDomainManager{
		domain: "service.example", proofs: make(map[string]string), cancel: cancel, done: make(chan struct{}),
		now: time.Now, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	started := make(chan struct{})
	manager.issue = func(ctx context.Context, _ *certificate.Resource, _ challenge.Provider) (*certificate.Resource, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	go func() {
		defer close(manager.done)
		manager.run(managerCtx)
	}()
	<-started
	stopped := make(chan struct{})
	go func() {
		manager.stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("manager stop did not cancel an in-flight ACME operation")
	}
}

func TestCertificateRenewalTimeUsesConservativeARIWindow(t *testing.T) {
	now := time.Now().UTC()
	resource, _ := testACMEResource(t, "service.example", now.Add(-24*time.Hour), now.Add(60*24*time.Hour), 1)
	pair, err := tls.X509KeyPair(resource.Certificate, resource.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	start := now.Add(10 * 24 * time.Hour)
	end := start.Add(10 * 24 * time.Hour)
	info := &certificate.RenewalInfoResponse{RenewalInfoResponse: legoacme.RenewalInfoResponse{SuggestedWindow: legoacme.Window{Start: start, End: end}}}
	got := certificateRenewalTime(pair.Leaf, info)
	if got.Before(start) || !got.Before(start.Add(end.Sub(start)/2)) {
		t.Fatalf("ARI renewal time = %s, want first half of %s to %s", got, start, end)
	}
	if repeated := certificateRenewalTime(pair.Leaf, info); !repeated.Equal(got) {
		t.Fatalf("ARI schedule is not deterministic: %s != %s", repeated, got)
	}
	invalid := &certificate.RenewalInfoResponse{RenewalInfoResponse: legoacme.RenewalInfoResponse{SuggestedWindow: legoacme.Window{Start: end, End: start}}}
	if gotInvalid, fallback := certificateRenewalTime(pair.Leaf, invalid), certificateRenewalTime(pair.Leaf, nil); !gotInvalid.Equal(fallback) {
		t.Fatalf("invalid ARI window = %s, want fallback %s", gotInvalid, fallback)
	}
}

func TestACMERenewalLoopHotReloadsDueCertificate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	dir := privateTempDir(t)
	first, _ := testACMEResource(t, "service.example", now.Add(-48*time.Hour), now.Add(time.Hour), 1)
	second, _ := testACMEResource(t, "service.example", now.Add(-time.Hour), now.Add(48*time.Hour), 2)
	manager := &acmeDomainManager{
		domain: "service.example", stateDir: dir, statePath: filepath.Join(dir, "service.example.json"),
		proofs: make(map[string]string), now: func() time.Time { return now },
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := manager.install(first, now); err != nil {
		t.Fatal(err)
	}
	issued := make(chan struct{}, 1)
	ariCalled := make(chan struct{}, 1)
	manager.renewalInfo = func(_ context.Context, current *certificateSnapshot) (*certificate.RenewalInfoResponse, error) {
		select {
		case ariCalled <- struct{}{}:
		default:
		}
		if current.certificate.Leaf.SerialNumber.Int64() == 2 {
			return &certificate.RenewalInfoResponse{RenewalInfoResponse: legoacme.RenewalInfoResponse{SuggestedWindow: legoacme.Window{
				Start: now.Add(24 * time.Hour), End: now.Add(25 * time.Hour),
			}}}, nil
		}
		return &certificate.RenewalInfoResponse{RenewalInfoResponse: legoacme.RenewalInfoResponse{SuggestedWindow: legoacme.Window{
			Start: now.Add(-time.Hour), End: now.Add(-time.Minute),
		}}}, nil
	}
	manager.issue = func(_ context.Context, current *certificate.Resource, _ challenge.Provider) (*certificate.Resource, error) {
		if current == nil || current.Domain != "service.example" {
			t.Fatal("renewal did not receive persisted certificate resource")
		}
		issued <- struct{}{}
		return second, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { manager.run(ctx); close(done) }()
	select {
	case <-ariCalled:
	case <-time.After(time.Second):
		t.Fatal("renewal loop did not query lego ARI")
	}
	select {
	case <-issued:
	case <-time.After(time.Second):
		t.Fatal("due certificate was not renewed")
	}
	deadline := time.Now().Add(time.Second)
	for manager.current.Load().certificate.Leaf.SerialNumber.Int64() != 2 {
		if time.Now().After(deadline) {
			t.Fatal("renewed certificate was not hot reloaded")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("renewal loop did not stop")
	}
}

func TestACMEAccountPersistsPrivateKeyAndRegistryRemovesMapping(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	registry, err := newACMERegistry(context.Background(), stateDir, "https://pebble.invalid/directory", "ops@example.test", &http.Client{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	stored, user, err := registry.account.loadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if stored.PrivateKey == "" || user.GetPrivateKey() == nil {
		t.Fatal("ACME account key was not persisted")
	}
	accountInfo, err := os.Stat(filepath.Join(stateDir, "acme", "account.json"))
	if err != nil || accountInfo.Mode().Perm() != 0o600 {
		t.Fatalf("account state mode = %v, %v", accountInfo, err)
	}

	created := 0
	registry.factory = func(domain string) (*acmeDomainManager, error) {
		created++
		_, cancel := context.WithCancel(context.Background())
		return &acmeDomainManager{domain: domain, cancel: cancel}, nil
	}
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "service.example"}
	plans := []workerPlan{
		{RelayAddr: "edge-a:5443", TLSMode: tlsModeAutomatic, Claim: claim},
		{RelayAddr: "edge-b:5443", TLSMode: tlsModeAutomatic, Claim: claim},
	}
	if err := registry.Reconcile(plans); err != nil {
		t.Fatal(err)
	}
	if created != 1 || registry.manager("service.example") == nil {
		t.Fatalf("shared managers created = %d", created)
	}
	if err := registry.Reconcile(nil); err != nil {
		t.Fatal(err)
	}
	if registry.manager("service.example") != nil {
		t.Fatal("mapping removal retained its manager")
	}
}

func TestACMERegistryRejectsPersistedAccountForDifferentDirectory(t *testing.T) {
	stateDir := privateTempDir(t)
	registry, err := newACMERegistry(context.Background(), stateDir, "https://first.invalid/directory", "ops@example.test", &http.Client{}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := registry.account.loadOrCreate(); err != nil {
		t.Fatal(err)
	}
	registry.Close()
	if _, err := newACMERegistry(context.Background(), stateDir, "https://second.invalid/directory", "ops@example.test", &http.Client{}, slog.Default()); err == nil {
		t.Fatal("persisted ACME account was reused with a different directory")
	}
}

func TestNewACMERegistryRejectsUnsafeDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := newACMERegistry(context.Background(), dir, "https://pebble.invalid/directory", "", &http.Client{}, slog.Default()); err == nil {
		t.Fatal("unsafe state directory was accepted")
	}
}

func TestLazyACMERegistryDoesNotTouchStateWithoutAutomaticPlans(t *testing.T) {
	registry, err := newLazyACMERegistry(context.Background(), "", "", "", nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Reconcile(nil); err != nil {
		t.Fatal(err)
	}
	registry.Close()
	if registry.initialized {
		t.Fatal("legacy reconciliation initialized ACME state")
	}
}

func TestPebbleAutomaticTLSIntegration(t *testing.T) {
	directoryURL := os.Getenv("BLINDPORT_PEBBLE_DIRECTORY_URL")
	if directoryURL == "" {
		t.Skip("set BLINDPORT_PEBBLE_DIRECTORY_URL for a local Pebble configured with PEBBLE_VA_ALWAYS_VALID=1")
	}
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Pebble's development directory uses its generated private test CA.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 30 * time.Second} //nolint:gosec
	registry, err := newACMERegistry(context.Background(), stateDir, directoryURL, "pebble@example.test", client, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	manager := &acmeDomainManager{domain: "service.example", proofs: make(map[string]string)}
	resource, err := registry.account.issue(context.Background(), manager.domain, nil, manager)
	if err != nil {
		t.Fatal(err)
	}
	manager.stateDir = registry.certDir
	manager.statePath = filepath.Join(registry.certDir, manager.domain+".json")
	if err := manager.install(resource, time.Now()); err != nil {
		t.Fatal(err)
	}
	if manager.current.Load() == nil || manager.current.Load().certificate.Leaf.DNSNames[0] != manager.domain {
		t.Fatal("Pebble certificate was not installed for the exact hostname")
	}
	registry.account.email = "updated-pebble@example.test"
	resource, err = registry.account.issue(context.Background(), manager.domain, resource, manager)
	if err != nil {
		t.Fatal(err)
	}
	var stored storedACMEAccount
	if err := readPrivateJSON(registry.account.statePath, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Email != registry.account.email {
		t.Fatalf("updated ACME account email = %q", stored.Email)
	}
}

type testError struct{ message string }

func (e *testError) Error() string { return e.message }

func roundTripChallengeStream(t *testing.T, manager *acmeDomainManager, request string) string {
	t.Helper()
	agentRaw, relayRaw := net.Pipe()
	agent := tunnel.New(agentRaw, func(stream *tunnel.Stream) { manager.handleStream(slog.Default(), stream, "unused:80") })
	relay := tunnel.New(relayRaw, nil)
	go func() { _ = agent.Run() }()
	go func() { _ = relay.Run() }()
	defer agent.Close()
	defer relay.Close()
	stream, err := relay.OpenStream("tcp", "192.0.2.1:1234", "domain:service.example:80")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(stream, request); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	return string(response)
}

func waitForNoAutomaticStreams(t *testing.T, manager *acmeDomainManager) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for manager.activeStreams.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("automatic TLS streams remained active: %d", manager.activeStreams.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testACMEResource(t *testing.T, domain string, notBefore, notAfter time.Time, serial int64) (*certificate.Resource, *x509.CertPool) {
	return testACMEResourceWithTemplate(t, domain, notBefore, notAfter, serial, nil)
}

func testACMEResourceWithTemplate(t *testing.T, domain string, notBefore, notAfter time.Time, serial int64, configure func(*x509.Certificate)) (*certificate.Resource, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	if configure != nil {
		configure(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	return &certificate.Resource{Domain: domain, Certificate: certPEM, PrivateKey: keyPEM}, roots
}
