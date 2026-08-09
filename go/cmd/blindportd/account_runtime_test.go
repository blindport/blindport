package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLoadStaticAccountTokenRequiresPrivateRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("ACCOUNT-TOKEN\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := loadStaticAccountToken(path)
	if err != nil || token != "ACCOUNT-TOKEN" {
		t.Fatalf("loadStaticAccountToken() = %q, %v", token, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStaticAccountToken(path); err == nil {
		t.Fatal("group-readable account token was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "token-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStaticAccountToken(link); err == nil {
		t.Fatal("symlink account token was accepted")
	}
	if _, err := loadStaticAccountToken("relative-token"); err == nil {
		t.Fatal("relative account token was accepted")
	}
	if err := os.WriteFile(path, []byte("two tokens\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStaticAccountToken(path); err == nil {
		t.Fatal("invalid account token was accepted")
	}
}

func TestAccountStateDirectoryIsPrivateAndNotASymlink(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := prepareCredentialStateDir(stateDir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("state directory mode = %04o", info.Mode().Perm())
	}
	link := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(stateDir, link); err != nil {
		t.Fatal(err)
	}
	if err := prepareCredentialStateDir(link); err == nil {
		t.Fatal("symlink state directory was accepted")
	}
}

func TestAccountRuntimesScopeMappingsWorkersAndCachePaths(t *testing.T) {
	accounts := []staticAccount{
		{Name: "public", TokenFile: "/run/secrets/public", StateDir: "/var/lib/blindport/accounts/public", Mappings: []mapping{{SubscriptionID: testSubscriptionID1, Upstream: "public:80"}}},
		{Name: "private", TokenFile: "/run/secrets/private", StateDir: "/var/lib/blindport/accounts/private", Mappings: []mapping{{SubscriptionID: testSubscriptionID2, Upstream: "private:80"}}},
	}
	runtimes := newAccountRuntimes(accounts, framedRuntimeOptions{backend: "https://blindport.example"})
	if len(runtimes) != 2 || runtimes[0].options.stateDir == runtimes[1].options.stateDir || runtimes[0].coordinator == runtimes[1].coordinator {
		t.Fatalf("account runtimes = %+v", runtimes)
	}
	if runtimes[0].mappings[0].AccountName != "public" || runtimes[1].coordinator.mappings[0].AccountName != "private" {
		t.Fatalf("account mappings = %+v, %+v", runtimes[0].mappings, runtimes[1].coordinator.mappings)
	}
	firstCache, secondCache := authorizationCache{stateDir: runtimes[0].stateDir}, authorizationCache{stateDir: runtimes[1].stateDir}
	if firstCache.path() == secondCache.path() || firstCache.v3Path() == secondCache.v3Path() {
		t.Fatal("account authorization caches share a path")
	}

	events := make(chan workerEvent, 4)
	supervisor := newWorkerSupervisor(context.Background(), func(ctx context.Context, plan workerPlan) {
		events <- workerEvent{kind: "start", plan: plan}
		<-ctx.Done()
	})
	defer supervisor.Shutdown()
	plans := []workerPlan{
		{AccountName: "public", SubscriptionID: testSubscriptionID1, RelayAddr: "edge.example:5443", Upstream: "public:80"},
		{AccountName: "private", SubscriptionID: testSubscriptionID1, RelayAddr: "edge.example:5443", Upstream: "private:80"},
	}
	if err := supervisor.Reconcile(plans); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for range plans {
		select {
		case event := <-events:
			seen[event.plan.AccountName] = true
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for scoped workers")
		}
	}
	if !seen["public"] || !seen["private"] {
		t.Fatalf("worker accounts = %v", seen)
	}
}

func TestAccountRuntimeFailureDoesNotCancelOtherAccounts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	privateStarted := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runAccountRuntimes(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), testAccountRuntimes(), func(ctx context.Context, _ *slog.Logger, runtime accountRuntime) error {
			if runtime.name == "public" {
				return errors.New("public failed")
			}
			close(privateStarted)
			<-ctx.Done()
			return nil
		})
	}()
	select {
	case <-privateStarted:
	case <-time.After(time.Second):
		t.Fatal("healthy account was canceled before starting")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runAccountRuntimes() = %v", err)
	}
}

func TestAccountRuntimeReturnsErrorWhenAllAccountsFail(t *testing.T) {
	err := runAccountRuntimes(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), testAccountRuntimes(), func(context.Context, *slog.Logger, accountRuntime) error {
		return errors.New("failed")
	})
	if err == nil || !strings.Contains(err.Error(), "all 2 account runtimes") {
		t.Fatalf("runAccountRuntimes() error = %v", err)
	}
}

func TestAccountRuntimeCancellationWaitsForAllAccounts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 2)
	var finished sync.WaitGroup
	finished.Add(2)
	done := make(chan error, 1)
	go func() {
		done <- runAccountRuntimes(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), testAccountRuntimes(), func(ctx context.Context, _ *slog.Logger, _ accountRuntime) error {
			started <- struct{}{}
			<-ctx.Done()
			finished.Done()
			return nil
		})
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("account runtime did not start")
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runAccountRuntimes() = %v", err)
	}
	finished.Wait()
}

func TestValidateStaticV3InvocationRejectsUnsupportedModes(t *testing.T) {
	if err := validateStaticV3Invocation(true, false, false, nil); err == nil {
		t.Fatal("WireGuard mode was accepted")
	}
	if err := validateStaticV3Invocation(false, false, true, nil); err != nil {
		t.Fatalf("Docker mode was rejected: %v", err)
	}
	if err := validateStaticV3Invocation(false, false, false, map[string]bool{"kind": true}); err == nil {
		t.Fatal("legacy flag was accepted")
	}
	if err := validateStaticV3Invocation(false, true, false, nil); err == nil {
		t.Fatal("WireGuard gateway mode was accepted")
	}
	if err := validateStaticV3Invocation(false, false, false, map[string]bool{"wireguard-inbound-tcp-ports": true}); err == nil {
		t.Fatal("WireGuard gateway setting was accepted")
	}
}

func testAccountRuntimes() []accountRuntime {
	return []accountRuntime{{name: "public"}, {name: "private"}}
}
