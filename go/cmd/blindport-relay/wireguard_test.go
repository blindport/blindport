package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/relayauth"
	"github.com/blindport/blindport/internal/wgnet"
)

type fakePeersFetcher struct {
	state *relayauth.WireGuardDesiredState
	err   error
}

func (f *fakePeersFetcher) WireGuardPeers(context.Context) (*relayauth.WireGuardDesiredState, error) {
	return f.state, f.err
}

type fakeWireGuardApplier struct {
	applied    []*wgnet.DesiredState
	failClosed int
	applyErr   error
}

func (f *fakeWireGuardApplier) Apply(state *wgnet.DesiredState) error {
	f.applied = append(f.applied, state)
	return f.applyErr
}

func (f *fakeWireGuardApplier) FailClosed() error {
	f.failClosed++
	return nil
}

func wireGuardTestKey() string {
	raw := make([]byte, 32)
	for index := range raw {
		raw[index] = byte(index + 1)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestWireGuardManagerAppliesDesiredStateAndReportsHealth(t *testing.T) {
	health := newRelayHealth(false, time.Minute, time.Minute)
	health.wgNeeded.Store(true)
	metrics := &relayMetrics{health: health}
	fetcher := &fakePeersFetcher{state: &relayauth.WireGuardDesiredState{
		Revision:            "r1",
		ManagedPrefixes:     []string{"198.51.100.20/32", "198.51.100.21/32"},
		SMTPAllowedPrefixes: []string{"198.51.100.20/32"},
		Peers: []relayauth.WireGuardPeer{{
			PublicKey:       wireGuardTestKey(),
			AllowedPrefixes: []string{"198.51.100.20/32"},
		}},
	}}
	applier := &fakeWireGuardApplier{}
	manager := newWireGuardManager(slog.Default(), fetcher, applier, time.Second, 2*time.Second, health, metrics)

	manager.cycle(context.Background())

	if len(applier.applied) != 1 || applier.applied[0].Revision != "r1" {
		t.Fatalf("applied = %+v", applier.applied)
	}
	if len(applier.applied[0].SMTPAllowedPrefixes) != 1 || applier.applied[0].SMTPAllowedPrefixes[0] != "198.51.100.20/32" {
		t.Fatalf("SMTP allowed prefixes = %v", applier.applied[0].SMTPAllowedPrefixes)
	}
	if health.wgState.Load() != wgHealthy {
		t.Fatalf("wireguard health state = %d", health.wgState.Load())
	}
	if metrics.wireguard.peers.Load() != 1 || metrics.wireguard.activePrefixes.Load() != 1 {
		t.Fatalf("metrics peers/prefixes = %d/%d",
			metrics.wireguard.peers.Load(), metrics.wireguard.activePrefixes.Load())
	}
}

func TestWireGuardManagerFailsClosedAfterStaleBackendState(t *testing.T) {
	health := newRelayHealth(false, time.Minute, time.Minute)
	health.wgNeeded.Store(true)
	metrics := &relayMetrics{health: health}
	fetcher := &fakePeersFetcher{state: &relayauth.WireGuardDesiredState{
		Revision:        "r1",
		ManagedPrefixes: []string{"198.51.100.20/32"},
	}}
	applier := &fakeWireGuardApplier{}
	manager := newWireGuardManager(slog.Default(), fetcher, applier, time.Second, 2*time.Second, health, metrics)

	manager.cycle(context.Background())
	fetcher.err = errors.New("backend unavailable")
	if applier.failClosed != 0 {
		t.Fatal("manager failed closed before staleness elapsed")
	}
	manager.lastSuccess = time.Now().Add(-3 * time.Second)
	manager.cycle(context.Background())
	if applier.failClosed != 1 {
		t.Fatalf("failClosed count = %d, want 1", applier.failClosed)
	}
	if health.wgState.Load() != wgUnavailable || health.ready(time.Now()) {
		t.Fatal("stale WireGuard state did not remove readiness")
	}
	manager.cycle(context.Background())
	if applier.failClosed != 1 {
		t.Fatal("manager repeated fail-closed application")
	}
}

func TestWireGuardManagerFailsClosedImmediatelyWithoutInitialSnapshot(t *testing.T) {
	health := newRelayHealth(false, time.Minute, time.Minute)
	health.wgNeeded.Store(true)
	metrics := &relayMetrics{health: health}
	fetcher := &fakePeersFetcher{err: errors.New("backend unavailable")}
	applier := &fakeWireGuardApplier{}
	manager := newWireGuardManager(slog.Default(), fetcher, applier, time.Second, 2*time.Second, health, metrics)

	manager.cycle(context.Background())

	if applier.failClosed != 1 {
		t.Fatalf("failClosed count = %d, want 1", applier.failClosed)
	}
}

func TestWireGuardManagerApplyFailureHonorsMaximumStaleness(t *testing.T) {
	health := newRelayHealth(false, time.Minute, time.Minute)
	health.wgNeeded.Store(true)
	metrics := &relayMetrics{health: health}
	fetcher := &fakePeersFetcher{state: &relayauth.WireGuardDesiredState{
		Revision:        "r1",
		ManagedPrefixes: []string{"198.51.100.20/32"},
	}}
	applier := &fakeWireGuardApplier{applyErr: errors.New("netlink apply failed")}
	manager := newWireGuardManager(slog.Default(), fetcher, applier, time.Second, 2*time.Second, health, metrics)
	manager.lastSuccess = time.Now().Add(-3 * time.Second)

	manager.cycle(context.Background())

	if applier.failClosed != 1 {
		t.Fatalf("failClosed count = %d, want 1", applier.failClosed)
	}
	if health.wgState.Load() != wgUnavailable {
		t.Fatalf("wireguard health state = %d, want unavailable", health.wgState.Load())
	}
}

func TestWireGuardManagerFailsClosedOnShutdown(t *testing.T) {
	health := newRelayHealth(false, time.Minute, time.Minute)
	health.wgNeeded.Store(true)
	metrics := &relayMetrics{health: health}
	fetcher := &fakePeersFetcher{state: &relayauth.WireGuardDesiredState{
		Revision:        "r1",
		ManagedPrefixes: []string{"198.51.100.20/32"},
	}}
	applier := &fakeWireGuardApplier{}
	manager := newWireGuardManager(slog.Default(), fetcher, applier, time.Second, 2*time.Second, health, metrics)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	manager.run(ctx)

	if applier.failClosed != 1 {
		t.Fatalf("failClosed count = %d, want 1", applier.failClosed)
	}
}

func TestWireGuardManagerRecoversAfterFailClosed(t *testing.T) {
	health := newRelayHealth(false, time.Minute, time.Minute)
	health.wgNeeded.Store(true)
	metrics := &relayMetrics{health: health}
	fetcher := &fakePeersFetcher{err: errors.New("backend unavailable")}
	applier := &fakeWireGuardApplier{}
	manager := newWireGuardManager(slog.Default(), fetcher, applier, time.Second, 2*time.Second, health, metrics)
	manager.lastSuccess = time.Now().Add(-3 * time.Second)
	manager.cycle(context.Background())

	fetcher.err = nil
	fetcher.state = &relayauth.WireGuardDesiredState{
		Revision:        "r2",
		ManagedPrefixes: []string{"198.51.100.20/32"},
	}
	manager.cycle(context.Background())
	if health.wgState.Load() != wgHealthy {
		t.Fatalf("recovered health state = %d", health.wgState.Load())
	}
}

func TestLoadRelayWireGuardKeyPersistsAndValidatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wireguard.key")
	created, err := loadRelayWireGuardKey(path, "")
	if err != nil {
		t.Fatalf("loadRelayWireGuardKey() error = %v", err)
	}
	reloaded, err := loadRelayWireGuardKey(path, "")
	if err != nil || reloaded.String() != created.String() {
		t.Fatalf("reloaded key = %s, %v", reloaded, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, %v", info.Mode(), err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRelayWireGuardKey(path, ""); err == nil {
		t.Fatal("exposed key file accepted")
	}

	if _, err := loadRelayWireGuardKey("", ""); err == nil {
		t.Fatal("missing key configuration accepted")
	}
	fromEnv, err := loadRelayWireGuardKey("", created.String())
	if err != nil || fromEnv.String() != created.String() {
		t.Fatalf("environment key = %s, %v", fromEnv, err)
	}
}

func TestValidateWireGuardConfigBounds(t *testing.T) {
	if err := validateWireGuardConfig(10*time.Second, 90*time.Second, 1420, 51820); err != nil {
		t.Fatalf("validateWireGuardConfig() error = %v", err)
	}
	invalid := []struct {
		interval, staleness time.Duration
		mtu, port           int
	}{
		{time.Millisecond, 90 * time.Second, 1420, 51820},
		{10 * time.Second, 15 * time.Second, 1420, 51820},
		{10 * time.Second, 90 * time.Second, 1200, 51820},
		{10 * time.Second, 90 * time.Second, 1421, 51820},
		{10 * time.Second, 90 * time.Second, 1420, 0},
	}
	for index, item := range invalid {
		if err := validateWireGuardConfig(item.interval, item.staleness, item.mtu, item.port); err == nil {
			t.Fatalf("case %d accepted invalid configuration", index)
		}
	}
}
