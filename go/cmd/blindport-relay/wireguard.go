package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/blindport/blindport/internal/relayauth"
	"github.com/blindport/blindport/internal/wgnet"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wireGuardStateFetcher interface {
	WireGuardPeers(ctx context.Context) (*relayauth.WireGuardDesiredState, error)
}

type wireGuardApplier interface {
	Apply(state *wgnet.DesiredState) error
	FailClosed() error
}

// wireGuardManager reconciles backend desired state into the kernel plane.
type wireGuardManager struct {
	log          *slog.Logger
	fetcher      wireGuardStateFetcher
	reconciler   wireGuardApplier
	interval     time.Duration
	maxStaleness time.Duration
	health       *relayHealth
	metrics      *relayMetrics
	lastSuccess  time.Time
	failedClosed bool
}

func validateWireGuardConfig(interval, maxStaleness time.Duration, mtu, listenPort int) error {
	if interval < time.Second || interval > 5*time.Minute {
		return errors.New("WireGuard reconcile interval must be within 1s-5m")
	}
	if maxStaleness < 2*interval || maxStaleness > time.Hour {
		return errors.New("WireGuard maximum staleness must be within 2 intervals and one hour")
	}
	if mtu < 1280 || mtu > 1420 {
		return errors.New("WireGuard MTU must be within 1280-1420")
	}
	if listenPort < 1 || listenPort > 65535 {
		return errors.New("WireGuard listen port must be within 1-65535")
	}
	return nil
}

// loadRelayWireGuardKey loads the persistent relay key, creating it on first
// start. The environment value is a development convenience only.
func loadRelayWireGuardKey(path, envValue string) (wgtypes.Key, error) {
	if envValue != "" {
		key, err := wgtypes.ParseKey(strings.TrimSpace(envValue))
		if err != nil {
			return wgtypes.Key{}, fmt.Errorf("parse BLINDPORT_RELAY_WIREGUARD_KEY: %w", err)
		}
		return key, nil
	}
	if path == "" {
		return wgtypes.Key{}, errors.New("a WireGuard key file is required")
	}
	data, err := os.ReadFile(path)
	if err == nil {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return wgtypes.Key{}, fmt.Errorf("inspect WireGuard key file: %w", statErr)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return wgtypes.Key{}, fmt.Errorf(
				"WireGuard key file %s must be a regular owner-only file", path)
		}
		key, parseErr := wgtypes.ParseKey(strings.TrimSpace(string(data)))
		if parseErr != nil {
			return wgtypes.Key{}, fmt.Errorf("parse WireGuard key file: %w", parseErr)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return wgtypes.Key{}, fmt.Errorf("read WireGuard key file: %w", err)
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("generate WireGuard key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("create WireGuard key file: %w", err)
	}
	if _, err := file.WriteString(key.String() + "\n"); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return wgtypes.Key{}, fmt.Errorf("write WireGuard key file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return wgtypes.Key{}, fmt.Errorf("sync WireGuard key file: %w", err)
	}
	if err := file.Close(); err != nil {
		return wgtypes.Key{}, fmt.Errorf("close WireGuard key file: %w", err)
	}
	return key, nil
}

func desiredStateFromResponse(state *relayauth.WireGuardDesiredState) *wgnet.DesiredState {
	peers := make([]wgnet.Peer, 0, len(state.Peers))
	for _, peer := range state.Peers {
		peers = append(peers, wgnet.Peer{
			PublicKey:       peer.PublicKey,
			AllowedPrefixes: append([]string(nil), peer.AllowedPrefixes...),
		})
	}
	return &wgnet.DesiredState{
		Revision:        state.Revision,
		ManagedPrefixes: append([]string(nil), state.ManagedPrefixes...),
		Peers:           peers,
	}
}

func newWireGuardManager(
	log *slog.Logger,
	fetcher wireGuardStateFetcher,
	reconciler wireGuardApplier,
	interval, maxStaleness time.Duration,
	health *relayHealth,
	metrics *relayMetrics,
) *wireGuardManager {
	return &wireGuardManager{
		log: log, fetcher: fetcher, reconciler: reconciler,
		interval: interval, maxStaleness: maxStaleness,
		health: health, metrics: metrics,
	}
}

func (m *wireGuardManager) run(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	defer m.failClosed("relay shutdown")
	m.cycle(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cycle(ctx)
		}
	}
}

func (m *wireGuardManager) cycle(ctx context.Context) {
	state, err := m.fetcher.WireGuardPeers(ctx)
	now := time.Now()
	if err == nil {
		desired := desiredStateFromResponse(state)
		if applyErr := m.reconciler.Apply(desired); applyErr != nil {
			m.log.Warn("apply WireGuard desired state failed")
			m.health.wgState.Store(wgUnavailable)
			m.failClosedIfStale(now, "desired-state apply failures")
			return
		}
		m.lastSuccess = now
		m.failedClosed = false
		m.health.wgState.Store(wgHealthy)
		m.metrics.wireguard.peers.Store(int64(len(desired.Peers)))
		m.metrics.wireguard.activePrefixes.Store(int64(len(desired.ActivePrefixes())))
		return
	}
	m.log.Warn("fetch WireGuard desired state failed")
	m.failClosedIfStale(now, "stale backend state")
}

func (m *wireGuardManager) failClosedIfStale(now time.Time, reason string) {
	if m.failedClosed || (!m.lastSuccess.IsZero() && now.Sub(m.lastSuccess) < m.maxStaleness) {
		return
	}
	m.failClosed(reason)
}

func (m *wireGuardManager) failClosed(reason string) {
	if m.failedClosed {
		return
	}
	if failErr := m.reconciler.FailClosed(); failErr != nil {
		m.log.Error("fail closed WireGuard plane failed")
		m.health.wgState.Store(wgUnavailable)
		return
	}
	m.failedClosed = true
	m.health.wgState.Store(wgUnavailable)
	m.metrics.wireguard.peers.Store(0)
	m.metrics.wireguard.activePrefixes.Store(0)
	m.log.Warn("WireGuard plane failed closed", "reason", reason)
}
