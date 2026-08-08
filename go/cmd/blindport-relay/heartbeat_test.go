package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/relayauth"
)

const testHeartbeatToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestHeartbeatSnapshotIncludesFixedHealthAndMetrics(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	health := newRelayHealth(true, time.Minute, time.Minute)
	health.listenersUp.Store(true)
	health.observeAuth(nil)
	health.certExpiry.Store(now.Add(time.Hour).Unix())
	health.wgNeeded.Store(true)
	health.wgState.Store(wgHealthy)
	metrics := &relayMetrics{health: health}
	for kind := range metrics.connections {
		metrics.connections[kind].accepted.Store(uint64(kind + 1))
	}
	for kind := range metrics.tunnels {
		metrics.tunnels[kind].active.Store(int64(kind + 2))
		metrics.streams[kind].active.Store(int64(kind + 5))
		metrics.bytes[kind][0].Store(uint64(kind + 10))
		metrics.bytes[kind][1].Store(uint64(kind + 20))
	}

	got := metrics.heartbeatSnapshot("edge-1", now)
	want := relayauth.Heartbeat{
		EdgeID: "edge-1", Ready: true,
		Components:    relayauth.HealthComponents{Authorization: "ok", Certificate: "ok", Lifecycle: "serving", Listeners: "ok", WireGuard: "ok"},
		ActiveTunnels: 9, ActiveStreams: 18, AcceptedConnectionsTotal: 15, ForwardedBytesTotal: 96,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("heartbeatSnapshot() = %+v, want %+v", got, want)
	}
}

func TestHeartbeatSnapshotClampsNegativeGaugesAndSaturates(t *testing.T) {
	metrics := &relayMetrics{health: newRelayHealth(false, time.Minute, time.Minute)}
	metrics.tunnels[0].active.Store(-1)
	metrics.tunnels[1].active.Store(math.MaxInt64)
	metrics.tunnels[2].active.Store(1)
	metrics.streams[0].active.Store(-1)
	metrics.streams[1].active.Store(-2)
	metrics.streams[2].active.Store(-3)
	metrics.connections[0].accepted.Store(math.MaxUint64)
	metrics.bytes[0][0].Store(math.MaxUint64)

	got := metrics.heartbeatSnapshot("edge-1", time.Unix(2_000_000_000, 0))
	if got.ActiveTunnels != math.MaxInt64 || got.ActiveStreams != 0 || got.AcceptedConnectionsTotal != math.MaxInt64 || got.ForwardedBytesTotal != math.MaxInt64 {
		t.Fatalf("saturated heartbeat = %+v", got)
	}
}

func TestValidateHeartbeatConfig(t *testing.T) {
	for _, test := range []struct {
		name     string
		edgeID   string
		token    string
		interval time.Duration
		enabled  bool
		wantErr  bool
	}{
		{name: "empty edge and token disable heartbeat", interval: time.Nanosecond, enabled: false},
		{name: "edge without token", edgeID: "edge-1", interval: 30 * time.Second, wantErr: true},
		{name: "token without edge", token: testHeartbeatToken, interval: 30 * time.Second, wantErr: true},
		{name: "valid enabled heartbeat", edgeID: "edge-1", token: testHeartbeatToken, interval: 30 * time.Second, enabled: true},
		{name: "offline edge validation", edgeID: "Bad_edge", token: testHeartbeatToken, interval: 30 * time.Second, wantErr: true},
		{name: "invalid token", edgeID: "edge-1", token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF", interval: 30 * time.Second, wantErr: true},
		{name: "interval too short", edgeID: "edge-1", token: testHeartbeatToken, interval: minHeartbeatInterval - time.Nanosecond, wantErr: true},
		{name: "interval too long", edgeID: "edge-1", token: testHeartbeatToken, interval: maxHeartbeatInterval + time.Nanosecond, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			enabled, err := validateHeartbeatConfig(test.edgeID, test.token, test.interval)
			if (err != nil) != test.wantErr || enabled != test.enabled {
				t.Fatalf("validateHeartbeatConfig() = (%t, %v), want (%t, error %t)", enabled, err, test.enabled, test.wantErr)
			}
		})
	}
}

func TestHeartbeatReporterReportsImmediatelyThenOnTicksUntilCanceled(t *testing.T) {
	ticker := &manualHeartbeatTicker{ticks: make(chan time.Time, 1)}
	reports := make(chan relayauth.Heartbeat, 2)
	reporter := &heartbeatReporter{
		log:      slog.Default(),
		interval: time.Hour,
		snapshot: func(time.Time) relayauth.Heartbeat { return relayauth.Heartbeat{EdgeID: "edge-1"} },
		report: func(_ context.Context, heartbeat relayauth.Heartbeat) error {
			reports <- heartbeat
			return nil
		},
		ticker: func(time.Duration) heartbeatTicker { return ticker },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		reporter.run(ctx)
	}()
	assertHeartbeatReport(t, reports)
	ticker.ticks <- time.Now()
	assertHeartbeatReport(t, reports)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat reporter did not stop after cancellation")
	}
	if !ticker.stopped.Load() {
		t.Fatal("heartbeat ticker was not stopped")
	}
}

func TestHeartbeatReporterFailureDoesNotAffectReadiness(t *testing.T) {
	var output bytes.Buffer
	health := newRelayHealth(false, time.Minute, time.Minute)
	health.listenersUp.Store(true)
	health.observeAuth(nil)
	if !health.ready(time.Now()) {
		t.Fatal("test relay is not ready before heartbeat failure")
	}
	called := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	reporter := &heartbeatReporter{
		log: slog.New(slog.NewTextHandler(&output, nil)), interval: time.Hour,
		snapshot: func(time.Time) relayauth.Heartbeat { return relayauth.Heartbeat{} },
		report: func(context.Context, relayauth.Heartbeat) error {
			called <- struct{}{}
			return errors.New("backend unavailable")
		},
		ticker: func(time.Duration) heartbeatTicker { return &manualHeartbeatTicker{ticks: make(chan time.Time)} },
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		reporter.run(ctx)
	}()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("heartbeat reporter did not make an immediate report")
	}
	cancel()
	<-done
	if !health.ready(time.Now()) {
		t.Fatal("heartbeat failure changed relay readiness")
	}
	if got := output.String(); got == "" || bytes.Contains([]byte(got), []byte("backend unavailable")) {
		t.Fatalf("heartbeat failure log = %q", got)
	}
}

type manualHeartbeatTicker struct {
	ticks   chan time.Time
	stopped atomic.Bool
}

func (t *manualHeartbeatTicker) Chan() <-chan time.Time { return t.ticks }
func (t *manualHeartbeatTicker) Stop()                  { t.stopped.Store(true) }

func assertHeartbeatReport(t *testing.T, reports <-chan relayauth.Heartbeat) {
	t.Helper()
	select {
	case heartbeat := <-reports:
		if heartbeat.EdgeID != "edge-1" {
			t.Fatalf("reported heartbeat = %+v", heartbeat)
		}
	case <-time.After(time.Second):
		t.Fatal("heartbeat was not reported")
	}
}
