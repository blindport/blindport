package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRelayHealthReadinessTransitions(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	health := newRelayHealth(true, 5*time.Minute, 90*time.Second)
	health.listenersUp.Store(true)
	health.certExpiry.Store(now.Add(time.Hour).Unix())
	if health.ready(now) {
		t.Fatal("relay with unknown authorization state is ready")
	}
	health.observeAuth(nil)
	if !health.ready(now) {
		t.Fatal("healthy relay is not ready")
	}
	health.observeAuth(assertionError("backend unavailable"))
	if !health.ready(time.Now().Add(30 * time.Second)) {
		t.Fatal("transient auth outage immediately removed readiness")
	}
	health.authLastSuccess.Store(now.Add(-2 * time.Minute).UnixNano())
	if health.ready(now) {
		t.Fatal("stale auth outage remained ready")
	}
	health.observeAuth(nil)
	health.certExpiry.Store(now.Add(4 * time.Minute).Unix())
	if health.ready(now) {
		t.Fatal("near-expiry certificate remained ready")
	}
	health.certExpiry.Store(now.Add(time.Hour).Unix())
	health.draining.Store(true)
	if health.ready(now) {
		t.Fatal("draining relay remained ready")
	}
}

func TestRelayHealthPreservesSubsecondAuthorizationStaleness(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	health := newRelayHealth(false, time.Minute, 500*time.Millisecond)
	health.listenersUp.Store(true)
	health.authState.Store(authInfrastructureFailure)
	health.authLastSuccess.Store(now.Add(-499 * time.Millisecond).UnixNano())
	if !health.ready(now) {
		t.Fatal("authorization became stale before the configured subsecond deadline")
	}
	if health.ready(now.Add(time.Millisecond)) {
		t.Fatal("authorization remained ready at the configured subsecond deadline")
	}
}

type assertionError string

func (e assertionError) Error() string { return string(e) }

func TestAdminEndpointsAndMetricsUseFixedLabels(t *testing.T) {
	health := newRelayHealth(false, time.Minute, time.Minute)
	health.listenersUp.Store(true)
	health.observeAuth(nil)
	metrics := &relayMetrics{health: health}
	var workers sync.WaitGroup
	for range 20 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				metrics.connections[listenerSNI].accepted.Add(1)
				metrics.streams[claimKindIndexFromKey("domain:sensitive.example")].total.Add(1)
			}
		}()
	}
	workers.Wait()
	server := httptest.NewServer(metrics.handler())
	defer server.Close()

	ready, err := http.Get(server.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	_ = ready.Body.Close()
	if ready.StatusCode != http.StatusOK {
		t.Fatalf("ready status = %d", ready.StatusCode)
	}
	response, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, required := range []string{
		`blindport_relay_connections_accepted_total{listener="sni"} 2000`,
		`blindport_relay_connections_accepted_total{listener="http_challenge"} 0`,
		`blindport_relay_streams_total{claim="relay"} 2000`,
		"blindport_relay_udp_associations_active 0",
		`blindport_relay_udp_datagrams_total{direction="ingress_to_tunnel"} 0`,
		"blindport_relay_wireguard_peers_active 0",
		"blindport_relay_wireguard_prefixes_active 0",
		"blindport_relay_ready 1",
		`blindport_relay_http_challenge_outcomes_total{outcome="success"} 0`,
		`blindport_relay_http_challenge_outcomes_total{outcome="redirected"} 0`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("metrics missing %q:\n%s", required, text)
		}
	}
	if strings.Contains(text, "sensitive.example") {
		t.Fatal("metrics exposed tenant domain")
	}
}
