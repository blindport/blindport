package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/blindport/blindport/internal/protocol"
	"github.com/blindport/blindport/internal/relayauth"
)

const (
	controlAccepted = iota
	controlBadHello
	controlInventoryDenied
	controlAuthDenied
	controlAuthError
	controlIdentityDenied
	controlWriteError
	controlOutcomeCount
)

const (
	authAllowed = iota
	authDenied
	authInfrastructure
	authSecret
	authProtocol
	authOutcomeCount
)

const (
	entitlementOnline = iota
	entitlementOffline
	entitlementOutcomeCount
)

const (
	sniSuccess = iota
	sniInvalid
	sniNoTunnel
	sniOutcomeCount
)

type metricPair struct {
	active atomic.Int64
	total  atomic.Uint64
}

type relayMetrics struct {
	connections [listenerKindCount]struct {
		accepted atomic.Uint64
		active   atomic.Int64
		rejected atomic.Uint64
	}
	tunnels     [claimKindCount]metricPair
	streams     [claimKindCount]metricPair
	bytes       [claimKindCount][2]atomic.Uint64
	control     [controlOutcomeCount]atomic.Uint64
	auth        [authOutcomeCount]atomic.Uint64
	entitlement [entitlementOutcomeCount]atomic.Uint64
	sni         [sniOutcomeCount]atomic.Uint64
	challenge   [challengeOutcomeCount]atomic.Uint64
	udp         struct {
		associations metricPair
		rejected     atomic.Uint64
		dropped      atomic.Uint64
		datagrams    [2]atomic.Uint64
	}
	wireguard struct {
		peers          atomic.Int64
		activePrefixes atomic.Int64
	}
	health *relayHealth
}

type relayHealth struct {
	listenersUp     atomic.Bool
	draining        atomic.Bool
	authState       atomic.Int32
	certNeeded      atomic.Bool
	certExpiry      atomic.Int64
	certMargin      time.Duration
	authMaxStale    time.Duration
	authLastSuccess atomic.Int64 // Unix nanoseconds
	wgNeeded        atomic.Bool
	wgState         atomic.Int32
}

const (
	wgStarting int32 = iota
	wgHealthy
	wgUnavailable
)

const (
	authUnknown int32 = iota
	authHealthy
	authInfrastructureFailure
	authSecretFailure
	authProtocolFailure
)

func newRelayHealth(certNeeded bool, certMargin, authMaxStale time.Duration) *relayHealth {
	h := &relayHealth{certMargin: certMargin, authMaxStale: authMaxStale}
	h.certNeeded.Store(certNeeded)
	h.authLastSuccess.Store(time.Now().UnixNano())
	return h
}

func (h *relayHealth) observeAuth(err error) {
	switch {
	case err == nil, relayauth.IsKind(err, relayauth.ErrorDenied):
		h.authState.Store(authHealthy)
		h.authLastSuccess.Store(time.Now().UnixNano())
	case relayauth.IsKind(err, relayauth.ErrorSecret):
		h.authState.Store(authSecretFailure)
	case relayauth.IsKind(err, relayauth.ErrorProtocol):
		h.authState.Store(authProtocolFailure)
	default:
		h.authState.Store(authInfrastructureFailure)
	}
}

func (h *relayHealth) ready(now time.Time) bool {
	if !h.listenersUp.Load() || h.draining.Load() {
		return false
	}
	authState := h.authState.Load()
	if authState == authUnknown || authState == authSecretFailure || authState == authProtocolFailure || (authState == authInfrastructureFailure && h.authorizationStale(now)) {
		return false
	}
	if h.wgNeeded.Load() && h.wgState.Load() != wgHealthy {
		return false
	}
	if !h.certNeeded.Load() {
		return true
	}
	expiry := h.certExpiry.Load()
	return expiry > 0 && now.Add(h.certMargin).Unix() < expiry
}

func (h *relayHealth) authorizationStale(now time.Time) bool {
	return now.UnixNano()-h.authLastSuccess.Load() >= h.authMaxStale.Nanoseconds()
}

func (m *relayMetrics) observeAuth(err error) {
	m.health.observeAuth(err)
	switch {
	case err == nil:
		m.auth[authAllowed].Add(1)
	case relayauth.IsKind(err, relayauth.ErrorDenied):
		m.auth[authDenied].Add(1)
	case relayauth.IsKind(err, relayauth.ErrorSecret):
		m.auth[authSecret].Add(1)
	case relayauth.IsKind(err, relayauth.ErrorProtocol):
		m.auth[authProtocol].Add(1)
	default:
		m.auth[authInfrastructure].Add(1)
	}
}

func (m *relayMetrics) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("live\n"))
	}))
	mux.HandleFunc("/readyz", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		now := time.Now()
		ready := m.health.ready(now)
		w.Header().Set("Content-Type", "application/json")
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     map[bool]string{true: "ok", false: "unavailable"}[ready],
			"components": m.health.components(now),
		})
	}))
	mux.HandleFunc("/metrics", getOnly(m.writeMetrics))
	return mux
}

func (h *relayHealth) components(now time.Time) map[string]string {
	listeners := "ok"
	if !h.listenersUp.Load() || h.draining.Load() {
		listeners = "unavailable"
	}
	authorization := "ok"
	switch h.authState.Load() {
	case authSecretFailure:
		authorization = "unavailable"
	case authProtocolFailure:
		authorization = "unavailable"
	case authInfrastructureFailure:
		if h.authorizationStale(now) {
			authorization = "unavailable"
		} else {
			authorization = "degraded"
		}
	case authUnknown:
		authorization = "starting"
	}
	certificate := "disabled"
	if h.certNeeded.Load() {
		certificate = "ok"
		if expiry := h.certExpiry.Load(); expiry == 0 || now.Add(h.certMargin).Unix() >= expiry {
			certificate = "unavailable"
		}
	}
	lifecycle := "serving"
	if h.draining.Load() {
		lifecycle = "draining"
	}
	wireguard := "disabled"
	if h.wgNeeded.Load() {
		switch h.wgState.Load() {
		case wgHealthy:
			wireguard = "ok"
		case wgUnavailable:
			wireguard = "unavailable"
		default:
			wireguard = "starting"
		}
	}
	return map[string]string{
		"authorization": authorization,
		"certificate":   certificate,
		"lifecycle":     lifecycle,
		"listeners":     listeners,
		"wireguard":     wireguard,
	}
}

func getOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

func (m *relayMetrics) writeMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeHelpType(w, "blindport_relay_connections_accepted_total", "Accepted TCP connections.", "counter")
	for kind, label := range listenerKindLabels {
		writeMetric(w, "blindport_relay_connections_accepted_total", "listener", label, m.connections[kind].accepted.Load())
	}
	writeHelpType(w, "blindport_relay_connections_active", "Active admitted TCP connections.", "gauge")
	for kind, label := range listenerKindLabels {
		writeMetric(w, "blindport_relay_connections_active", "listener", label, m.connections[kind].active.Load())
	}
	writeHelpType(w, "blindport_relay_connections_rejected_total", "Connections rejected by admission control.", "counter")
	for kind, label := range listenerKindLabels {
		writeMetric(w, "blindport_relay_connections_rejected_total", "listener", label, m.connections[kind].rejected.Load())
	}

	writeHelpType(w, "blindport_relay_tunnels_active", "Active control tunnels.", "gauge")
	writeHelpType(w, "blindport_relay_tunnels_total", "Established control tunnels.", "counter")
	writeHelpType(w, "blindport_relay_streams_active", "Active forwarded streams.", "gauge")
	writeHelpType(w, "blindport_relay_streams_total", "Forwarded streams opened.", "counter")
	for kind, label := range claimKindLabels {
		writeMetric(w, "blindport_relay_tunnels_active", "claim", label, m.tunnels[kind].active.Load())
		writeMetric(w, "blindport_relay_tunnels_total", "claim", label, m.tunnels[kind].total.Load())
		writeMetric(w, "blindport_relay_streams_active", "claim", label, m.streams[kind].active.Load())
		writeMetric(w, "blindport_relay_streams_total", "claim", label, m.streams[kind].total.Load())
	}
	writeHelpType(w, "blindport_relay_bytes_total", "Forwarded application bytes.", "counter")
	for kind, claim := range claimKindLabels {
		writeMetric2(w, "blindport_relay_bytes_total", "claim", claim, "direction", "ingress_to_tunnel", m.bytes[kind][0].Load())
		writeMetric2(w, "blindport_relay_bytes_total", "claim", claim, "direction", "tunnel_to_ingress", m.bytes[kind][1].Load())
	}
	writeHelpType(w, "blindport_relay_udp_associations_active", "Active Blindport Port UDP source associations.", "gauge")
	fmt.Fprintf(w, "blindport_relay_udp_associations_active %d\n", m.udp.associations.active.Load())
	writeHelpType(w, "blindport_relay_udp_associations_total", "Blindport Port UDP source associations admitted.", "counter")
	fmt.Fprintf(w, "blindport_relay_udp_associations_total %d\n", m.udp.associations.total.Load())
	writeHelpType(w, "blindport_relay_udp_associations_rejected_total", "Blindport Port UDP source associations rejected by admission control.", "counter")
	fmt.Fprintf(w, "blindport_relay_udp_associations_rejected_total %d\n", m.udp.rejected.Load())
	writeHelpType(w, "blindport_relay_udp_datagrams_dropped_total", "Blindport Port UDP datagrams dropped before forwarding.", "counter")
	fmt.Fprintf(w, "blindport_relay_udp_datagrams_dropped_total %d\n", m.udp.dropped.Load())
	writeHelpType(w, "blindport_relay_udp_datagrams_total", "Forwarded Blindport Port UDP datagrams.", "counter")
	writeMetric(w, "blindport_relay_udp_datagrams_total", "direction", "ingress_to_tunnel", m.udp.datagrams[0].Load())
	writeMetric(w, "blindport_relay_udp_datagrams_total", "direction", "tunnel_to_ingress", m.udp.datagrams[1].Load())
	writeHelpType(w, "blindport_relay_wireguard_peers_active", "Configured routed WireGuard peers.", "gauge")
	fmt.Fprintf(w, "blindport_relay_wireguard_peers_active %d\n", m.wireguard.peers.Load())
	writeHelpType(w, "blindport_relay_wireguard_prefixes_active", "Routed WireGuard prefixes with an authorized peer.", "gauge")
	fmt.Fprintf(w, "blindport_relay_wireguard_prefixes_active %d\n", m.wireguard.activePrefixes.Load())

	writeFixedOutcomes(w, "blindport_relay_control_outcomes_total", "Control handshake outcomes.", controlOutcomeLabels, m.control[:])
	writeFixedOutcomes(w, "blindport_relay_auth_outcomes_total", "Backend authorization outcomes.", authOutcomeLabels, m.auth[:])
	writeFixedOutcomes(w, "blindport_relay_entitlement_authorizations_total", "Accepted or retained signed entitlement authorizations.", entitlementOutcomeLabels, m.entitlement[:])
	writeFixedOutcomes(w, "blindport_relay_sni_outcomes_total", "SNI inspection outcomes.", sniOutcomeLabels, m.sni[:])
	writeFixedOutcomes(w, "blindport_relay_http_challenge_outcomes_total", "HTTP ingress outcomes.", challengeOutcomeLabels, m.challenge[:])
	writeHelpType(w, "blindport_relay_ready", "Whether the relay is ready.", "gauge")
	ready := uint64(0)
	if m.health.ready(time.Now()) {
		ready = 1
	}
	fmt.Fprintf(w, "blindport_relay_ready %d\n", ready)
	writeHelpType(w, "blindport_relay_certificate_expiry_timestamp_seconds", "Current server certificate expiry as Unix time.", "gauge")
	fmt.Fprintf(w, "blindport_relay_certificate_expiry_timestamp_seconds %d\n", m.health.certExpiry.Load())
}

func writeHelpType(w http.ResponseWriter, name, help, metricType string) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
}

func writeMetric(w http.ResponseWriter, name, labelName, label string, value any) {
	fmt.Fprintf(w, "%s{%s=%s} %v\n", name, labelName, strconv.Quote(label), value)
}

func writeMetric2(w http.ResponseWriter, name, key1, value1, key2, value2 string, value any) {
	fmt.Fprintf(w, "%s{%s=%s,%s=%s} %v\n", name, key1, strconv.Quote(value1), key2, strconv.Quote(value2), value)
}

func writeFixedOutcomes(w http.ResponseWriter, name, help string, labels []string, values []atomic.Uint64) {
	writeHelpType(w, name, help, "counter")
	for index, label := range labels {
		writeMetric(w, name, "outcome", label, values[index].Load())
	}
}

var listenerKindLabels = []string{"control", "ip", "port", "sni", "http_challenge"}
var claimKindLabels = []string{"ip", "port", "relay"}
var controlOutcomeLabels = []string{"accepted", "bad_hello", "inventory_denied", "auth_denied", "auth_error", "identity_denied", "write_error"}
var authOutcomeLabels = []string{"allowed", "denied", "infrastructure", "secret", "protocol"}
var entitlementOutcomeLabels = []string{"online", "offline"}
var sniOutcomeLabels = []string{"success", "invalid", "no_tunnel"}
var challengeOutcomeLabels = []string{"success", "redirected", "invalid", "rate_limited", "no_tunnel", "upstream_error"}

const (
	listenerKindCount = 5
	claimKindCount    = 3
)

func claimKindIndex(kind protocol.ClaimKind) int {
	switch kind {
	case protocol.ClaimIP:
		return 0
	case protocol.ClaimPort:
		return 1
	case protocol.ClaimRelay:
		return 2
	default:
		return 0
	}
}
