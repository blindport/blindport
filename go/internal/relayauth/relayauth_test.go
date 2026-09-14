package relayauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/blindport/blindport/internal/protocol"
)

const testHeartbeatToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestFetchRelayCertEncodesNilSANListsAsArrays(t *testing.T) {
	tests := []struct {
		name      string
		hostnames []string
		ips       []string
	}{
		{name: "IP-only relay", ips: []string{"203.0.113.20"}},
		{name: "hostname-only relay", hostnames: []string{"relay.example"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Hostnames []string `json:"hostnames"`
					IPs       []string `json:"ips"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body.Hostnames == nil || body.IPs == nil {
					t.Fatalf("SAN lists = %#v/%#v, want JSON arrays", body.Hostnames, body.IPs)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ca_cert_pem":"ca","server_cert_pem":"cert","server_key_pem":"key","not_after":"2026-08-08T00:00:00Z"}`))
			}))
			defer server.Close()

			resolver, err := New(server.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.FetchRelayCert(context.Background(), tt.hostnames, tt.ips); err != nil {
				t.Fatalf("FetchRelayCert() error = %v", err)
			}
		})
	}
}

func TestReportHeartbeatSendsStrictAcceptedSnapshot(t *testing.T) {
	heartbeat := Heartbeat{
		EdgeID: "relay-1", Ready: true,
		Components:    HealthComponents{Authorization: "ok", Certificate: "ok", Lifecycle: "serving", Listeners: "ok", WireGuard: "disabled"},
		ActiveTunnels: 2, ActiveStreams: 3, AcceptedConnectionsTotal: 4, ForwardedBytesTotal: 5,
		ActiveSubscriptionIDs: []string{
			"018f47b8-2c36-7d4e-9a51-123456789abc",
			"118f47b8-2c36-7d4e-9a51-123456789abc",
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/relay/heartbeat" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-Relay-Secret"); got != "secret" {
			t.Fatalf("X-Relay-Secret = %q", got)
		}
		if got := r.Header.Get("X-Relay-Heartbeat-Token"); got != testHeartbeatToken {
			t.Fatalf("X-Relay-Heartbeat-Token = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("Content-Type = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		wantBody := `{"edge_id":"relay-1","ready":true,"components":{"authorization":"ok","certificate":"ok","lifecycle":"serving","listeners":"ok","wireguard":"disabled"},"active_tunnels":2,"active_streams":3,"accepted_connections_total":4,"forwarded_bytes_total":5,"active_subscription_ids":["018f47b8-2c36-7d4e-9a51-123456789abc","118f47b8-2c36-7d4e-9a51-123456789abc"],"active_subscription_ids_truncated":false}`
		if got := string(body); got != wantBody {
			t.Fatalf("request body = %s, want %s", got, wantBody)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	}))
	defer server.Close()

	resolver, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := resolver.ReportHeartbeat(context.Background(), testHeartbeatToken, heartbeat); err != nil {
		t.Fatalf("ReportHeartbeat() error = %v", err)
	}
}

func TestReportHeartbeatRejectsInvalidSubscriptionSnapshotBeforeNetwork(t *testing.T) {
	resolver, err := New("http://127.0.0.1:1", "secret")
	if err != nil {
		t.Fatal(err)
	}
	valid := "018f47b8-2c36-7d4e-9a51-123456789abc"
	for _, subscriptions := range [][]string{
		{valid, valid},
		{"118f47b8-2c36-7d4e-9a51-123456789abc", valid},
		{"not-a-uuid"},
		make([]string, MaxHeartbeatActiveSubscriptions+1),
	} {
		err := resolver.ReportHeartbeat(
			context.Background(), testHeartbeatToken, Heartbeat{ActiveSubscriptionIDs: subscriptions},
		)
		if !IsKind(err, ErrorProtocol) {
			t.Fatalf("ReportHeartbeat(%q) error = %v, want protocol error", subscriptions, err)
		}
	}
}

func TestReportHeartbeatReturnsTypedBackendAndProtocolErrors(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		body       string
		kind       ErrorKind
		wantStatus int
	}{
		{name: "backend failure", status: http.StatusServiceUnavailable, kind: ErrorInfrastructure, wantStatus: http.StatusServiceUnavailable},
		{name: "unexpected acknowledgment", status: http.StatusOK, body: `{"status":"rejected"}`, kind: ErrorProtocol},
		{name: "unknown acknowledgment field", status: http.StatusOK, body: `{"status":"accepted","extra":true}`, kind: ErrorProtocol},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			resolver, err := New(server.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			err = resolver.ReportHeartbeat(context.Background(), testHeartbeatToken, Heartbeat{})
			var typed *Error
			if !errors.As(err, &typed) || typed.Kind != test.kind || typed.Status != test.wantStatus {
				t.Fatalf("ReportHeartbeat() error = %v, want kind %q and status %d", err, test.kind, test.wantStatus)
			}
		})
	}
}

func TestReportHeartbeatRejectsInvalidTokenBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	resolver, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	err = resolver.ReportHeartbeat(context.Background(), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF", Heartbeat{})
	if !IsKind(err, ErrorProtocol) {
		t.Fatalf("ReportHeartbeat() error = %v, want protocol error", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("heartbeat requests = %d, want 0", calls.Load())
	}
}

func TestReportDailyBandwidthSendsAcceptedBatch(t *testing.T) {
	batch := DailyBandwidthBatch{
		EdgeID: "relay-1", BootID: "018f47b8-2c36-7d4e-9a51-123456789abc", Sequence: 7,
		Reports: []DailyBandwidthReport{{
			SubscriptionID: "118f47b8-2c36-7d4e-9a51-123456789abc", Day: "2026-08-09", IngressBytes: 12, EgressBytes: 34,
		}},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/relay/bandwidth/daily" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-Relay-Secret"); got != "secret" {
			t.Fatalf("X-Relay-Secret = %q", got)
		}
		if got := r.Header.Get("X-Relay-Heartbeat-Token"); got != testHeartbeatToken {
			t.Fatalf("X-Relay-Heartbeat-Token = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		want := `{"edge_id":"relay-1","boot_id":"018f47b8-2c36-7d4e-9a51-123456789abc","sequence":7,"reports":[{"subscription_id":"118f47b8-2c36-7d4e-9a51-123456789abc","day":"2026-08-09","ingress_bytes":12,"egress_bytes":34}]}`
		if got := string(body); got != want {
			t.Fatalf("request body = %s, want %s", got, want)
		}
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	}))
	defer server.Close()

	resolver, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := resolver.ReportDailyBandwidth(context.Background(), testHeartbeatToken, batch); err != nil {
		t.Fatalf("ReportDailyBandwidth() error = %v", err)
	}
}

func TestReportDailyBandwidthRejectsInvalidBatchesBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	resolver, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	valid := DailyBandwidthBatch{
		EdgeID: "relay-1", BootID: "018f47b8-2c36-7d4e-9a51-123456789abc",
		Reports: []DailyBandwidthReport{{SubscriptionID: "118f47b8-2c36-7d4e-9a51-123456789abc", Day: "2026-08-09"}},
	}
	for _, batch := range []DailyBandwidthBatch{
		{},
		{EdgeID: valid.EdgeID, BootID: valid.BootID},
		{EdgeID: valid.EdgeID, BootID: "bad", Reports: valid.Reports},
		{EdgeID: valid.EdgeID, BootID: valid.BootID, Sequence: -1, Reports: valid.Reports},
		{EdgeID: valid.EdgeID, BootID: valid.BootID, Reports: []DailyBandwidthReport{{SubscriptionID: valid.Reports[0].SubscriptionID, Day: "2026-2-9"}}},
	} {
		if err := resolver.ReportDailyBandwidth(context.Background(), testHeartbeatToken, batch); !IsKind(err, ErrorProtocol) {
			t.Fatalf("ReportDailyBandwidth() error = %v, want protocol error", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("bandwidth requests = %d, want 0", calls.Load())
	}
}

func TestReportDailyBandwidthRejectsStrictResponses(t *testing.T) {
	batch := DailyBandwidthBatch{
		EdgeID: "relay-1", BootID: "018f47b8-2c36-7d4e-9a51-123456789abc",
		Reports: []DailyBandwidthReport{{SubscriptionID: "118f47b8-2c36-7d4e-9a51-123456789abc", Day: "2026-08-09"}},
	}
	for _, body := range []string{`{"status":"rejected"}`, `{"status":"accepted","extra":true}`, `{}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
		resolver, err := New(server.URL, "secret")
		if err != nil {
			t.Fatal(err)
		}
		err = resolver.ReportDailyBandwidth(context.Background(), testHeartbeatToken, batch)
		server.Close()
		if !IsKind(err, ErrorProtocol) {
			t.Fatalf("ReportDailyBandwidth() error = %v, want protocol error", err)
		}
	}
}

func TestResolveDecodesPortLeases(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Relay-Secret"); got != "secret" {
			t.Fatalf("X-Relay-Secret = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"account_id":"018f47b8-2c36-7d4e-9a51-123456789abc","user_id":42,"ip_ips":[],"relay_domains":[],"port_leases":[{"assigned_ip":"203.0.113.20","assigned_port":10000,"transport":"tcp"}]}`))
	}))
	defer server.Close()

	resolver, err := New(server.URL, "secret")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	resolution, err := resolver.Resolve(context.Background(), "token", nil)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if len(resolution.PortLeases) != 1 || resolution.PortLeases[0].AssignedPort != 10000 {
		t.Fatalf("PortLeases = %+v", resolution.PortLeases)
	}
	if resolution.AccountID != "018f47b8-2c36-7d4e-9a51-123456789abc" || resolution.UserID != 42 {
		t.Fatalf("resolution identity = account %q, user %d", resolution.AccountID, resolution.UserID)
	}
}

func TestResolveIncludesClaimScopeWithoutChangingExactJSON(t *testing.T) {
	tests := []struct {
		name     string
		claim    *protocol.Claim
		wantBody string
	}{
		{
			name:     "exact",
			claim:    &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "public.example"},
			wantBody: `{"token":"token","claim":{"kind":"relay","domain":"public.example"}}`,
		},
		{
			name:     "wildcard",
			claim:    &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "public.example", Scope: protocol.RelayHostnameScopeWildcard},
			wantBody: `{"token":"token","claim":{"kind":"relay","domain":"public.example","scope":"wildcard"}}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				if got := string(body); got != test.wantBody {
					t.Fatalf("request body = %s, want %s", got, test.wantBody)
				}
				_, _ = w.Write([]byte(`{"account_id":"018f47b8-2c36-7d4e-9a51-123456789abc","user_id":42,"ip_ips":[],"relay_domains":[],"relay_claims":[{"domain":"public.example","scope":"wildcard"}],"port_leases":[]}`))
			}))
			defer server.Close()
			resolver, err := New(server.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			resolution, err := resolver.Resolve(context.Background(), "token", test.claim)
			if err != nil {
				t.Fatal(err)
			}
			if len(resolution.RelayClaims) != 1 || resolution.RelayClaims[0].Domain != "public.example" || resolution.RelayClaims[0].Scope != protocol.RelayHostnameScopeWildcard {
				t.Fatalf("relay claims = %+v", resolution.RelayClaims)
			}
			if !resolution.SubscriptionAuthoritative {
				t.Fatal("V3 resolution did not mark subscription attribution authoritative")
			}
		})
	}
}

func TestResolveUsesV3ThenRollingSafeFallback(t *testing.T) {
	var paths, bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, r.URL.Path)
		bodies = append(bodies, string(body))
		if r.URL.Path == "/internal/v3/resolve" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"account_id":"018f47b8-2c36-7d4e-9a51-123456789abc","user_id":42,"ip_ips":[],"relay_domains":["public.example"],"port_leases":[]}`))
	}))
	defer server.Close()
	resolver, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "public.example"}
	resolution, err := resolver.Resolve(context.Background(), "token", claim)
	if err != nil {
		t.Fatal(err)
	}
	if resolution.SubscriptionAuthoritative {
		t.Fatal("V2 fallback marked subscription attribution authoritative")
	}
	if got, want := strings.Join(paths, ","), "/internal/v3/resolve,/internal/v2/resolve"; got != want {
		t.Fatalf("paths = %q, want %q", got, want)
	}
	if bodies[0] != `{"token":"token","claim":{"kind":"relay","domain":"public.example"}}` || bodies[1] != `{"token":"token"}` {
		t.Fatalf("request bodies = %q", bodies)
	}
	paths, bodies = nil, nil
	wildcard := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "public.example", Scope: protocol.RelayHostnameScopeWildcard}
	if _, err := resolver.Resolve(context.Background(), "token", wildcard); !IsKind(err, ErrorDenied) || len(paths) != 1 {
		t.Fatalf("wildcard fallback = %v, paths = %v", err, paths)
	}
}

func TestResolveDecodesStructuredRelayClaimScopes(t *testing.T) {
	tests := []struct {
		name      string
		claimJSON string
		wantScope protocol.RelayHostnameScope
		wantErr   bool
	}{
		{name: "exact", claimJSON: `{"domain":"public.example","scope":"exact"}`},
		{name: "wildcard", claimJSON: `{"domain":"public.example","scope":"wildcard"}`, wantScope: protocol.RelayHostnameScopeWildcard},
		{name: "unknown", claimJSON: `{"domain":"public.example","scope":"other"}`, wantErr: true},
		{name: "missing", claimJSON: `{"domain":"public.example"}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"account_id":"018f47b8-2c36-7d4e-9a51-123456789abc","user_id":42,"ip_ips":[],"relay_domains":[],"relay_claims":[` + test.claimJSON + `],"port_leases":[]}`))
			}))
			defer server.Close()
			resolver, err := New(server.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			resolution, err := resolver.Resolve(context.Background(), "token", nil)
			if test.wantErr {
				if !IsKind(err, ErrorProtocol) {
					t.Fatalf("Resolve() error = %v, want protocol error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(resolution.RelayClaims) != 1 || resolution.RelayClaims[0].Scope != test.wantScope {
				t.Fatalf("relay claims = %+v, want scope %q", resolution.RelayClaims, test.wantScope)
			}
		})
	}
}

func TestResolveAcceptsNewAndLegacyIdentityFields(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantAccount string
		wantUser    int64
	}{
		{name: "account only", body: `{"account_id":"018f47b8-2c36-7d4e-9a51-123456789abc","ip_ips":[],"relay_domains":[],"port_leases":[]}`, wantAccount: "018f47b8-2c36-7d4e-9a51-123456789abc"},
		{name: "legacy user only", body: `{"user_id":42,"ip_ips":[],"relay_domains":[],"port_leases":[]}`, wantUser: 42},
		{name: "rollout response with both", body: `{"account_id":"018f47b8-2c36-7d4e-9a51-123456789abc","user_id":42,"ip_ips":[],"relay_domains":[],"port_leases":[]}`, wantAccount: "018f47b8-2c36-7d4e-9a51-123456789abc", wantUser: 42},
		{name: "identity fields absent", body: `{"ip_ips":[],"relay_domains":[],"port_leases":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			resolver, err := New(server.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			resolution, err := resolver.Resolve(context.Background(), "token", nil)
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if resolution.AccountID != tt.wantAccount || resolution.UserID != tt.wantUser {
				t.Fatalf("identity = account %q, user %d; want account %q, user %d", resolution.AccountID, resolution.UserID, tt.wantAccount, tt.wantUser)
			}
		})
	}
}

func TestResolveFallsBackToLegacyEndpoint(t *testing.T) {
	var v2Calls atomic.Int64
	var v1Calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v2/resolve":
			v2Calls.Add(1)
			http.NotFound(w, r)
		case "/internal/v1/resolve":
			v1Calls.Add(1)
			_, _ = w.Write([]byte(`{"user_id":42,"ip_ips":[],"relay_domains":[],"port_leases":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	resolver, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := resolver.Resolve(context.Background(), "token", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resolution.UserID != 42 || resolution.AccountID != "" || v2Calls.Load() != 1 || v1Calls.Load() != 1 {
		t.Fatalf("fallback resolution/calls = %+v/%d/%d", resolution, v2Calls.Load(), v1Calls.Load())
	}
}

func TestResolveLegacyFallbackPreservesTokenDenial(t *testing.T) {
	var v2Calls atomic.Int64
	var v1Calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v2/resolve":
			v2Calls.Add(1)
			http.NotFound(w, r)
		case "/internal/v1/resolve":
			v1Calls.Add(1)
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	resolver, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), "token", nil); !IsKind(err, ErrorDenied) {
		t.Fatalf("Resolve() error = %v, want typed denial", err)
	}
	if v2Calls.Load() != 1 || v1Calls.Load() != 1 {
		t.Fatalf("v2/v1 calls = %d/%d", v2Calls.Load(), v1Calls.Load())
	}
}

func TestResolveDoesNotFallbackAfterNonNotFoundFailure(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	resolver, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), "token", nil); !IsKind(err, ErrorInfrastructure) {
		t.Fatalf("Resolve() error = %v, want infrastructure", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("backend calls = %d, want 1", calls.Load())
	}
}

func TestWireGuardPeersFetchesCompleteSnapshot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/internal/v3/wireguard/peers" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-Relay-Secret"); got != "secret" {
			t.Fatalf("X-Relay-Secret = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revision":"abc","generated_at":"2026-07-18T00:00:00Z",` +
			`"managed_prefixes":["198.51.100.20/32"],` +
			`"peers":[{"public_key":"k","allowed_prefixes":["198.51.100.20/32"]}],` +
			`"smtp_allowed_prefixes":["198.51.100.20/32"],` +
			`"prefix_bindings":[{"prefix":"198.51.100.20/32","subscription_id":"118f47b8-2c36-7d4e-9a51-123456789abc"}]}`))
	}))
	defer server.Close()

	resolver, err := New(server.URL, "secret")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	state, err := resolver.WireGuardPeers(context.Background())
	if err != nil {
		t.Fatalf("WireGuardPeers() error = %v", err)
	}
	if state.Revision != "abc" || len(state.Peers) != 1 || state.Peers[0].PublicKey != "k" || len(state.SMTPAllowedPrefixes) != 1 || len(state.PrefixBindings) != 1 {
		t.Fatalf("state = %+v", state)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer failing.Close()
	resolver, err = New(failing.URL, "secret")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := resolver.WireGuardPeers(context.Background()); !IsKind(err, ErrorSecret) {
		t.Fatalf("WireGuardPeers() error = %v, want secret", err)
	}
}

func TestWireGuardPeersFallsBackToV1WithoutSMTPExceptions(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/internal/v3/wireguard/peers" || r.URL.Path == "/internal/v2/wireguard/peers" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"revision":"legacy","generated_at":"2026-07-18T00:00:00Z","managed_prefixes":[],"peers":[]}`))
	}))
	defer server.Close()
	resolver, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	state, err := resolver.WireGuardPeers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(paths, ",") != "/internal/v3/wireguard/peers,/internal/v2/wireguard/peers,/internal/v1/wireguard/peers" || state.SMTPAllowedPrefixes != nil || state.PrefixBindings != nil {
		t.Fatalf("paths/state = %v/%+v", paths, state)
	}
}

func TestWireGuardPeersRetainsStrictDecodingOnV2AndV1(t *testing.T) {
	for _, test := range []struct {
		name string
		v2   bool
		body string
	}{
		{name: "v2 rejects v3 prefix bindings", v2: true, body: `{"revision":"r","generated_at":"now","managed_prefixes":[],"peers":[],"smtp_allowed_prefixes":[],"prefix_bindings":[]}`},
		{name: "v2 unknown field", v2: true, body: `{"revision":"r","generated_at":"now","managed_prefixes":[],"peers":[],"smtp_allowed_prefixes":[],"extra":true}`},
		{name: "v1 rejects SMTP field", body: `{"revision":"r","generated_at":"now","managed_prefixes":[],"peers":[],"smtp_allowed_prefixes":[]}`},
		{name: "v1 rejects prefix bindings", body: `{"revision":"r","generated_at":"now","managed_prefixes":[],"peers":[],"prefix_bindings":[]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/internal/v3/wireguard/peers" || (!test.v2 && r.URL.Path == "/internal/v2/wireguard/peers") {
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			resolver, err := New(server.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.WireGuardPeers(context.Background()); !IsKind(err, ErrorProtocol) {
				t.Fatalf("WireGuardPeers() error = %v", err)
			}
		})
	}
}

func TestResolveClassifiesStatus(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		kind   ErrorKind
	}{
		{name: "token denied", status: http.StatusNotFound, kind: ErrorDenied},
		{name: "account suspended", status: http.StatusForbidden, kind: ErrorDenied},
		{name: "bad secret", status: http.StatusUnauthorized, kind: ErrorSecret},
		{name: "backend failure", status: http.StatusServiceUnavailable, kind: ErrorInfrastructure},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer server.Close()
			resolver, err := New(server.URL, "secret")
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			_, err = resolver.Resolve(context.Background(), "token", nil)
			if !IsKind(err, tt.kind) {
				t.Fatalf("Resolve() error = %v, want kind %q", err, tt.kind)
			}
		})
	}
}

func TestResponseDecodeIsBoundedAndStrict(t *testing.T) {
	for _, body := range []string{
		`{"user_id":42,"ip_ips":[],"relay_domains":[],"port_leases":[]} {}`,
		`{"user_id":42,"ip_ips":[],"relay_domains":[],"port_leases":[],"unexpected":true}`,
		`{"account_id":42,"ip_ips":[],"relay_domains":[],"port_leases":[]}`,
		`{"padding":"` + strings.Repeat("x", maxResponseBody) + `"}`,
		`{"user_id":42,"ip_ips":[],"relay_domains":[],"port_leases":[]}` + strings.Repeat(" ", maxResponseBody),
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
		resolver, err := New(server.URL, "secret")
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		_, err = resolver.Resolve(context.Background(), "token", nil)
		server.Close()
		if !IsKind(err, ErrorProtocol) {
			t.Fatalf("Resolve() error = %v, want protocol", err)
		}
	}
}

func TestNewValidatesBackendURL(t *testing.T) {
	for _, raw := range []string{"", "backend:8000", "ftp://backend", "http://", "http://user:pass@backend", "http://backend?q=1"} {
		if _, err := New(raw, "secret"); err == nil {
			t.Fatalf("New(%q) returned nil error", raw)
		}
	}
	resolver, err := New("http://backend/base/", "secret")
	if err != nil || resolver.backendURL != "http://backend/base" {
		t.Fatalf("New() = (%+v, %v)", resolver, err)
	}
}

func TestResolveHonorsContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	resolver, err := New(server.URL, "secret")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = resolver.Resolve(ctx, "token", nil)
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != ErrorInfrastructure {
		t.Fatalf("Resolve() error = %v", err)
	}
}

func TestResolverDoesNotFollowRedirectsWithRelaySecret(t *testing.T) {
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		followed.Store(true)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	resolver, err := New(redirect.URL, "secret")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = resolver.Resolve(context.Background(), "token", nil)
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != ErrorProtocol || typed.Status != http.StatusTemporaryRedirect {
		t.Fatalf("Resolve() error = %v, want protocol status %d", err, http.StatusTemporaryRedirect)
	}
	if followed.Load() {
		t.Fatal("resolver followed a backend redirect carrying the relay secret")
	}
}
