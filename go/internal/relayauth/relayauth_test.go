package relayauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

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
	resolution, err := resolver.Resolve(context.Background(), "token")
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
			resolution, err := resolver.Resolve(context.Background(), "token")
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
	resolution, err := resolver.Resolve(context.Background(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if resolution.UserID != 42 || resolution.AccountID != "" || v2Calls.Load() != 1 || v1Calls.Load() != 1 {
		t.Fatalf("fallback resolution/calls = %+v/%d/%d", resolution, v2Calls.Load(), v1Calls.Load())
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
	if _, err := resolver.Resolve(context.Background(), "token"); !IsKind(err, ErrorInfrastructure) {
		t.Fatalf("Resolve() error = %v, want infrastructure", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("backend calls = %d, want 1", calls.Load())
	}
}

func TestWireGuardPeersFetchesCompleteSnapshot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/internal/v2/wireguard/peers" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-Relay-Secret"); got != "secret" {
			t.Fatalf("X-Relay-Secret = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revision":"abc","generated_at":"2026-07-18T00:00:00Z",` +
			`"managed_prefixes":["198.51.100.20/32"],` +
			`"peers":[{"public_key":"k","allowed_prefixes":["198.51.100.20/32"]}],` +
			`"smtp_allowed_prefixes":["198.51.100.20/32"]}`))
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
	if state.Revision != "abc" || len(state.Peers) != 1 || state.Peers[0].PublicKey != "k" || len(state.SMTPAllowedPrefixes) != 1 {
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
		if r.URL.Path == "/internal/v2/wireguard/peers" {
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
	if strings.Join(paths, ",") != "/internal/v2/wireguard/peers,/internal/v1/wireguard/peers" || state.SMTPAllowedPrefixes != nil {
		t.Fatalf("paths/state = %v/%+v", paths, state)
	}
}

func TestWireGuardPeersRetainsStrictDecodingOnV2AndV1(t *testing.T) {
	for _, test := range []struct {
		name string
		v2   bool
		body string
	}{
		{name: "v2 unknown field", v2: true, body: `{"revision":"r","generated_at":"now","managed_prefixes":[],"peers":[],"smtp_allowed_prefixes":[],"extra":true}`},
		{name: "v1 does not accept v2 field", body: `{"revision":"r","generated_at":"now","managed_prefixes":[],"peers":[],"smtp_allowed_prefixes":[]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !test.v2 && r.URL.Path == "/internal/v2/wireguard/peers" {
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
			if _, err := resolver.WireGuardPeers(context.Background()); !IsKind(err, ErrorInfrastructure) {
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
			_, err = resolver.Resolve(context.Background(), "token")
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
		_, err = resolver.Resolve(context.Background(), "token")
		server.Close()
		if !IsKind(err, ErrorInfrastructure) {
			t.Fatalf("Resolve() error = %v, want infrastructure", err)
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
	_, err = resolver.Resolve(ctx, "token")
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
	_, err = resolver.Resolve(context.Background(), "token")
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != ErrorInfrastructure || typed.Status != http.StatusTemporaryRedirect {
		t.Fatalf("Resolve() error = %v, want infrastructure status %d", err, http.StatusTemporaryRedirect)
	}
	if followed.Load() {
		t.Fatal("resolver followed a backend redirect carrying the relay secret")
	}
}
