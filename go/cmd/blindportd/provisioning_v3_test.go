package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/protocol"
)

func TestParseProvisioningV3ScopesAndWildcardPropagation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	config := testV3WildcardConfig(t, now, "11111111-2222-4333-8444-555555555555", 7)
	raw := testJSON(t, config)
	parsed, err := parseProvisioningV3(raw, now)
	if err != nil {
		t.Fatalf("parseProvisioningV3() = %v", err)
	}
	plans, err := buildV3MappingPlans([]mapping{{SubscriptionID: testSubscriptionID1, Upstream: "app:443", TLSMode: tlsModePassthrough}}, parsed, "")
	if err != nil || len(plans) != 1 || plans[0].Claim.Scope != protocol.RelayHostnameScopeWildcard {
		t.Fatalf("plans = %+v, %v", plans, err)
	}
	if _, err := buildV3MappingPlans([]mapping{{SubscriptionID: testSubscriptionID1, Upstream: "app:443", TLSMode: tlsModeAutomatic, ACMETermsAccepted: true}}, parsed, ""); err == nil {
		t.Fatal("wildcard plan accepted automatic TLS")
	}
	for _, raw := range [][]byte{
		[]byte(strings.Replace(string(raw), `"scope":"wildcard"`, `"scope":"other"`, 1)),
		[]byte(strings.Replace(string(raw), `"relay_hostname_scope":"wildcard"`, `"relay_hostname_scope":"exact"`, 1)),
		[]byte(strings.Replace(string(raw), `,"scope":"wildcard"`, "", 1)),
	} {
		if _, err := parseProvisioningV3(raw, now); err == nil {
			t.Fatal("parseProvisioningV3 accepted invalid scope")
		}
	}
}

func TestProvisioningV3RetainsV1EntitlementsForExactClaims(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	domain := "exact.example"
	v2Edge := testV2Edge(now, "edge-a", "edge.example:5443", provisioningV2Claim{Kind: protocol.ClaimRelay, Domain: domain}, testSubscriptionID1, instance, 7)
	config := provisioningV3{Version: 3, Subscriptions: []provisioningV3Subscription{{
		Domain: &domain, Transport: "tcp", Product: string(protocol.ClaimRelay), RelayHostnameScope: "exact", SubscriptionID: testSubscriptionID1,
		Edges: []provisioningV3Edge{{ID: v2Edge.ID, Endpoint: v2Edge.Endpoint, Claim: provisioningV3Claim{Kind: protocol.ClaimRelay, Domain: domain, Scope: "exact"}, Entitlement: v2Edge.Entitlement, PaidThrough: v2Edge.PaidThrough, GraceThrough: v2Edge.GraceThrough, Generation: v2Edge.Generation}},
	}}}
	if _, err := parseProvisioningV3(testJSON(t, config), now); err != nil {
		t.Fatalf("exact v3 with v1 entitlement rejected: %v", err)
	}
}

func TestProvisioningV3CacheIsSeparateAndStrict(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	config := testV3WildcardConfig(t, now, instance, 7)
	raw := testJSON(t, config)
	cache := authorizationCache{stateDir: privateStateDir(t)}
	identity := credentialIdentity{instanceID: instance, generation: 7}
	if err := cache.storeV3(identity, raw, &config); err != nil {
		t.Fatal(err)
	}
	if cache.path() == cache.v3Path() {
		t.Fatal("v3 cache reused v2 cache path")
	}
	if _, err := cache.loadV3(instance, 7, now); err != nil {
		t.Fatalf("loadV3 = %v", err)
	}
	v2 := testV2Config(now, testSubscriptionID1, instance, 7, []provisioningV2Edge{testV2Edge(now, "edge-a", "edge.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, 7)})
	if err := os.WriteFile(cache.v3Path(), testJSON(t, v2), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.loadV3(instance, 7, now); err == nil {
		t.Fatal("v3 cache accepted v2 response")
	}
}

func TestProvisioningV3FallbackOnlyOnNotFound(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	credentials := &credentialManager{stateDir: privateStateDir(t), snapshot: &credentialSnapshot{stored: storedCredential{InstanceID: instance, Generation: 7}}}
	v2 := testV2Config(now, testSubscriptionID1, instance, 7, []provisioningV2Edge{testV2Edge(now, "edge-a", "edge.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, 7)})
	var v2Calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/client/config":
			http.NotFound(w, r)
		case "/api/v2/client/config":
			v2Calls++
			_, _ = w.Write(testJSON(t, v2))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	result, err := fetchProvisioning(context.Background(), server.Client(), server.URL, "token", credentials, false)
	if err != nil || result.Source != provisioningOnlineV2 || result.V2 == nil || v2Calls != 1 {
		t.Fatalf("fallback result = %+v, %v, v2 calls %d", result, err, v2Calls)
	}
	v2Calls = 0
	malformed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v3/client/config" {
			_, _ = w.Write([]byte(`{`))
			return
		}
		v2Calls++
	}))
	defer malformed.Close()
	if _, err := fetchProvisioning(context.Background(), malformed.Client(), malformed.URL, "token", credentials, false); err == nil || v2Calls != 0 {
		t.Fatalf("malformed v3 downgraded, error = %v, v2 calls %d", err, v2Calls)
	}
}

func testV3WildcardConfig(t testing.TB, now time.Time, instance string, generation int) provisioningV3 {
	t.Helper()
	domain := "public.example"
	paid := uint64(now.Add(time.Hour).Unix())
	grace := paid + 3600
	encodedGeneration := paid<<generationBits | uint64(generation)
	claim := provisioningV3Claim{Kind: protocol.ClaimRelay, Domain: domain, Scope: "wildcard"}
	payload := entitlementMetadata{Type: "blindport-offline-entitlement", Version: 2, KeyID: "offline-a", Account: testSubscriptionID2, Subscription: testSubscriptionID1, Instance: instance, ClientKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Edge: "edge-a", Kind: string(claim.Kind), Domain: claim.Domain, Scope: claim.Scope, IssuedAt: uint64(now.Unix()), NotBefore: uint64(now.Unix()), PaidThrough: paid, GraceThrough: grace, Generation: encodedGeneration, TokenID: base64.RawURLEncoding.EncodeToString(make([]byte, 16))}
	edge := provisioningV3Edge{ID: "edge-a", Endpoint: "edge.example:5443", Claim: claim, Entitlement: testArtifact(testJSON(t, payload)), PaidThrough: paid, GraceThrough: grace, Generation: encodedGeneration}
	return provisioningV3{Version: 3, Subscriptions: []provisioningV3Subscription{{Domain: &domain, Transport: "tcp", Product: string(protocol.ClaimRelay), RelayHostnameScope: "wildcard", SubscriptionID: testSubscriptionID1, Edges: []provisioningV3Edge{edge}}}}
}
