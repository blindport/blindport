package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/protocol"
)

func TestParseProvisioningV2StrictBoundsAndClaims(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	valid := testV2Config(now, testSubscriptionID1, "11111111-2222-4333-8444-555555555555", 7, []provisioningV2Edge{testV2Edge(now, "edge-a", "edge-a.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, "11111111-2222-4333-8444-555555555555", 7)})
	raw := testJSON(t, valid)
	if _, err := parseProvisioningV2(raw, now); err != nil {
		t.Fatalf("parseProvisioningV2(valid) = %v", err)
	}
	tests := map[string][]byte{
		"unknown":                []byte(`{"version":2,"subscriptions":[],"extra":true}`),
		"trailing":               append(append([]byte{}, raw...), []byte(` {}`)...),
		"duplicate":              []byte(`{"version":2,"version":2,"subscriptions":[]}`),
		"missing claim":          []byte(strings.Replace(string(raw), `,"domain":""`, ``, 1)),
		"too many subscriptions": testJSON(t, provisioningV2{Version: 2, Subscriptions: make([]provisioningSubscription, maxV2Subscriptions+1)}),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseProvisioningV2(input, now); err == nil {
				t.Fatal("parseProvisioningV2() accepted invalid response")
			}
		})
	}
	oversized := append(raw, make([]byte, maxProvisioningJSON)...)
	if _, err := parseProvisioningV2(oversized, now); err == nil {
		t.Fatal("parseProvisioningV2() accepted an oversized response")
	}
}

func TestParseProvisioningV2AcceptsExactIPAndRelayMetadata(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	ip := "203.0.113.20"
	domain := "site.example"
	tests := []provisioningSubscription{
		{
			AssignedIP: &ip, Transport: "tcp", Product: "ip", SubscriptionID: testSubscriptionID1,
			Edges: []provisioningV2Edge{testV2Edge(now, "edge-a", "edge-a.example:5443", provisioningV2Claim{Kind: protocol.ClaimIP, IP: ip}, testSubscriptionID1, instance, 7)},
		},
		{
			Domain: &domain, Transport: "tcp", Product: "relay", SubscriptionID: testSubscriptionID1,
			Edges: []provisioningV2Edge{testV2Edge(now, "edge-a", "edge-a.example:5443", provisioningV2Claim{Kind: protocol.ClaimRelay, Domain: domain}, testSubscriptionID1, instance, 7)},
		},
	}
	for _, subscription := range tests {
		raw := testJSON(t, provisioningV2{Version: 2, Subscriptions: []provisioningSubscription{subscription}})
		if _, err := parseProvisioningV2(raw, now); err != nil {
			t.Fatalf("parseProvisioningV2(%s) = %v", subscription.Product, err)
		}
		for _, transport := range []string{"", "udp"} {
			invalid := subscription
			invalid.Transport = transport
			if _, err := parseProvisioningV2(testJSON(t, provisioningV2{Version: 2, Subscriptions: []provisioningSubscription{invalid}}), now); err == nil {
				t.Fatalf("parseProvisioningV2(%s transport %q) succeeded", subscription.Product, transport)
			}
		}
	}
}

func TestFetchProvisioningV2ResponseClassification(t *testing.T) {
	instance := "11111111-2222-4333-8444-555555555555"
	now := time.Now().UTC().Truncate(time.Second)
	valid := testJSON(t, testV2Config(now, testSubscriptionID1, instance, 7, []provisioningV2Edge{testV2Edge(now, "edge-a", "edge-a.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, 7)}))
	tests := []struct {
		name string
		code int
		body string
		kind v2FetchKind
	}{
		{name: "not found", code: http.StatusNotFound, kind: v2FeatureUnavailable},
		{name: "denied", code: http.StatusForbidden, kind: v2Terminal},
		{name: "multiple choices", code: http.StatusMultipleChoices, kind: v2Terminal},
		{name: "rate limited", code: http.StatusTooManyRequests, kind: v2Terminal},
		{name: "malformed", code: http.StatusOK, body: `{`, kind: v2Terminal},
		{name: "server", code: http.StatusBadGateway, kind: v2Infrastructure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("instance_id") != instance || r.Header.Get("Authorization") != "Bearer secret" {
					t.Error("request was not bound to the client identity")
				}
				w.WriteHeader(test.code)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			_, _, err := fetchProvisioningV2(context.Background(), server.Client(), server.URL, "secret", instance)
			var classified *v2FetchError
			if !errors.As(err, &classified) || classified.kind != test.kind {
				t.Fatalf("error = %v, want kind %d", err, test.kind)
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(valid) }))
	defer server.Close()
	if _, _, err := fetchProvisioningV2(context.Background(), server.Client(), server.URL, "secret", instance); err != nil {
		t.Fatalf("valid fetch = %v", err)
	}
	redirected := false
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirected" {
			redirected = true
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/redirected", http.StatusFound)
	}))
	defer server.Close()
	_, _, err := fetchProvisioningV2(context.Background(), server.Client(), server.URL, "secret", instance)
	var classified *v2FetchError
	if !errors.As(err, &classified) || classified.kind != v2Terminal || redirected {
		t.Fatalf("redirect error = %v, redirected = %t", err, redirected)
	}
}

func TestAuthorizationCacheSecurityAndBinding(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	identity := credentialIdentity{instanceID: instance, generation: 7}
	config := testV2Config(now, testSubscriptionID1, instance, 7, []provisioningV2Edge{testV2Edge(now, "edge-a", "edge-a.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, 7)})
	raw := testJSON(t, config)
	directory := privateStateDir(t)
	cache := authorizationCache{stateDir: directory}
	if err := cache.store(identity, raw, &config); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(cache.path())
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode = %v, %v", info, err)
	}
	if _, err := cache.load(instance, 7, now); err != nil {
		t.Fatalf("load cache = %v", err)
	}
	if _, err := cache.load(instance, 8, now); err == nil {
		t.Fatal("cache accepted another credential generation")
	}
	if _, err := cache.load("22222222-2222-4333-8444-555555555555", 7, now); err == nil {
		t.Fatal("cache accepted another instance")
	}

	previous, err := os.ReadFile(cache.path())
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.store(identity, []byte(`{`), &config); err == nil {
		t.Fatal("cache stored invalid bytes")
	}
	current, err := os.ReadFile(cache.path())
	if err != nil || string(current) != string(previous) {
		t.Fatal("invalid cache write did not preserve the prior file")
	}
	if err := os.Remove(cache.path()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(directory, "target"), cache.path()); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.load(instance, 7, now); err == nil {
		t.Fatal("cache followed a symlink")
	}
	if err := os.Remove(cache.path()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache.path(), make([]byte, maxAuthorizationCacheSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.load(instance, 7, now); err == nil {
		t.Fatal("cache accepted oversized data")
	}
	if err := os.Remove(cache.path()); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(cache.path(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.load(instance, 7, now); err == nil {
		t.Fatal("cache accepted a FIFO")
	}
}

func TestAuthorizationCacheBindsEmptyResponsesAndRejectsLegacyRaw(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	otherInstance := "22222222-2222-4333-8444-555555555555"
	directory := privateStateDir(t)
	cache := authorizationCache{stateDir: directory}
	empty := provisioningV2{Version: 2, Subscriptions: []provisioningSubscription{}}
	raw := testJSON(t, empty)
	if err := cache.store(credentialIdentity{instanceID: instance, generation: 7}, raw, &empty); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.load(otherInstance, 7, now); err == nil {
		t.Fatal("empty cache response accepted another instance")
	}
	if _, err := cache.load(instance, 8, now); err == nil {
		t.Fatal("empty cache response accepted another credential generation")
	}
	if err := os.WriteFile(cache.path(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.load(instance, 7, now); err == nil {
		t.Fatal("legacy unbound cache response was accepted")
	}
	envelope := `{"version":1,"instance_id":"` + instance + `","generation":7,"response":` + string(raw) + `}`
	for name, input := range map[string][]byte{
		"unknown":   []byte(envelope[:len(envelope)-1] + `,"extra":true}`),
		"duplicate": []byte(`{"version":1,"version":1,"instance_id":"` + instance + `","generation":7,"response":` + string(raw) + `}`),
		"trailing":  []byte(envelope + ` {}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseAuthorizationCache(input, instance, 7, now); err == nil {
				t.Fatal("authorization cache envelope was accepted")
			}
		})
	}
}

func TestFetchProvisioningReplacesNonemptyCacheWithAuthoritativeEmptyResponse(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	directory := privateStateDir(t)
	credentials := &credentialManager{stateDir: directory, snapshot: &credentialSnapshot{stored: storedCredential{InstanceID: instance, Generation: 7}}}
	nonempty := testV2Config(now, testSubscriptionID1, instance, 7, []provisioningV2Edge{testV2Edge(now, "edge-a", "edge.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, 7)})
	responses := [][]byte{testJSON(t, nonempty), testJSON(t, provisioningV2{Version: 2, Subscriptions: []provisioningSubscription{}})}
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v3/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(responses[requests])
		requests++
	}))
	defer server.Close()
	for range responses {
		result, err := fetchProvisioning(context.Background(), server.Client(), server.URL, "secret", credentials, false)
		if err != nil || result.Source != provisioningOnlineV2 {
			t.Fatalf("fetch result = %+v, err = %v", result, err)
		}
	}
	cached, err := (authorizationCache{stateDir: directory}).load(instance, 7, now)
	if err != nil || len(cached.Subscriptions) != 0 {
		t.Fatalf("cached configuration = %+v, err = %v", cached, err)
	}
}

func TestFetchProvisioningCoordinatorFallbackMatrix(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	directory := privateStateDir(t)
	credentials := &credentialManager{stateDir: directory, snapshot: &credentialSnapshot{stored: storedCredential{InstanceID: instance, Generation: 7}}}
	config := testV2Config(now, testSubscriptionID1, instance, 7, []provisioningV2Edge{testV2Edge(now, "edge-a", "edge-a.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, 7)})
	raw := testJSON(t, config)
	cache := authorizationCache{stateDir: directory}
	if err := cache.store(credentialIdentity{instanceID: instance, generation: 7}, raw, &config); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, v2Body string
		v2Code       int
		want         provisioningSource
		wantErr      bool
	}{
		{name: "v1 fallback", v2Code: http.StatusNotFound, want: provisioningOnlineV1},
		{name: "infrastructure cache", v2Code: http.StatusServiceUnavailable, want: provisioningCacheV2},
		{name: "denial does not use cache", v2Code: http.StatusForbidden, wantErr: true},
		{name: "malformed does not use cache", v2Code: http.StatusOK, v2Body: `{`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/api/v3/") {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if strings.HasPrefix(r.URL.Path, "/api/v1/") {
					_, _ = io.WriteString(w, `[]`)
					return
				}
				w.WriteHeader(test.v2Code)
				_, _ = io.WriteString(w, test.v2Body)
			}))
			defer server.Close()
			result, err := fetchProvisioning(context.Background(), server.Client(), server.URL, "secret-value", credentials, false)
			if test.wantErr {
				if err == nil {
					t.Fatal("fetchProvisioning() succeeded")
				}
				if strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), "203.0.113.20") {
					t.Fatalf("unsanitized error %q", err)
				}
				return
			}
			if err != nil || result.Source != test.want {
				t.Fatalf("result = %+v, %v", result, err)
			}
		})
	}
	if err := os.Remove(cache.path()); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	if _, err := fetchProvisioning(context.Background(), server.Client(), server.URL, "secret-value", credentials, false); err == nil {
		t.Fatal("first infrastructure outage used a nonexistent cache")
	}
}

func TestFetchProvisioningInsecureUsesV1WithoutCredentialsOrV2Cache(t *testing.T) {
	var v1Calls, v2Calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/client/config":
			v1Calls++
			_, _ = io.WriteString(w, `[]`)
		case "/api/v2/client/config":
			v2Calls++
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	result, err := fetchProvisioning(context.Background(), server.Client(), server.URL, "secret", nil, true)
	if err != nil || result.Source != provisioningOnlineV1 || v1Calls != 1 || v2Calls != 0 {
		t.Fatalf("result = %+v, err = %v, v1 = %d, v2 = %d", result, err, v1Calls, v2Calls)
	}
	if _, err := fetchProvisioning(context.Background(), server.Client(), server.URL, "secret", nil, false); err == nil {
		t.Fatal("secure fetch accepted nil credentials")
	}
}

func TestFetchProvisioningRetriesWhenCredentialGenerationChanges(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	directory := privateStateDir(t)
	credentials := &credentialManager{stateDir: directory, snapshot: &credentialSnapshot{stored: storedCredential{InstanceID: instance, Generation: 7}}}
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v3/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		requests++
		generation := 8
		if requests == 1 {
			generation = 7
			close(firstStarted)
			<-releaseFirst
		}
		config := testV2Config(now, testSubscriptionID1, instance, generation, []provisioningV2Edge{testV2Edge(now, "edge-a", "edge.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, generation)})
		_, _ = w.Write(testJSON(t, config))
	}))
	defer server.Close()
	resultCh := make(chan provisioningResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := fetchProvisioning(context.Background(), server.Client(), server.URL, "secret", credentials, false)
		resultCh <- result
		errCh <- err
	}()
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first provisioning request did not start")
	}
	credentials.mu.Lock()
	credentials.snapshot = &credentialSnapshot{stored: storedCredential{InstanceID: instance, Generation: 8}}
	credentials.mu.Unlock()
	close(releaseFirst)
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	result := <-resultCh
	if result.Source != provisioningOnlineV2 || result.V2 == nil || requests != 2 {
		t.Fatalf("result = %+v, requests = %d", result, requests)
	}
}

type hookedAuthorizationCacheStore struct {
	cache      authorizationCache
	afterStore func()
}

func (s *hookedAuthorizationCacheStore) store(identity credentialIdentity, raw []byte, config *provisioningV2) error {
	if err := s.cache.store(identity, raw, config); err != nil {
		return err
	}
	if s.afterStore != nil {
		s.afterStore()
	}
	return nil
}

func (s *hookedAuthorizationCacheStore) load(instanceID string, generation int, now time.Time) (*provisioningV2, error) {
	return s.cache.load(instanceID, generation, now)
}

func TestFetchProvisioningRetriesAfterCredentialChangeDuringCacheStore(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	directory := privateStateDir(t)
	credentials := &credentialManager{stateDir: directory, snapshot: &credentialSnapshot{stored: storedCredential{InstanceID: instance, Generation: 7}}}
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v3/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		requests++
		generation := credentials.generation()
		config := testV2Config(now, testSubscriptionID1, instance, generation, []provisioningV2Edge{testV2Edge(now, "edge-a", "edge.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, generation)})
		_, _ = w.Write(testJSON(t, config))
	}))
	defer server.Close()
	store := &hookedAuthorizationCacheStore{cache: authorizationCache{stateDir: directory}}
	store.afterStore = func() {
		credentials.mu.Lock()
		defer credentials.mu.Unlock()
		if credentials.snapshot.stored.Generation == 7 {
			credentials.snapshot = &credentialSnapshot{stored: storedCredential{InstanceID: instance, Generation: 8}}
		}
	}
	result, err := fetchProvisioningWithCache(context.Background(), server.Client(), server.URL, "secret", credentials, false, store)
	if err != nil || result.Source != provisioningOnlineV2 || result.V2 == nil || requests != 2 || credentials.generation() != 8 {
		t.Fatalf("result = %+v, err = %v, requests = %d, generation = %d", result, err, requests, credentials.generation())
	}
}

func TestFetchProvisioningFailsAfterSecondCredentialChangeDuringCacheStore(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	directory := privateStateDir(t)
	credentials := &credentialManager{stateDir: directory, snapshot: &credentialSnapshot{stored: storedCredential{InstanceID: instance, Generation: 7}}}
	var requests, stores int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v3/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		requests++
		generation := credentials.generation()
		config := testV2Config(now, testSubscriptionID1, instance, generation, []provisioningV2Edge{testV2Edge(now, "edge-a", "edge.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, generation)})
		_, _ = w.Write(testJSON(t, config))
	}))
	defer server.Close()
	store := &hookedAuthorizationCacheStore{cache: authorizationCache{stateDir: directory}, afterStore: func() {
		stores++
		credentials.mu.Lock()
		credentials.snapshot = &credentialSnapshot{stored: storedCredential{InstanceID: instance, Generation: 7 + stores}}
		credentials.mu.Unlock()
	}}
	result, err := fetchProvisioningWithCache(context.Background(), server.Client(), server.URL, "secret", credentials, false, store)
	if err == nil || provisioningFailure(err) != provisioningInfrastructure || result.V2 != nil || requests != 2 || stores != 2 {
		t.Fatalf("result = %+v, err = %v, requests = %d, stores = %d", result, err, requests, stores)
	}
}

func TestBuildV2PlansBindsExactProviderEdgesAndOverride(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	edges := []provisioningV2Edge{
		testV2Edge(now, "edge-a", "primary.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, 7),
		testV2Edge(now, "edge-b", "secondary.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.21", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, 7),
	}
	config := testV2Config(now, testSubscriptionID1, instance, 7, edges)
	plans, err := buildV2MappingPlans([]mapping{{SubscriptionID: testSubscriptionID1, Upstream: "app:80"}}, &config, "secondary.example:5443")
	if err != nil || len(plans) != 1 || plans[0].EdgeID != "edge-b" || plans[0].Claim.IP != "203.0.113.21" || plans[0].Entitlement != edges[1].Entitlement {
		t.Fatalf("plans = %+v, %v", plans, err)
	}
	if _, err := buildV2MappingPlans([]mapping{{SubscriptionID: testSubscriptionID1, Upstream: "app:80"}}, &config, "other.example:5443"); err == nil {
		t.Fatal("v2 override was not rejected")
	}
}

func TestBuildV2PlansSortsAndAllowsMissingSubscriptions(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	edges := []provisioningV2Edge{
		testV2Edge(now, "edge-b", "b.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.21", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, 7),
		testV2Edge(now, "edge-a", "a.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, 7),
	}
	config := testV2Config(now, testSubscriptionID1, instance, 7, edges)
	mappings := []mapping{{SubscriptionID: testSubscriptionID1, Upstream: "app:80"}, {SubscriptionID: testSubscriptionID2, Upstream: "other:80"}}
	plans, err := buildAvailableV2MappingPlans(mappings, &config, "")
	if err != nil || len(plans) != 2 || plans[0].RelayAddr != "a.example:5443" || plans[1].RelayAddr != "b.example:5443" {
		t.Fatalf("plans = %+v, %v", plans, err)
	}
	if _, err := buildV2MappingPlans(mappings, &config, ""); err == nil {
		t.Fatal("required v2 plan builder accepted missing subscription")
	}
}

func TestEntitlementMetadataRejectsNoncanonicalAndMismatchedFields(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	edge := testV2Edge(now, "edge-a", "edge-a.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, 7)
	payload, err := parseEntitlementMetadata(edge.Entitlement)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEntitlement(edge.Entitlement, testSubscriptionID1, edge, now); err != nil {
		t.Fatalf("validate valid entitlement: %v", err)
	}
	parts := strings.Split(edge.Entitlement, ".")
	payloadJSON := testJSON(t, payload)
	reordered := bytes.Replace(payloadJSON, []byte(`{"typ":"blindport-offline-entitlement","v":1`), []byte(`{"v":1,"typ":"blindport-offline-entitlement"`), 1)
	tests := map[string]string{
		"padded payload":         "v1." + parts[1] + "=." + parts[2],
		"noncanonical signature": "v1." + parts[1] + "." + parts[2][:len(parts[2])-1] + "B",
		"short signature":        "v1." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 63)),
		"duplicate metadata":     testArtifact([]byte(strings.TrimSuffix(string(payloadJSON), "}") + `,"typ":"blindport-offline-entitlement"}`)),
		"unknown metadata":       testArtifact([]byte(strings.TrimSuffix(string(payloadJSON), "}") + `,"extra":true}`)),
		"trailing metadata":      testArtifact(append(append([]byte(nil), payloadJSON...), []byte(` {}`)...)),
		"noncanonical order":     testArtifact(reordered),
	}
	for name, artifact := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateEntitlement(artifact, testSubscriptionID1, edge, now); err == nil {
				t.Fatal("validateEntitlement() accepted invalid metadata")
			}
		})
	}
	payload.Edge = "other"
	if err := validateEntitlement(testArtifact(testJSON(t, payload)), testSubscriptionID1, edge, now); err == nil {
		t.Fatal("validateEntitlement() accepted an edge mismatch")
	}
	payload, _ = parseEntitlementMetadata(edge.Entitlement)
	payload.IssuedAt++
	if err := validateEntitlement(testArtifact(testJSON(t, payload)), testSubscriptionID1, edge, now); err == nil {
		t.Fatal("validateEntitlement() accepted mismatched iat and nbf")
	}
	payload, _ = parseEntitlementMetadata(edge.Entitlement)
	payload.IP = "203.0.113.21"
	if err := validateEntitlement(testArtifact(testJSON(t, payload)), testSubscriptionID1, edge, now); err == nil {
		t.Fatal("validateEntitlement() accepted a claim mismatch")
	}
	for name, mutate := range map[string]func(*entitlementMetadata){
		"type":         func(value *entitlementMetadata) { value.Type = "other" },
		"version":      func(value *entitlementMetadata) { value.Version = 2 },
		"kid":          func(value *entitlementMetadata) { value.KeyID = "UPPER" },
		"account":      func(value *entitlementMetadata) { value.Account = "invalid" },
		"subscription": func(value *entitlementMetadata) { value.Subscription = "invalid" },
		"instance":     func(value *entitlementMetadata) { value.Instance = "invalid" },
		"client key":   func(value *entitlementMetadata) { value.ClientKey = "A" },
		"edge":         func(value *entitlementMetadata) { value.Edge = "UPPER" },
		"generation":   func(value *entitlementMetadata) { value.Generation = 0 },
		"jti":          func(value *entitlementMetadata) { value.TokenID = "A" },
	} {
		t.Run(name, func(t *testing.T) {
			value, err := parseEntitlementMetadata(edge.Entitlement)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&value)
			if err := validateEntitlement(testArtifact(testJSON(t, value)), testSubscriptionID1, edge, now); err == nil {
				t.Fatal("validateEntitlement() accepted malformed fixed metadata")
			}
		})
	}
}

func TestEntitlementRefreshDoesNotRestartWorker(t *testing.T) {
	key := workerKey{subscriptionID: testSubscriptionID1, relayAddr: "edge.example:5443"}
	first := workerPlan{SubscriptionID: key.subscriptionID, RelayAddr: key.relayAddr, EdgeID: "edge-a", Entitlement: "old", Upstream: "app:80", Claim: &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "site.example"}}
	second := first
	second.Entitlement = "new"
	if !sameWorkerPlan(first, second) {
		t.Fatal("proof refresh changed worker plan equality")
	}
	started := make(chan struct{}, 2)
	supervisor := newWorkerSupervisor(context.Background(), func(ctx context.Context, _ workerPlan) {
		started <- struct{}{}
		<-ctx.Done()
	})
	if err := supervisor.Reconcile([]workerPlan{first}); err != nil {
		t.Fatal(err)
	}
	assertWorkerStarts(t, started, 1)
	if err := supervisor.Reconcile([]workerPlan{second}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
		t.Fatal("proof refresh restarted a healthy worker")
	case <-time.After(20 * time.Millisecond):
	}
	if got, ok := supervisor.entitlements.Get(key); !ok || got != "new" {
		t.Fatalf("store = %q, %t", got, ok)
	}
	supervisor.Shutdown()
}

func TestEntitlementStoreReplaceRemovesInactiveWorkers(t *testing.T) {
	supervisor := newWorkerSupervisor(context.Background(), func(ctx context.Context, _ workerPlan) { <-ctx.Done() })
	first := workerPlan{SubscriptionID: testSubscriptionID1, RelayAddr: "edge-a:5443", Entitlement: "first"}
	second := workerPlan{SubscriptionID: testSubscriptionID2, RelayAddr: "edge-b:5443", Entitlement: "second"}
	if err := supervisor.Reconcile([]workerPlan{first, second}); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Reconcile([]workerPlan{second}); err != nil {
		t.Fatal(err)
	}
	if _, ok := supervisor.entitlements.Get(workerKey{subscriptionID: first.SubscriptionID, relayAddr: first.RelayAddr}); ok {
		t.Fatal("removed worker entitlement remained active")
	}
	if got, ok := supervisor.entitlements.Get(workerKey{subscriptionID: second.SubscriptionID, relayAddr: second.RelayAddr}); !ok || got != second.Entitlement {
		t.Fatalf("active entitlement = %q, %t", got, ok)
	}
	supervisor.Shutdown()
}

func TestEntitlementStoreConcurrentReplaceAndRead(t *testing.T) {
	store := newEntitlementStore()
	first := workerKey{subscriptionID: testSubscriptionID1, relayAddr: "edge-a:5443"}
	second := workerKey{subscriptionID: testSubscriptionID2, relayAddr: "edge-b:5443"}
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 1_000 {
				store.Replace(map[workerKey]string{first: "first"})
				store.Replace(map[workerKey]string{second: "second"})
			}
		}()
	}
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 1_000 {
				_, _ = store.Get(first)
				_, _ = store.Get(second)
			}
		}()
	}
	workers.Wait()
}

func testV2Config(now time.Time, subscriptionID, instance string, generation int, edges []provisioningV2Edge) provisioningV2 {
	ip := "203.0.113.20"
	port := uint16(10000)
	return provisioningV2{Version: 2, Subscriptions: []provisioningSubscription{{AssignedIP: &ip, AssignedPort: &port, Transport: "tcp", Product: "port", SubscriptionID: subscriptionID, Edges: edges}}}
}

func testV2Edge(now time.Time, id, endpoint string, claim provisioningV2Claim, subscriptionID, instance string, generation int) provisioningV2Edge {
	paid := uint64(now.Add(time.Hour).Unix())
	grace := paid + 3600
	encodedGeneration := paid<<generationBits | uint64(generation)
	payload := entitlementMetadata{Type: "blindport-offline-entitlement", Version: 1, KeyID: "offline-a", Account: testSubscriptionID2, Subscription: subscriptionID, Instance: instance, ClientKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Edge: id, Kind: string(claim.Kind), IP: claim.IP, Port: claim.Port, Transport: string(claim.Transport), Domain: claim.Domain, IssuedAt: uint64(now.Unix()), NotBefore: uint64(now.Unix()), PaidThrough: paid, GraceThrough: grace, Generation: encodedGeneration, TokenID: base64.RawURLEncoding.EncodeToString(make([]byte, 16))}
	raw := testJSON(nil, payload)
	return provisioningV2Edge{ID: id, Endpoint: endpoint, Claim: claim, Entitlement: testArtifact(raw), PaidThrough: paid, GraceThrough: grace, Generation: encodedGeneration}
}

func testArtifact(payload []byte) string {
	return "v1." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
}

func testJSON(t testing.TB, value any) []byte {
	if t != nil {
		t.Helper()
	}
	raw, err := json.Marshal(value)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	return raw
}
