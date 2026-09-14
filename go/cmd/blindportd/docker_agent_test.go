package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/protocol"
	containertypes "github.com/moby/moby/api/types/container"
)

type recordingPlanReconciler struct {
	mu    sync.Mutex
	calls [][]workerPlan
}

func (r *recordingPlanReconciler) Reconcile(plans []workerPlan) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]workerPlan(nil), plans...))
	return nil
}

func (r *recordingPlanReconciler) snapshots() [][]workerPlan {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([][]workerPlan, len(r.calls))
	for i := range r.calls {
		result[i] = append([]workerPlan(nil), r.calls[i]...)
	}
	return result
}

func TestOrderAPIClientSendsContractAndAcceptsFullResponse(t *testing.T) {
	var gotRequest orderRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/client/orders/web" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer SECRET" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotRequest); err != nil {
			t.Error(err)
		}
		_, _ = io.WriteString(w, `{
  "order_key":"web",
  "subscription":{"id":"42424242-4242-4242-8242-424242424242","status":"pending","product":"relay","monthly_price_sats":100},
  "payment":{"id":7,"status":"pending"},
  "state":"awaiting_domain"
}`)
	}))
	defer server.Close()
	client := &orderAPIClient{client: server.Client(), backend: server.URL + "/", token: "SECRET"}
	response, err := client.put(context.Background(), mapping{
		AccountName: "public", OrderKey: "web", Product: "relay", Domain: "web.example", Transport: "tcp", BillingTerm: "yearly",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Subscription.ID != testSubscriptionID42 || response.State != "awaiting_domain" {
		t.Fatalf("response = %+v", response)
	}
	want := orderRequest{Product: "relay", Domain: "web.example", Transport: "tcp", Delivery: "framed", BillingTerm: "yearly"}
	if gotRequest != want {
		t.Fatalf("request = %+v, want %+v", gotRequest, want)
	}
}

func TestOrderAPIClientBoundsAndValidatesResponses(t *testing.T) {
	tests := map[string]struct {
		status int
		body   string
	}{
		"status":        {status: http.StatusUnauthorized, body: `{"detail":"SECRET"}`},
		"oversized":     {body: strings.Repeat("x", maxOrderResponse+1)},
		"trailing":      {body: `{"order_key":"web","subscription":{"id":"11111111-1111-4111-8111-111111111111","status":"pending"},"state":"awaiting_payment"} {}`},
		"wrong key":     {body: `{"order_key":"other","subscription":{"id":"11111111-1111-4111-8111-111111111111","status":"pending"},"state":"awaiting_payment"}`},
		"invalid sub":   {body: `{"order_key":"web","subscription":{"id":0,"status":"pending"},"state":"awaiting_payment"}`},
		"unknown state": {body: `{"order_key":"web","subscription":{"id":"11111111-1111-4111-8111-111111111111","status":"pending"},"state":"surprising"}`},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if test.status != 0 {
					w.WriteHeader(test.status)
				}
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			client := &orderAPIClient{client: server.Client(), backend: server.URL, token: "SECRET"}
			_, err := client.put(context.Background(), testOrderDeclaration())
			if err == nil {
				t.Fatal("put() succeeded")
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("error exposed bearer token: %v", err)
			}
		})
	}
}

func TestOrderAPIClientUsesHTTPTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = 25 * time.Millisecond
	client := &orderAPIClient{client: httpClient, backend: server.URL, token: "token"}
	started := time.Now()
	if _, err := client.put(context.Background(), testOrderDeclaration()); err == nil {
		t.Fatal("put() succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("stalled order response took %s", elapsed)
	}
}

func TestDockerAgentPendingToActiveRepeatedSnapshotAndRemoval(t *testing.T) {
	var putCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		putCalls++
		_, _ = io.WriteString(w, `{"order_key":"web","subscription":{"id":"42424242-4242-4242-8242-424242424242","status":"pending"},"payment":null,"state":"awaiting_payment"}`)
	}))
	defer server.Close()
	fake := &fakeDockerClient{containers: []containertypes.Summary{{ID: "web", Labels: testOrderLabels()}}}
	reconciler := &recordingPlanReconciler{}
	var cfg []provisioning
	agent := newTestDockerAgent(fake, server, reconciler, func(context.Context) ([]provisioning, error) {
		return cfg, nil
	})

	agent.reconcile(context.Background())
	if calls := reconciler.snapshots(); len(calls) != 1 || len(calls[0]) != 0 {
		t.Fatalf("pending reconciliations = %+v", calls)
	}
	cfg = []provisioning{{
		SubscriptionID: testSubscriptionID42, Product: "relay", Domain: "web.example",
		RelayEndpoint: "edge.example:5443", Transport: "tcp",
	}}
	agent.reconcile(context.Background())
	calls := reconciler.snapshots()
	if len(calls) != 2 || len(calls[1]) != 1 || calls[1][0].SubscriptionID != testSubscriptionID42 || calls[1][0].Upstream != "web:443" {
		t.Fatalf("active reconciliations = %+v", calls)
	}
	if putCalls != 1 {
		t.Fatalf("unchanged declaration PUT calls = %d, want 1", putCalls)
	}

	fake.containers = nil
	agent.reconcile(context.Background())
	calls = reconciler.snapshots()
	if len(calls) != 3 || len(calls[2]) != 0 {
		t.Fatalf("removal reconciliations = %+v", calls)
	}
	if len(agent.orderCache) != 0 {
		t.Fatalf("order cache after removal = %+v", agent.orderCache)
	}
}

func TestDockerAgentsScopeOrdersAndRemovalByConfiguredAccount(t *testing.T) {
	var mu sync.Mutex
	requests := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		requests[token]++
		mu.Unlock()
		subscriptionID := testSubscriptionID1
		if token == "PRIVATE" {
			subscriptionID = testSubscriptionID2
		}
		_, _ = io.WriteString(w, `{"order_key":"web","subscription":{"id":"`+subscriptionID+`","status":"active"},"state":"active"}`)
	}))
	defer server.Close()
	fake := &fakeDockerClient{containers: []containertypes.Summary{
		{ID: "public", Labels: accountOrderLabels("public", "web", "public:443")},
		{ID: "private", Labels: accountOrderLabels("private", "web", "private:443")},
	}}
	now := time.Unix(1_700_000_000, 0)
	discovery, err := newSharedDockerDiscovery(fake, []staticAccount{{Name: "public"}, {Name: "private"}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	discovery.now = func() time.Time { return now }
	publicPlans := &recordingPlanReconciler{}
	privatePlans := &recordingPlanReconciler{}
	newAgent := func(accountName, token, subscriptionID string, plans *recordingPlanReconciler) *dockerAgent {
		return &dockerAgent{
			docker: fake, discovery: discovery,
			accountName: accountName, accountNames: []string{"public", "private"},
			orders: &orderAPIClient{client: server.Client(), backend: server.URL, token: token},
			fetchConfig: func(context.Context) ([]provisioning, error) {
				return []provisioning{{
					SubscriptionID: subscriptionID, Product: "relay", Domain: "web.example",
					RelayEndpoint: "edge.example:5443", Transport: "tcp",
				}}, nil
			},
			supervisor: plans, pollInterval: time.Second,
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)), now: time.Now,
			orderCache: make(map[string]*orderCacheEntry),
		}
	}
	publicAgent := newAgent("public", "PUBLIC", testSubscriptionID1, publicPlans)
	privateAgent := newAgent("private", "PRIVATE", testSubscriptionID2, privatePlans)
	if err := publicAgent.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := privateAgent.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	publicRequests, privateRequests := requests["PUBLIC"], requests["PRIVATE"]
	mu.Unlock()
	if publicRequests != 1 || privateRequests != 1 || len(publicAgent.orderCache) != 1 || len(privateAgent.orderCache) != 1 || fake.calls != 1 {
		t.Fatalf("requests/cache/discovery = %d/%d, %d/%d, %d", publicRequests, privateRequests, len(publicAgent.orderCache), len(privateAgent.orderCache), fake.calls)
	}
	publicSnapshots, privateSnapshots := publicPlans.snapshots(), privatePlans.snapshots()
	if len(publicSnapshots) != 1 || len(publicSnapshots[0]) != 1 || publicSnapshots[0][0].AccountName != "public" || publicSnapshots[0][0].Upstream != "public:443" {
		t.Fatalf("public plans = %+v", publicSnapshots)
	}
	if len(privateSnapshots) != 1 || len(privateSnapshots[0]) != 1 || privateSnapshots[0][0].AccountName != "private" || privateSnapshots[0][0].Upstream != "private:443" {
		t.Fatalf("private plans = %+v", privateSnapshots)
	}

	fake.containers = []containertypes.Summary{{ID: "private", Labels: accountOrderLabels("private", "web", "private:443")}}
	now = now.Add(time.Second)
	if err := publicAgent.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := privateAgent.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(publicAgent.orderCache) != 0 || len(privateAgent.orderCache) != 1 {
		t.Fatalf("cache after public removal = %d/%d", len(publicAgent.orderCache), len(privateAgent.orderCache))
	}
	publicSnapshots, privateSnapshots = publicPlans.snapshots(), privatePlans.snapshots()
	if len(publicSnapshots[len(publicSnapshots)-1]) != 0 || len(privateSnapshots[len(privateSnapshots)-1]) != 1 {
		t.Fatalf("plans after public removal = %+v/%+v", publicSnapshots, privateSnapshots)
	}
}

func TestDockerAgentRetainsAccountSnapshotOnUnknownSelector(t *testing.T) {
	fake := &fakeDockerClient{containers: []containertypes.Summary{{ID: "public", Labels: map[string]string{
		dockerMappingPrefix + "web.account":      "public",
		dockerMappingPrefix + "web.subscription": testSubscriptionID1,
		dockerMappingPrefix + "web.upstream":     "public:443",
	}}}}
	reconciler := &recordingPlanReconciler{}
	agent := &dockerAgent{
		docker: fake, accountName: "public", accountNames: []string{"public"}, supervisor: reconciler,
		fetchConfig: func(context.Context) ([]provisioning, error) {
			return []provisioning{{SubscriptionID: testSubscriptionID1, Product: "relay", Domain: "web.example", RelayEndpoint: "edge.example:5443"}}, nil
		},
		pollInterval: time.Second, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), now: time.Now,
		orderCache: make(map[string]*orderCacheEntry),
	}
	if err := agent.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fake.containers = append(fake.containers, containertypes.Summary{ID: "unknown", Labels: accountOrderLabels("unknown", "bad", "bad:443")})
	if err := agent.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(agent.desired) != 1 || agent.desired[0].AccountName != "public" {
		t.Fatalf("desired snapshot after unknown account = %+v", agent.desired)
	}
	snapshots := reconciler.snapshots()
	if len(snapshots) != 2 || len(snapshots[1]) != 1 {
		t.Fatalf("worker snapshot after unknown account = %+v", snapshots)
	}
}

func TestDockerAgentRetainsSnapshotAndWorkersAcrossTransientFailures(t *testing.T) {
	fake := &fakeDockerClient{containers: []containertypes.Summary{{ID: "legacy", Labels: dockerLabels("web", testSubscriptionID42, "web:443")}}}
	reconciler := &recordingPlanReconciler{}
	fetchErr := error(nil)
	agent := newTestDockerAgent(fake, nil, reconciler, func(context.Context) ([]provisioning, error) {
		if fetchErr != nil {
			return nil, fetchErr
		}
		return []provisioning{{
			SubscriptionID: testSubscriptionID42, Product: "relay", Domain: "web.example", RelayEndpoint: "edge.example:5443",
		}}, nil
	})
	agent.reconcile(context.Background())
	if calls := reconciler.snapshots(); len(calls) != 1 || len(calls[0]) != 1 {
		t.Fatalf("initial reconciliations = %+v", calls)
	}

	fake.err = errors.New("Docker unavailable")
	agent.reconcile(context.Background())
	if calls := reconciler.snapshots(); len(calls) != 2 || len(calls[1]) != 1 {
		t.Fatalf("Docker failure discarded desired state: %+v", calls)
	}
	fetchErr = errors.New("backend unavailable")
	agent.reconcile(context.Background())
	if calls := reconciler.snapshots(); len(calls) != 2 {
		t.Fatalf("backend failure reconciled workers: %+v", calls)
	}
}

func TestDockerAgentV2PlansFailureHandlingAndRecovery(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	edges := []provisioningV2Edge{
		testV2Edge(now, "edge-a", "a.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, 7),
		testV2Edge(now, "edge-b", "b.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.21", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, 7),
	}
	config := testV2Config(now, testSubscriptionID1, instance, 7, edges)
	valid := provisioningResult{V2: &config, Source: provisioningOnlineV2}
	responses := []struct {
		result provisioningResult
		err    error
	}{
		{result: valid},
		{err: &provisioningFetchError{kind: provisioningInfrastructure}},
		{err: &provisioningFetchError{kind: provisioningTerminal}},
		{result: valid},
	}
	index := 0
	reconciler := &recordingPlanReconciler{}
	agent := &dockerAgent{
		docker: &fakeDockerClient{},
		static: []mapping{
			{SubscriptionID: testSubscriptionID1, Upstream: "app:80"},
		},
		fetchProvisioning: func(context.Context) (provisioningResult, error) {
			response := responses[index]
			index++
			return response.result, response.err
		},
		supervisor: reconciler, pollInterval: time.Second,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)), now: time.Now, orderCache: make(map[string]*orderCacheEntry),
	}
	if err := agent.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := reconciler.snapshots()
	if len(calls) != 1 || len(calls[0]) != 2 {
		t.Fatalf("initial plans = %+v", calls)
	}
	for i, edge := range edges {
		plan := calls[0][i]
		if plan.SubscriptionID != testSubscriptionID1 || plan.RelayAddr != edge.Endpoint || plan.EdgeID != edge.ID || plan.Entitlement != edge.Entitlement || plan.Claim == nil || *plan.Claim != edge.Claim.protocolClaim() {
			t.Fatalf("plan %d = %+v, edge = %+v", i, plan, edge)
		}
	}
	if err := agent.reconcile(context.Background()); provisioningFailure(err) != provisioningInfrastructure {
		t.Fatalf("infrastructure reconcile error = %v", err)
	}
	if calls = reconciler.snapshots(); len(calls) != 1 {
		t.Fatalf("infrastructure failure changed workers: %+v", calls)
	}
	if err := agent.reconcile(context.Background()); provisioningFailure(err) != provisioningTerminal {
		t.Fatalf("terminal reconcile error = %v", err)
	}
	if calls = reconciler.snapshots(); len(calls) != 2 || len(calls[1]) != 0 {
		t.Fatalf("terminal failure did not clear workers: %+v", calls)
	}
	if err := agent.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls = reconciler.snapshots(); len(calls) != 3 || len(calls[2]) != 2 {
		t.Fatalf("valid recovery plans = %+v", calls)
	}
}

func TestDockerAgentKeepsChangedOrderFallbackButStillAppliesRemoval(t *testing.T) {
	var puts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		puts++
		if puts > 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"order_key":"web","subscription":{"id":"42424242-4242-4242-8242-424242424242","status":"active"},"state":"active"}`)
	}))
	defer server.Close()
	fake := &fakeDockerClient{containers: []containertypes.Summary{{ID: "web", Labels: testOrderLabels()}}}
	reconciler := &recordingPlanReconciler{}
	agent := newTestDockerAgent(fake, server, reconciler, func(context.Context) ([]provisioning, error) {
		return []provisioning{{
			SubscriptionID: testSubscriptionID42, Product: "relay", Domain: "web.example", RelayEndpoint: "edge.example:5443",
		}}, nil
	})
	agent.reconcile(context.Background())

	changed := testOrderLabels()
	changed[dockerMappingPrefix+"web.upstream"] = "new:443"
	fake.containers = []containertypes.Summary{{ID: "web", Labels: changed}}
	agent.reconcile(context.Background())
	calls := reconciler.snapshots()
	if len(calls) != 2 || len(calls[1]) != 1 || calls[1][0].Upstream != "web:443" {
		t.Fatalf("failed changed order did not retain fallback: %+v", calls)
	}

	fake.containers = nil
	agent.reconcile(context.Background())
	calls = reconciler.snapshots()
	if len(calls) != 3 || len(calls[2]) != 0 {
		t.Fatalf("successful removal was not applied: %+v", calls)
	}
}

func TestDockerAgentRetriesFailedAndAttentionOrdersWithBackoff(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	responses := []struct {
		status int
		state  string
	}{
		{status: http.StatusServiceUnavailable},
		{state: "attention_required"},
		{state: "active"},
	}
	var puts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := responses[puts]
		puts++
		if response.status != 0 {
			w.WriteHeader(response.status)
			return
		}
		_, _ = io.WriteString(w, `{"order_key":"web","subscription":{"id":"42424242-4242-4242-8242-424242424242","status":"pending"},"state":"`+response.state+`"}`)
	}))
	defer server.Close()
	fake := &fakeDockerClient{containers: []containertypes.Summary{{ID: "web", Labels: testOrderLabels()}}}
	reconciler := &recordingPlanReconciler{}
	agent := newTestDockerAgent(fake, server, reconciler, func(context.Context) ([]provisioning, error) { return nil, nil })
	agent.now = func() time.Time { return now }

	agent.reconcile(context.Background())
	agent.reconcile(context.Background())
	if puts != 1 || len(reconciler.snapshots()) != 2 {
		t.Fatalf("failed order before retry: puts=%d reconciliations=%d", puts, len(reconciler.snapshots()))
	}
	now = now.Add(orderRetryInitial)
	agent.reconcile(context.Background())
	if puts != 2 || len(reconciler.snapshots()) != 3 {
		t.Fatalf("attention order retry: puts=%d reconciliations=%d", puts, len(reconciler.snapshots()))
	}
	agent.reconcile(context.Background())
	if puts != 2 {
		t.Fatalf("attention order ignored backoff: puts=%d", puts)
	}
	now = now.Add(2 * orderRetryInitial)
	agent.reconcile(context.Background())
	if puts != 3 {
		t.Fatalf("attention order was not retried: puts=%d", puts)
	}
}

func TestDockerAgentDoesNotRequestOrRetryIPOrders(t *testing.T) {
	var puts int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		puts++
	}))
	defer server.Close()
	fake := &fakeDockerClient{containers: []containertypes.Summary{{ID: "address", Labels: map[string]string{
		dockerMappingPrefix + "address.product":  "ip",
		dockerMappingPrefix + "address.upstream": "gateway:8080",
	}}}}
	agent := newTestDockerAgent(fake, server, &recordingPlanReconciler{}, func(context.Context) ([]provisioning, error) {
		return []provisioning{{
			SubscriptionID: testSubscriptionID1,
			Product:        "relay",
			Domain:         "unused.example",
			RelayEndpoint:  "edge.example:5443",
		}}, nil
	})

	for range 2 {
		if err := agent.reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if puts != 0 || len(agent.orderCache) != 0 {
		t.Fatalf("IP order requests/cache = %d/%+v", puts, agent.orderCache)
	}
}

func TestDockerAgentRunStaysAliveWithZeroMappings(t *testing.T) {
	fake := &fakeDockerClient{}
	reconciler := &recordingPlanReconciler{}
	agent := newTestDockerAgent(fake, nil, reconciler, func(context.Context) ([]provisioning, error) { return nil, nil })
	agent.pollInterval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		agent.run(ctx)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("agent exited with zero mappings")
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("agent did not stop after cancellation")
	}
}

func TestDockerAgentRunRetriesInitialProvisioningFailure(t *testing.T) {
	fake := &fakeDockerClient{containers: []containertypes.Summary{{ID: "legacy", Labels: dockerLabels("web", testSubscriptionID42, "web:443")}}}
	reconciler := &recordingPlanReconciler{}
	var fetches int
	agent := newTestDockerAgent(fake, nil, reconciler, func(context.Context) ([]provisioning, error) {
		fetches++
		if fetches == 1 {
			return nil, errors.New("backend unavailable")
		}
		return []provisioning{{
			SubscriptionID: testSubscriptionID42, Product: "relay", Domain: "web.example", RelayEndpoint: "edge.example:5443",
		}}, nil
	})
	agent.pollInterval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		agent.run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for len(reconciler.snapshots()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	snapshots := reconciler.snapshots()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("agent did not stop after recovery")
	}
	if len(snapshots) != 1 || len(snapshots[0]) != 1 || fetches < 2 {
		t.Fatalf("recovery snapshots/fetches = %+v/%d", snapshots, fetches)
	}
}

func newTestDockerAgent(fake *fakeDockerClient, server *httptest.Server, reconciler planReconciler, fetch func(context.Context) ([]provisioning, error)) *dockerAgent {
	var orders *orderAPIClient
	if server != nil {
		orders = &orderAPIClient{client: server.Client(), backend: server.URL, token: "token"}
	}
	return &dockerAgent{
		docker: fake, orders: orders, fetchConfig: fetch, supervisor: reconciler,
		pollInterval: time.Second, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		now: time.Now, orderCache: make(map[string]*orderCacheEntry),
	}
}

func testOrderDeclaration() mapping {
	return mapping{
		OrderKey: "web", Product: "relay", Domain: "web.example", Transport: "tcp",
		BillingTerm: "monthly", Upstream: "web:443",
	}
}

func testOrderLabels() map[string]string {
	return map[string]string{
		dockerMappingPrefix + "web.product":  "relay",
		dockerMappingPrefix + "web.domain":   "web.example",
		dockerMappingPrefix + "web.upstream": "web:443",
	}
}
