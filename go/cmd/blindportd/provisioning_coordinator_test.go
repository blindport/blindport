package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/protocol"
)

func TestLegacyProvisioningCoordinatorSelectsV1AndBuildsExactV2Edges(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	v1 := []provisioning{{RelayEndpoint: "edge.example:5443", Product: "relay", Domain: "site.example", Transport: "tcp", SubscriptionID: testSubscriptionID1}}
	v2 := testV2Config(now, testSubscriptionID1, instance, 7, []provisioningV2Edge{testV2Edge(now, "edge-a", "edge.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, 7)})
	// Use a Port response after selection to prove the selected subscription, not
	// response metadata, controls later legacy reconciliation.
	v1[0] = provisioning{RelayEndpoint: "edge.example:5443", Product: "port", AssignedIP: "203.0.113.20", AssignedPort: 10000, Transport: "tcp", SubscriptionID: testSubscriptionID1}
	coordinator := newLegacyProvisioningCoordinator(legacySelection{}, "", "", "")
	if _, err := coordinator.plans(provisioningResult{V1: v1, Source: provisioningOnlineV1}); err != nil {
		t.Fatal(err)
	}
	plans, err := coordinator.plans(provisioningResult{V2: &v2, Source: provisioningOnlineV2})
	if err != nil || len(plans) != 1 || plans[0].EdgeID != "edge-a" || plans[0].Entitlement != v2.Subscriptions[0].Edges[0].Entitlement {
		t.Fatalf("v2 plans = %+v, %v", plans, err)
	}
	if coordinator.legacy.subscriptionID != testSubscriptionID1 || plans[0].Upstream != "127.0.0.1:80" {
		t.Fatalf("legacy selection = %+v, plan = %+v", coordinator.legacy, plans[0])
	}
}

func TestLegacyProvisioningCoordinatorSelectsV2AndFreezesSubscription(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instance := "11111111-2222-4333-8444-555555555555"
	edge := testV2Edge(now, "edge-a", "edge.example:5443", provisioningV2Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, testSubscriptionID1, instance, 7)
	config := testV2Config(now, testSubscriptionID1, instance, 7, []provisioningV2Edge{edge})
	coordinator := newLegacyProvisioningCoordinator(legacySelection{}, "", "", "")
	plans, err := coordinator.plans(provisioningResult{V2: &config, Source: provisioningOnlineV2})
	if err != nil || len(plans) != 1 || coordinator.legacy.subscriptionID != testSubscriptionID1 {
		t.Fatalf("initial v2 plans = %+v, selection = %+v, err = %v", plans, coordinator.legacy, err)
	}
	removed := provisioningV2{Version: 2, Subscriptions: []provisioningSubscription{}}
	if _, err := coordinator.plans(provisioningResult{V2: &removed, Source: provisioningOnlineV2}); err == nil {
		t.Fatal("frozen legacy subscription was silently replaced after removal")
	}
}

type planRecorder struct {
	mu    sync.Mutex
	calls [][]workerPlan
	ch    chan struct{}
}

func (r *planRecorder) Reconcile(plans []workerPlan) error {
	r.mu.Lock()
	r.calls = append(r.calls, append([]workerPlan(nil), plans...))
	r.mu.Unlock()
	select {
	case r.ch <- struct{}{}:
	default:
	}
	return nil
}

func (r *planRecorder) snapshot() [][]workerPlan {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([][]workerPlan, len(r.calls))
	for i := range r.calls {
		result[i] = append([]workerPlan(nil), r.calls[i]...)
	}
	return result
}

func TestProvisioningReconcilerRetainsInfrastructureThenFailsClosedAndRecovers(t *testing.T) {
	valid := provisioningResult{V1: []provisioning{{RelayEndpoint: "edge.example:5443", Product: "relay", Domain: "site.example", Transport: "tcp", SubscriptionID: testSubscriptionID1}}, Source: provisioningOnlineV1}
	responses := []struct {
		result provisioningResult
		err    error
	}{
		{result: valid},
		{err: &provisioningFetchError{kind: provisioningInfrastructure}},
		{err: &provisioningFetchError{kind: provisioningTerminal}},
		{result: valid},
	}
	var mu sync.Mutex
	index := 0
	fetch := func(context.Context) (provisioningResult, error) {
		mu.Lock()
		defer mu.Unlock()
		response := responses[index]
		if index < len(responses)-1 {
			index++
		}
		return response.result, response.err
	}
	recorder := &planRecorder{ch: make(chan struct{}, 8)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runProvisioningReconciler(ctx, fetch, newMappingProvisioningCoordinator([]mapping{{SubscriptionID: testSubscriptionID1, Upstream: "app:80"}}, "", false), recorder, 5*time.Millisecond, func(string, error) {})
	}()
	for range 3 { // initial valid, terminal empty, later valid
		select {
		case <-recorder.ch:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for reconcile")
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	calls := recorder.snapshot()
	if len(calls) != 3 || len(calls[0]) != 1 || len(calls[1]) != 0 || len(calls[2]) != 1 {
		t.Fatalf("reconciliations = %+v", calls)
	}
}

func TestProvisioningFailureClassificationIsSanitized(t *testing.T) {
	err := &provisioningFetchError{kind: provisioningTerminal, status: 429}
	if provisioningFailure(err) != provisioningTerminal || errors.Is(err, context.Canceled) {
		t.Fatalf("classification = %v", provisioningFailure(err))
	}
}
