package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/protocol"
)

func TestAutomaticTLSWorkerFailsClosedWithoutManager(t *testing.T) {
	done := make(chan struct{})
	go func() {
		runWorker(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), workerPlan{
			SubscriptionID: testSubscriptionID1, RelayAddr: "127.0.0.1:1", TLSMode: tlsModeAutomatic,
		}, "token", &net.Dialer{}, nil, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("automatic TLS worker attempted passthrough without a manager")
	}
}

type workerEvent struct {
	kind string
	plan workerPlan
}

func TestTLSConfigDerivesIndependentServerNames(t *testing.T) {
	material := &tlsMaterial{}
	first, err := material.configForEndpoint("edge-a.example:5443", "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := material.configForEndpoint("203.0.113.10:5443", "")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("configForEndpoint returned shared tls.Config")
	}
	if first.ServerName != "edge-a.example" || second.ServerName != "203.0.113.10" {
		t.Fatalf("ServerNames = %q, %q", first.ServerName, second.ServerName)
	}
	first.ServerName = "mutated.example"
	if second.ServerName != "203.0.113.10" {
		t.Fatal("TLS configs share mutable ServerName state")
	}
}

func TestTLSConfigUsesExplicitServerNameOverride(t *testing.T) {
	config, err := (&tlsMaterial{}).configForEndpoint("edge-a.example:5443", "relay-tls.example")
	if err != nil {
		t.Fatal(err)
	}
	if config.ServerName != "relay-tls.example" {
		t.Fatalf("ServerName = %q", config.ServerName)
	}
}

func TestWorkerSupervisorAddUpdateRemoveAndShutdown(t *testing.T) {
	events := make(chan workerEvent, 20)
	supervisor := newWorkerSupervisor(context.Background(), func(ctx context.Context, plan workerPlan) {
		events <- workerEvent{kind: "start", plan: plan}
		<-ctx.Done()
		events <- workerEvent{kind: "stop", plan: plan}
	})
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "web.example"}
	first := workerPlan{SubscriptionID: testSubscriptionID1, RelayAddr: "edge-a:5443", Upstream: "old:443", Claim: claim}
	second := workerPlan{SubscriptionID: testSubscriptionID1, RelayAddr: "edge-b:5443", Upstream: "old:443", Claim: claim}
	if err := supervisor.Reconcile([]workerPlan{first, second}); err != nil {
		t.Fatal(err)
	}
	assertWorkerEvents(t, events, map[string]int{"start:edge-a:5443:old:443": 1, "start:edge-b:5443:old:443": 1})
	if err := supervisor.Reconcile([]workerPlan{first, second}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-events:
		t.Fatalf("identical reconcile emitted event %+v", got)
	case <-time.After(20 * time.Millisecond):
	}

	updated := first
	updated.Upstream = "new:443"
	if err := supervisor.Reconcile([]workerPlan{updated}); err != nil {
		t.Fatal(err)
	}
	assertWorkerEvents(t, events, map[string]int{
		"stop:edge-a:5443:old:443":  1,
		"stop:edge-b:5443:old:443":  1,
		"start:edge-a:5443:new:443": 1,
	})
	if err := supervisor.Reconcile(nil); err != nil {
		t.Fatal(err)
	}
	assertWorkerEvents(t, events, map[string]int{"stop:edge-a:5443:new:443": 1})
	supervisor.Shutdown()
}

func TestWorkerSupervisorConcurrentReconcileIsRaceSafe(t *testing.T) {
	supervisor := newWorkerSupervisor(context.Background(), func(ctx context.Context, _ workerPlan) { <-ctx.Done() })
	var callers sync.WaitGroup
	for i := 0; i < 20; i++ {
		callers.Add(1)
		go func(i int) {
			defer callers.Done()
			ids := [...]string{testSubscriptionID1, testSubscriptionID2, testSubscriptionID3}
			plan := workerPlan{SubscriptionID: ids[i%len(ids)], RelayAddr: "edge:5443", Upstream: "app:80"}
			if err := supervisor.Reconcile([]workerPlan{plan}); err != nil {
				t.Errorf("Reconcile() = %v", err)
			}
		}(i)
	}
	callers.Wait()
	supervisor.Shutdown()
}

func TestWorkerSupervisorRestartsWorkerThatReturns(t *testing.T) {
	started := make(chan struct{}, 2)
	supervisor := newWorkerSupervisor(context.Background(), func(context.Context, workerPlan) {
		started <- struct{}{}
	})
	plan := workerPlan{SubscriptionID: testSubscriptionID1, RelayAddr: "edge:5443", Upstream: "app:80"}
	if err := supervisor.Reconcile([]workerPlan{plan}); err != nil {
		t.Fatal(err)
	}
	assertWorkerStarts(t, started, 1)

	deadline := time.Now().Add(time.Second)
	for {
		supervisor.mu.Lock()
		workers := len(supervisor.workers)
		supervisor.mu.Unlock()
		if workers == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("returned worker remained registered")
		}
		time.Sleep(time.Millisecond)
	}
	if err := supervisor.Reconcile([]workerPlan{plan}); err != nil {
		t.Fatal(err)
	}
	assertWorkerStarts(t, started, 1)
	supervisor.Shutdown()
}

func assertWorkerStarts(t *testing.T, started <-chan struct{}, count int) {
	t.Helper()
	for range count {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for worker start")
		}
	}
}

func assertWorkerEvents(t *testing.T, events <-chan workerEvent, want map[string]int) {
	t.Helper()
	for len(want) > 0 {
		select {
		case event := <-events:
			key := event.kind + ":" + event.plan.RelayAddr + ":" + event.plan.Upstream
			if want[key] == 0 {
				t.Fatalf("unexpected worker event %q", key)
			}
			if want[key] == 1 {
				delete(want, key)
			} else {
				want[key]--
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for worker events: %v", want)
		}
	}
}
