package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/relayauth"
	"github.com/blindport/blindport/internal/wgnet"
)

const (
	testSubscriptionOne = "11111111-1111-4111-8111-111111111111"
	testSubscriptionTwo = "22222222-2222-4222-8222-222222222222"
)

type fakeWireGuardAccounting struct {
	operations []string
	reads      [][]wgnet.AccountingCounter
	readErrs   []error
	readIndex  int
	removeErr  error
	installErr error
	installed  [][]wgnet.PrefixBinding
}

func (f *fakeWireGuardAccounting) Install(bindings []wgnet.PrefixBinding) error {
	f.operations = append(f.operations, "install")
	f.installed = append(f.installed, append([]wgnet.PrefixBinding(nil), bindings...))
	err := f.installErr
	f.installErr = nil
	return err
}

func (f *fakeWireGuardAccounting) Remove() error {
	f.operations = append(f.operations, "remove")
	return f.removeErr
}

func (f *fakeWireGuardAccounting) Read() ([]wgnet.AccountingCounter, error) {
	f.operations = append(f.operations, "read")
	index := f.readIndex
	f.readIndex++
	if index < len(f.readErrs) && f.readErrs[index] != nil {
		return nil, f.readErrs[index]
	}
	if index < len(f.reads) {
		return f.reads[index], nil
	}
	if len(f.installed) == 0 {
		return nil, nil
	}
	bindings := f.installed[len(f.installed)-1]
	counters := make([]wgnet.AccountingCounter, len(bindings))
	for index, binding := range bindings {
		counters[index].SubscriptionID = binding.SubscriptionID
	}
	return counters, nil
}

func testBandwidthReporter() *bandwidthReporter {
	return &bandwidthReporter{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		acc: newBandwidthAccumulator(),
		now: func() time.Time { return time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC) },
	}
}

func testWireGuardAccountingManager(t *testing.T, state *relayauth.WireGuardDesiredState, account *fakeWireGuardAccounting) (*wireGuardManager, *fakeWireGuardApplier) {
	t.Helper()
	health := newRelayHealth(false, time.Minute, time.Minute)
	health.wgNeeded.Store(true)
	metrics := &relayMetrics{health: health}
	applier := &fakeWireGuardApplier{operations: &account.operations}
	coordinator := newWireGuardBandwidthAccounting(slog.New(slog.NewTextHandler(io.Discard, nil)), testBandwidthReporter(), account)
	manager := newWireGuardManager(slog.Default(), &fakePeersFetcher{state: state}, applier, time.Second, 2*time.Second, health, metrics, coordinator)
	return manager, applier
}

func testBoundState(revision string, prefixes []string, bindings []relayauth.PrefixBinding) *relayauth.WireGuardDesiredState {
	return &relayauth.WireGuardDesiredState{
		Revision: revision,
		Peers: []relayauth.WireGuardPeer{{
			PublicKey: wireGuardTestKey(), AllowedPrefixes: prefixes,
		}},
		PrefixBindings: bindings,
	}
}

func TestWireGuardAccountingUnchangedCountersAddDeltas(t *testing.T) {
	state := testBoundState("r1", []string{"198.51.100.20/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.20/32", SubscriptionID: testSubscriptionOne}})
	account := &fakeWireGuardAccounting{reads: [][]wgnet.AccountingCounter{
		{{SubscriptionID: testSubscriptionOne, IngressBytes: 12, EgressBytes: 8}},
		{{SubscriptionID: testSubscriptionOne, IngressBytes: 19, EgressBytes: 11}},
	}}
	manager, _ := testWireGuardAccountingManager(t, state, account)
	manager.cycle(context.Background())
	account.operations = nil
	manager.cycle(context.Background())

	if !reflect.DeepEqual(account.operations, []string{"read", "apply"}) {
		t.Fatalf("operations = %v", account.operations)
	}
	manager.cycle(context.Background())
	reports := manager.accounting.reporter.acc.snapshot()
	if !reflect.DeepEqual(reports, []relayauth.DailyBandwidthReport{{SubscriptionID: testSubscriptionOne, Day: "2026-08-09", IngressBytes: 19, EgressBytes: 11}}) {
		t.Fatalf("reports = %+v", reports)
	}
}

func TestWireGuardAccountingCounterRollbackResetsBaseline(t *testing.T) {
	state := testBoundState("r1", []string{"198.51.100.20/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.20/32", SubscriptionID: testSubscriptionOne}})
	account := &fakeWireGuardAccounting{reads: [][]wgnet.AccountingCounter{
		{{SubscriptionID: testSubscriptionOne, IngressBytes: 12}},
		{{SubscriptionID: testSubscriptionOne, IngressBytes: 5}},
		{{SubscriptionID: testSubscriptionOne, IngressBytes: 8}},
	}}
	manager, _ := testWireGuardAccountingManager(t, state, account)
	manager.cycle(context.Background())
	manager.cycle(context.Background())
	manager.cycle(context.Background())
	manager.cycle(context.Background())

	reports := manager.accounting.reporter.acc.snapshot()
	want := []relayauth.DailyBandwidthReport{{SubscriptionID: testSubscriptionOne, Day: "2026-08-09", IngressBytes: 15}}
	if !reflect.DeepEqual(reports, want) {
		t.Fatalf("reports = %+v", reports)
	}
}

func TestWireGuardAccountingIncompleteReadPreservesBaseline(t *testing.T) {
	state := testBoundState("r1", []string{"198.51.100.20/32", "198.51.100.21/32"}, []relayauth.PrefixBinding{
		{Prefix: "198.51.100.20/32", SubscriptionID: testSubscriptionOne},
		{Prefix: "198.51.100.21/32", SubscriptionID: testSubscriptionTwo},
	})
	account := &fakeWireGuardAccounting{reads: [][]wgnet.AccountingCounter{
		{
			{SubscriptionID: testSubscriptionOne, IngressBytes: 10},
			{SubscriptionID: testSubscriptionTwo, EgressBytes: 20},
		},
		{{SubscriptionID: testSubscriptionOne, IngressBytes: 12}},
		{
			{SubscriptionID: testSubscriptionOne, IngressBytes: 15},
			{SubscriptionID: testSubscriptionTwo, EgressBytes: 25},
		},
	}}
	manager, _ := testWireGuardAccountingManager(t, state, account)
	manager.cycle(context.Background())
	manager.cycle(context.Background())
	manager.cycle(context.Background())
	manager.cycle(context.Background())

	want := []relayauth.DailyBandwidthReport{
		{SubscriptionID: testSubscriptionOne, Day: "2026-08-09", IngressBytes: 15},
		{SubscriptionID: testSubscriptionTwo, Day: "2026-08-09", EgressBytes: 25},
	}
	if got := manager.accounting.reporter.acc.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("reports = %+v", got)
	}
}

func TestWireGuardAccountingSamePeerPrefixesRemainIndependent(t *testing.T) {
	state := testBoundState("r1", []string{"198.51.100.20/32", "198.51.100.21/32"}, []relayauth.PrefixBinding{
		{Prefix: "198.51.100.20/32", SubscriptionID: testSubscriptionOne},
		{Prefix: "198.51.100.21/32", SubscriptionID: testSubscriptionTwo},
	})
	account := &fakeWireGuardAccounting{reads: [][]wgnet.AccountingCounter{{
		{SubscriptionID: testSubscriptionOne, IngressBytes: 7},
		{SubscriptionID: testSubscriptionTwo, EgressBytes: 9},
	}}}
	manager, _ := testWireGuardAccountingManager(t, state, account)
	manager.cycle(context.Background())
	manager.cycle(context.Background())

	reports := manager.accounting.reporter.acc.snapshot()
	want := []relayauth.DailyBandwidthReport{
		{SubscriptionID: testSubscriptionOne, Day: "2026-08-09", IngressBytes: 7},
		{SubscriptionID: testSubscriptionTwo, Day: "2026-08-09", EgressBytes: 9},
	}
	if !reflect.DeepEqual(reports, want) {
		t.Fatalf("reports = %+v", reports)
	}
}

func TestWireGuardAccountingChangeDrainsBeforeAuthorization(t *testing.T) {
	initial := testBoundState("r1", []string{"198.51.100.20/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.20/32", SubscriptionID: testSubscriptionOne}})
	account := &fakeWireGuardAccounting{reads: [][]wgnet.AccountingCounter{{{SubscriptionID: testSubscriptionOne, IngressBytes: 1}}}}
	manager, applier := testWireGuardAccountingManager(t, initial, account)
	manager.cycle(context.Background())
	account.operations = nil
	manager.fetcher = &fakePeersFetcher{state: testBoundState("r2", []string{"198.51.100.21/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.21/32", SubscriptionID: testSubscriptionTwo}})}
	manager.cycle(context.Background())

	if !reflect.DeepEqual(account.operations, []string{"read", "remove", "apply", "install"}) || len(applier.applied) != 2 {
		t.Fatalf("operations/applies = %v/%d", account.operations, len(applier.applied))
	}
}

func TestWireGuardAccountingReadFailurePreservesPreviousPolicy(t *testing.T) {
	initial := testBoundState("r1", []string{"198.51.100.20/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.20/32", SubscriptionID: testSubscriptionOne}})
	account := &fakeWireGuardAccounting{readErrs: []error{errors.New("nft failure")}}
	manager, applier := testWireGuardAccountingManager(t, initial, account)
	manager.cycle(context.Background())
	account.operations = nil
	account.readIndex = 0
	manager.fetcher = &fakePeersFetcher{state: testBoundState("r2", []string{"198.51.100.21/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.21/32", SubscriptionID: testSubscriptionTwo}})}
	manager.cycle(context.Background())

	if !reflect.DeepEqual(account.operations, []string{"read"}) || len(applier.applied) != 1 || !manager.accounting.present {
		t.Fatalf("operations/applies = %v/%d", account.operations, len(applier.applied))
	}
}

func TestWireGuardAccountingRemoveFailurePreventsApply(t *testing.T) {
	initial := testBoundState("r1", []string{"198.51.100.20/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.20/32", SubscriptionID: testSubscriptionOne}})
	account := &fakeWireGuardAccounting{removeErr: errors.New("nft failure")}
	manager, applier := testWireGuardAccountingManager(t, initial, account)
	manager.cycle(context.Background())
	account.operations = nil
	manager.fetcher = &fakePeersFetcher{state: testBoundState("r2", []string{"198.51.100.21/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.21/32", SubscriptionID: testSubscriptionTwo}})}
	manager.cycle(context.Background())

	if !reflect.DeepEqual(account.operations, []string{"read", "remove"}) || len(applier.applied) != 1 {
		t.Fatalf("operations/applies = %v/%d", account.operations, len(applier.applied))
	}
}

func TestWireGuardAccountingInstallFailureRetainsAuthorizationAndRetries(t *testing.T) {
	state := testBoundState("r1", []string{"198.51.100.20/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.20/32", SubscriptionID: testSubscriptionOne}})
	account := &fakeWireGuardAccounting{installErr: errors.New("nft failure")}
	manager, applier := testWireGuardAccountingManager(t, state, account)
	manager.cycle(context.Background())
	if applier.failClosed != 1 || !manager.failedClosed || manager.accounting.present {
		t.Fatalf("initial fail-close/present = %d/%t/%t", applier.failClosed, manager.failedClosed, manager.accounting.present)
	}
	account.operations = nil
	manager.cycle(context.Background())

	if !reflect.DeepEqual(account.operations, []string{"apply", "install"}) || len(applier.applied) != 2 || !manager.accounting.present || manager.failedClosed {
		t.Fatalf("operations/applies/present/failedClosed = %v/%d/%t/%t", account.operations, len(applier.applied), manager.accounting.present, manager.failedClosed)
	}
}

func TestWireGuardAccountingMissingTableReinstallsWithoutAuthorizationChurn(t *testing.T) {
	state := testBoundState("r1", []string{"198.51.100.20/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.20/32", SubscriptionID: testSubscriptionOne}})
	account := &fakeWireGuardAccounting{readErrs: []error{wgnet.ErrAccountingTableMissing}}
	manager, applier := testWireGuardAccountingManager(t, state, account)
	manager.cycle(context.Background())
	account.operations = nil
	manager.cycle(context.Background())

	if !reflect.DeepEqual(account.operations, []string{"read", "install"}) || len(applier.applied) != 1 || !manager.accounting.present {
		t.Fatalf("operations/applies/present = %v/%d/%t", account.operations, len(applier.applied), manager.accounting.present)
	}
}

func TestWireGuardAccountingApplyFailureAfterDrainFailsClosed(t *testing.T) {
	initial := testBoundState("r1", []string{"198.51.100.20/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.20/32", SubscriptionID: testSubscriptionOne}})
	account := &fakeWireGuardAccounting{}
	manager, applier := testWireGuardAccountingManager(t, initial, account)
	manager.cycle(context.Background())
	account.operations = nil
	applier.applyErr = errors.New("apply failed")
	manager.fetcher = &fakePeersFetcher{state: testBoundState("r2", []string{"198.51.100.21/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.21/32", SubscriptionID: testSubscriptionTwo}})}
	manager.cycle(context.Background())

	if !reflect.DeepEqual(account.operations, []string{"read", "remove", "apply", "fail-closed"}) || applier.failClosed != 1 || !manager.failedClosed {
		t.Fatalf("operations/failClosed/state = %v/%d/%t", account.operations, applier.failClosed, manager.failedClosed)
	}
}

func TestWireGuardAccountingRejectsInvalidBindings(t *testing.T) {
	valid := []relayauth.PrefixBinding{{Prefix: "198.51.100.20/32", SubscriptionID: testSubscriptionOne}}
	cases := []*relayauth.WireGuardDesiredState{
		testBoundState("r1", []string{"198.51.100.20/32"}, nil),
		testBoundState("r1", []string{"198.51.100.20/32", "198.51.100.21/32"}, valid),
		testBoundState("r1", []string{"198.51.100.20/32"}, append(valid, relayauth.PrefixBinding{Prefix: "198.51.100.21/32", SubscriptionID: testSubscriptionTwo})),
		testBoundState("r1", []string{"198.51.100.20/32"}, append(valid, valid[0])),
		testBoundState("r1", []string{"198.51.100.20/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.20/24", SubscriptionID: testSubscriptionOne}}),
		testBoundState("r1", []string{"198.51.100.20/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.20/32", SubscriptionID: "11111111-1111-4111-8111-11111111111A"}}),
	}
	for index, state := range cases {
		if _, err := bandwidthBindings(state); err == nil {
			t.Fatalf("case %d accepted invalid bindings", index)
		}
	}
}

func TestWireGuardAccountingPollsOnFetchFailure(t *testing.T) {
	state := testBoundState("r1", []string{"198.51.100.20/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.20/32", SubscriptionID: testSubscriptionOne}})
	account := &fakeWireGuardAccounting{reads: [][]wgnet.AccountingCounter{{{SubscriptionID: testSubscriptionOne, IngressBytes: 4}}}}
	manager, _ := testWireGuardAccountingManager(t, state, account)
	manager.cycle(context.Background())
	account.operations = nil
	manager.fetcher = &fakePeersFetcher{err: errors.New("backend unavailable")}
	manager.cycle(context.Background())

	if !reflect.DeepEqual(account.operations, []string{"read"}) {
		t.Fatalf("operations = %v", account.operations)
	}
}

func TestWireGuardAccountingShutdownCollectsRemovesThenFailsClosed(t *testing.T) {
	state := testBoundState("r1", []string{"198.51.100.20/32"}, []relayauth.PrefixBinding{{Prefix: "198.51.100.20/32", SubscriptionID: testSubscriptionOne}})
	account := &fakeWireGuardAccounting{reads: [][]wgnet.AccountingCounter{{{SubscriptionID: testSubscriptionOne, IngressBytes: 4}}}}
	manager, applier := testWireGuardAccountingManager(t, state, account)
	manager.cycle(context.Background())
	account.operations = nil
	manager.failClosed("shutdown")

	if !reflect.DeepEqual(account.operations, []string{"read", "remove", "fail-closed"}) || applier.failClosed != 1 {
		t.Fatalf("operations/failClosed = %v/%d", account.operations, applier.failClosed)
	}
}
