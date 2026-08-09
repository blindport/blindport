package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/relayauth"
)

const bandwidthTestToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func bandwidthTestUUID(index int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012x", index)
}

func TestBandwidthAccumulatorBucketsUTCAndRejectsUnsafeGrowth(t *testing.T) {
	accumulator := newBandwidthAccumulator()
	first := time.Date(2026, 8, 10, 23, 59, 0, 0, time.UTC)
	if err := accumulator.add(bandwidthTestUUID(1), bandwidthIngress, 7, first); err != nil {
		t.Fatal(err)
	}
	if err := accumulator.add(bandwidthTestUUID(1), bandwidthEgress, 5, first.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	want := []relayauth.DailyBandwidthReport{
		{SubscriptionID: bandwidthTestUUID(1), Day: "2026-08-10", IngressBytes: 7},
		{SubscriptionID: bandwidthTestUUID(1), Day: "2026-08-11", EgressBytes: 5},
	}
	if got := accumulator.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot = %+v, want %+v", got, want)
	}
	if err := accumulator.add("not-a-uuid", bandwidthIngress, 1, first); err == nil {
		t.Fatal("invalid subscription ID was accepted")
	}
	key := bandwidthKey{subscriptionID: bandwidthTestUUID(2), day: "2026-08-10"}
	accumulator.entries[key] = bandwidthTotals{ingress: math.MaxInt64}
	if err := accumulator.add(key.subscriptionID, bandwidthIngress, 1, first); err == nil {
		t.Fatal("counter overflow was accepted")
	}
	accumulator.entries = make(map[bandwidthKey]bandwidthTotals, maxBandwidthEntries)
	for index := 0; index < maxBandwidthEntries; index++ {
		accumulator.entries[bandwidthKey{subscriptionID: bandwidthTestUUID(index), day: "2026-08-10"}] = bandwidthTotals{}
	}
	if err := accumulator.add(bandwidthTestUUID(maxBandwidthEntries+1), bandwidthIngress, 1, first); err == nil {
		t.Fatal("entry cardinality overflow was accepted")
	}
}

func TestBandwidthAccumulatorBatchIsAtomic(t *testing.T) {
	accumulator := newBandwidthAccumulator()
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	overflowKey := bandwidthKey{subscriptionID: bandwidthTestUUID(1), day: "2026-08-10"}
	accumulator.entries[overflowKey] = bandwidthTotals{ingress: math.MaxInt64}
	err := accumulator.addBatch([]bandwidthIncrement{
		{subscriptionID: bandwidthTestUUID(2), direction: bandwidthIngress, count: 3},
		{subscriptionID: bandwidthTestUUID(1), direction: bandwidthIngress, count: 1},
	}, now)
	if err == nil {
		t.Fatal("overflowing batch was accepted")
	}
	if len(accumulator.entries) != 1 || accumulator.entries[overflowKey].ingress != math.MaxInt64 {
		t.Fatalf("failed batch changed accumulator: %+v", accumulator.entries)
	}
}

func TestBandwidthLedgerRoundTripIsCompactStrictAndOwnerOnly(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "bandwidth.json")
	ledger := bandwidthLedger{
		Version:  bandwidthLedgerVersion,
		BootID:   bandwidthTestUUID(1),
		Sequence: 9,
		Reports: []bandwidthLedgerReport{
			{SubscriptionID: bandwidthTestUUID(2), Day: "2026-08-10", IngressBytes: 3, EgressBytes: 4},
		},
	}
	if err := storeBandwidthLedger(path, ledger); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("ledger mode = %o, want 600", info.Mode().Perm())
	}
	loaded, err := loadBandwidthLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, ledger) {
		t.Fatalf("loaded ledger = %+v, want %+v", loaded, ledger)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"subscription_id", "ingress_bytes", "egress_bytes", "source", "destination", "domain", "port", "flow", "timestamp"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("ledger contains forbidden field %q: %s", forbidden, raw)
		}
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBandwidthLedger(path); err == nil {
		t.Fatal("unsafe ledger permissions were accepted")
	}
}

func TestBandwidthLedgerRejectsCorruptionAndStaysWithinLimit(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "bandwidth.json")
	for _, raw := range []string{
		`{"v":1,"b":"00000000-0000-4000-8000-000000000001","q":0,"r":[],"extra":true}`,
		`{"v":1,"b":"bad","q":0,"r":[]}`,
		`{"v":1,"b":"00000000-0000-4000-8000-000000000001","q":0,"r":[{"s":"00000000-0000-4000-8000-000000000002","d":"2026-8-1","i":0,"e":0}]}`,
	} {
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadBandwidthLedger(path); err == nil {
			t.Fatalf("corrupt ledger was accepted: %s", raw)
		}
	}
	reports := make([]bandwidthLedgerReport, maxBandwidthEntries)
	for index := range reports {
		reports[index] = bandwidthLedgerReport{SubscriptionID: bandwidthTestUUID(index), Day: "2026-08-10", IngressBytes: math.MaxInt64, EgressBytes: math.MaxInt64}
	}
	ledger := bandwidthLedger{Version: bandwidthLedgerVersion, BootID: bandwidthTestUUID(maxBandwidthEntries + 1), Reports: reports}
	if err := storeBandwidthLedger(path, ledger); err != nil {
		t.Fatalf("maximum bounded ledger cannot be persisted: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > maxBandwidthLedgerSize {
		t.Fatalf("ledger size = %d, max %d", info.Size(), maxBandwidthLedgerSize)
	}
}

func TestBandwidthReporterRetriesChunksAndPrunesOnlyAfterAllAcknowledge(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "bandwidth.json")
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	var sequences []int64
	failSecond := true
	send := func(_ context.Context, _ string, batch relayauth.DailyBandwidthBatch) error {
		sequences = append(sequences, batch.Sequence)
		if failSecond && len(sequences) == 2 {
			return errors.New("backend unavailable")
		}
		return nil
	}
	reporter, err := newBandwidthReporterWithClock(
		slog.New(slog.NewTextHandler(io.Discard, nil)), path, "relay-1", bandwidthTestToken,
		time.Minute, send, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 1001; index++ {
		reporter.acc.entries[bandwidthKey{subscriptionID: bandwidthTestUUID(index), day: "2026-08-09"}] = bandwidthTotals{ingress: 1}
	}
	reporter.acc.entries[bandwidthKey{subscriptionID: bandwidthTestUUID(2000), day: "2026-08-10"}] = bandwidthTotals{egress: 2}
	if err := reporter.flush(context.Background()); err == nil {
		t.Fatal("partial chunk failure was ignored")
	}
	if len(reporter.acc.snapshot()) != 1002 {
		t.Fatal("reports were pruned before every chunk was acknowledged")
	}
	persisted, err := loadBandwidthLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Sequence != 2 || len(persisted.Reports) != 1002 {
		t.Fatalf("failed-flush ledger = sequence %d, reports %d", persisted.Sequence, len(persisted.Reports))
	}
	failSecond = false
	if err := reporter.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sequences, []int64{1, 2, 3, 4}) {
		t.Fatalf("sequences = %v", sequences)
	}
	remaining := reporter.acc.snapshot()
	if !reflect.DeepEqual(remaining, []relayauth.DailyBandwidthReport{{SubscriptionID: bandwidthTestUUID(2000), Day: "2026-08-10", EgressBytes: 2}}) {
		t.Fatalf("remaining reports = %+v", remaining)
	}
	persisted, err = loadBandwidthLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Sequence != 4 || len(persisted.Reports) != 1 {
		t.Fatalf("successful ledger = sequence %d, reports %d", persisted.Sequence, len(persisted.Reports))
	}
}
