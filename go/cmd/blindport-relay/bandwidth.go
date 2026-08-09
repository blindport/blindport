package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/blindport/blindport/internal/relayauth"
)

const (
	bandwidthLedgerVersion = 1
	// The compact worst-case JSON entry is below 112 bytes, so this remains
	// safely inside the 1 MiB ledger cap while remaining below the 10k limit.
	maxBandwidthEntries    = 8500
	maxBandwidthLedgerSize = 1 << 20
)

type bandwidthDirection uint8

const (
	bandwidthIngress bandwidthDirection = iota
	bandwidthEgress
)

type bandwidthKey struct {
	subscriptionID string
	day            string
}

type bandwidthTotals struct {
	ingress int64
	egress  int64
}

type bandwidthIncrement struct {
	subscriptionID string
	direction      bandwidthDirection
	count          int
}

// bandwidthAccumulator intentionally contains only subscription/day totals.
type bandwidthAccumulator struct {
	mu      sync.Mutex
	entries map[bandwidthKey]bandwidthTotals
}

func newBandwidthAccumulator() *bandwidthAccumulator {
	return &bandwidthAccumulator{entries: make(map[bandwidthKey]bandwidthTotals)}
}

func (a *bandwidthAccumulator) add(subscriptionID string, direction bandwidthDirection, count int, now time.Time) error {
	return a.addBatch([]bandwidthIncrement{{subscriptionID: subscriptionID, direction: direction, count: count}}, now)
}

func (a *bandwidthAccumulator) addBatch(increments []bandwidthIncrement, now time.Time) error {
	day := now.UTC().Format("2006-01-02")
	a.mu.Lock()
	defer a.mu.Unlock()
	pending := make(map[bandwidthKey]bandwidthTotals, len(increments))
	newEntries := 0
	for _, increment := range increments {
		if !canonicalSubscriptionID(increment.subscriptionID) || increment.count < 0 ||
			(increment.direction != bandwidthIngress && increment.direction != bandwidthEgress) {
			return errors.New("invalid bandwidth accounting value")
		}
		if increment.count == 0 {
			continue
		}
		key := bandwidthKey{subscriptionID: increment.subscriptionID, day: day}
		totals, pendingEntry := pending[key]
		if !pendingEntry {
			var exists bool
			totals, exists = a.entries[key]
			if !exists {
				newEntries++
				if len(a.entries)+newEntries > maxBandwidthEntries {
					return errors.New("bandwidth accounting entry limit reached")
				}
			}
		}
		value := int64(increment.count)
		if (increment.direction == bandwidthIngress && totals.ingress > math.MaxInt64-value) ||
			(increment.direction == bandwidthEgress && totals.egress > math.MaxInt64-value) {
			return errors.New("bandwidth accounting total overflow")
		}
		if increment.direction == bandwidthIngress {
			totals.ingress += value
		} else {
			totals.egress += value
		}
		pending[key] = totals
	}
	for key, totals := range pending {
		a.entries[key] = totals
	}
	return nil
}

func (a *bandwidthAccumulator) snapshot() []relayauth.DailyBandwidthReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	reports := make([]relayauth.DailyBandwidthReport, 0, len(a.entries))
	for key, totals := range a.entries {
		reports = append(reports, relayauth.DailyBandwidthReport{
			SubscriptionID: key.subscriptionID, Day: key.day, IngressBytes: totals.ingress, EgressBytes: totals.egress,
		})
	}
	sort.Slice(reports, func(i, j int) bool {
		if reports[i].Day == reports[j].Day {
			return reports[i].SubscriptionID < reports[j].SubscriptionID
		}
		return reports[i].Day < reports[j].Day
	})
	return reports
}

func (a *bandwidthAccumulator) pruneBefore(day string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for key := range a.entries {
		if key.day < day {
			delete(a.entries, key)
		}
	}
}

type bandwidthLedgerReport struct {
	SubscriptionID string `json:"s"`
	Day            string `json:"d"`
	IngressBytes   int64  `json:"i"`
	EgressBytes    int64  `json:"e"`
}

type bandwidthLedger struct {
	Version  int                     `json:"v"`
	BootID   string                  `json:"b"`
	Sequence int64                   `json:"q"`
	Reports  []bandwidthLedgerReport `json:"r"`
}

// bandwidthReporter owns persistence and reports cumulative counter snapshots.
type bandwidthReporter struct {
	log      *slog.Logger
	path     string
	edgeID   string
	token    string
	interval time.Duration
	acc      *bandwidthAccumulator
	bootID   string
	sequence int64
	send     func(context.Context, string, relayauth.DailyBandwidthBatch) error
	now      func() time.Time
	mu       sync.Mutex
}

func newBandwidthReporter(log *slog.Logger, path, edgeID, token string, interval time.Duration, send func(context.Context, string, relayauth.DailyBandwidthBatch) error) (*bandwidthReporter, error) {
	return newBandwidthReporterWithClock(log, path, edgeID, token, interval, send, time.Now)
}

func newBandwidthReporterWithClock(log *slog.Logger, path, edgeID, token string, interval time.Duration, send func(context.Context, string, relayauth.DailyBandwidthBatch) error, now func() time.Time) (*bandwidthReporter, error) {
	if log == nil || send == nil || now == nil || path == "" || interval < 5*time.Second || interval > 5*time.Minute {
		return nil, errors.New("invalid bandwidth reporter configuration")
	}
	if _, err := validateOfflineEdgeID(edgeID); err != nil || !relayauthToken(token) {
		return nil, errors.New("invalid bandwidth reporter identity")
	}
	ledger, err := loadBandwidthLedger(path)
	if err != nil {
		return nil, err
	}
	acc := newBandwidthAccumulator()
	for _, report := range ledger.Reports {
		acc.entries[bandwidthKey{subscriptionID: report.SubscriptionID, day: report.Day}] = bandwidthTotals{ingress: report.IngressBytes, egress: report.EgressBytes}
	}
	return &bandwidthReporter{log: log, path: path, edgeID: edgeID, token: token, interval: interval, acc: acc, bootID: ledger.BootID, sequence: ledger.Sequence, send: send, now: now}, nil
}

func (r *bandwidthReporter) add(subscriptionID string, direction bandwidthDirection, count int) {
	if err := r.addChecked(subscriptionID, direction, count); err != nil {
		r.log.Warn("bandwidth accounting degraded")
	}
}

func (r *bandwidthReporter) addChecked(subscriptionID string, direction bandwidthDirection, count int) error {
	return r.acc.add(subscriptionID, direction, count, r.now())
}

func (r *bandwidthReporter) addBatchChecked(increments []bandwidthIncrement) error {
	return r.acc.addBatch(increments, r.now())
}

func (r *bandwidthReporter) run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.flush(ctx); err != nil {
				r.log.Warn("bandwidth report failed")
			}
		}
	}
}

func (r *bandwidthReporter) flush(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	reports := r.acc.snapshot()
	if len(reports) == 0 {
		return r.persistLocked()
	}
	if err := r.persistLocked(); err != nil {
		return err
	}
	for start := 0; start < len(reports); start += 1000 {
		end := start + 1000
		if end > len(reports) {
			end = len(reports)
		}
		if r.sequence == math.MaxInt64 {
			return errors.New("bandwidth sequence overflow")
		}
		r.sequence++
		if err := r.persistLocked(); err != nil {
			return err
		}
		batch := relayauth.DailyBandwidthBatch{EdgeID: r.edgeID, BootID: r.bootID, Sequence: r.sequence, Reports: reports[start:end]}
		if err := r.send(ctx, r.token, batch); err != nil {
			return err
		}
	}
	r.acc.pruneBefore(r.now().UTC().Format("2006-01-02"))
	return r.persistLocked()
}

func (r *bandwidthReporter) persistLocked() error {
	reports := r.acc.snapshot()
	persisted := make([]bandwidthLedgerReport, len(reports))
	for i, report := range reports {
		persisted[i] = bandwidthLedgerReport{SubscriptionID: report.SubscriptionID, Day: report.Day, IngressBytes: report.IngressBytes, EgressBytes: report.EgressBytes}
	}
	return storeBandwidthLedger(r.path, bandwidthLedger{Version: bandwidthLedgerVersion, BootID: r.bootID, Sequence: r.sequence, Reports: persisted})
}

func loadBandwidthLedger(path string) (bandwidthLedger, error) {
	if err := validateBandwidthLedgerPath(path); err != nil {
		return bandwidthLedger{}, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		bootID, err := randomCanonicalUUID()
		if err != nil {
			return bandwidthLedger{}, err
		}
		ledger := bandwidthLedger{Version: bandwidthLedgerVersion, BootID: bootID, Reports: []bandwidthLedgerReport{}}
		return ledger, storeBandwidthLedger(path, ledger)
	}
	if err != nil {
		return bandwidthLedger{}, fmt.Errorf("read bandwidth ledger: %w", err)
	}
	if len(raw) == 0 || len(raw) > maxBandwidthLedgerSize {
		return bandwidthLedger{}, errors.New("invalid bandwidth ledger size")
	}
	var ledger bandwidthLedger
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ledger); err != nil {
		return bandwidthLedger{}, errors.New("invalid bandwidth ledger")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return bandwidthLedger{}, errors.New("invalid bandwidth ledger")
	}
	if err := validateBandwidthLedger(ledger); err != nil {
		return bandwidthLedger{}, err
	}
	return ledger, nil
}

func validateBandwidthLedger(ledger bandwidthLedger) error {
	if ledger.Version != bandwidthLedgerVersion || !canonicalSubscriptionID(ledger.BootID) || ledger.Sequence < 0 || len(ledger.Reports) > maxBandwidthEntries {
		return errors.New("invalid bandwidth ledger")
	}
	previous := ""
	seen := make(map[bandwidthKey]struct{}, len(ledger.Reports))
	for _, report := range ledger.Reports {
		if !canonicalSubscriptionID(report.SubscriptionID) || !canonicalBandwidthDay(report.Day) || report.IngressBytes < 0 || report.EgressBytes < 0 {
			return errors.New("invalid bandwidth ledger")
		}
		order := report.Day + "/" + report.SubscriptionID
		if previous != "" && order <= previous {
			return errors.New("bandwidth ledger reports are not canonical")
		}
		previous = order
		key := bandwidthKey{subscriptionID: report.SubscriptionID, day: report.Day}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("invalid bandwidth ledger")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func storeBandwidthLedger(path string, ledger bandwidthLedger) error {
	if err := validateBandwidthLedgerPath(path); err != nil {
		return err
	}
	sort.Slice(ledger.Reports, func(i, j int) bool {
		if ledger.Reports[i].Day == ledger.Reports[j].Day {
			return ledger.Reports[i].SubscriptionID < ledger.Reports[j].SubscriptionID
		}
		return ledger.Reports[i].Day < ledger.Reports[j].Day
	})
	if err := validateBandwidthLedger(ledger); err != nil {
		return err
	}
	raw, err := json.Marshal(ledger)
	if err != nil || len(raw) > maxBandwidthLedgerSize {
		return errors.New("encode bandwidth ledger")
	}
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, ".bandwidth-ledger-")
	if err != nil {
		return fmt.Errorf("create bandwidth ledger: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err == nil {
		_, err = temp.Write(raw)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write bandwidth ledger: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace bandwidth ledger: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open bandwidth ledger directory: %w", err)
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

func validateBandwidthLedgerPath(path string) error {
	if path == "" || filepath.Base(path) == "." {
		return errors.New("bandwidth state file is required")
	}
	directory := filepath.Dir(path)
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return errors.New("bandwidth state directory is unavailable")
	}
	info, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("bandwidth state file must be a regular owner-only file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("bandwidth state file must be owned by the relay user")
	}
	return nil
}

func randomCanonicalUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func canonicalSubscriptionID(value string) bool {
	_, err := parseCanonicalUUID(value)
	return err == nil
}

func canonicalBandwidthDay(value string) bool {
	parsed, err := time.Parse("2006-01-02", value)
	return err == nil && parsed.Format("2006-01-02") == value
}

func relayauthToken(value string) bool {
	if len(value) != 64 {
		return false
	}
	for i := range value {
		if !(value[i] >= '0' && value[i] <= '9' || value[i] >= 'a' && value[i] <= 'f') {
			return false
		}
	}
	return true
}
