package main

import (
	"errors"
	"log/slog"
	"math"
	"sort"

	"github.com/blindport/blindport/internal/relayauth"
	"github.com/blindport/blindport/internal/wgnet"
)

type wireGuardCounterAccounting interface {
	Install([]wgnet.PrefixBinding) error
	Remove() error
	Read() ([]wgnet.AccountingCounter, error)
}

// wireGuardBandwidthAccounting keeps live nft counter state separate from the
// persisted reporter. It is called only by wireGuardManager's single loop.
type wireGuardBandwidthAccounting struct {
	log      *slog.Logger
	reporter *bandwidthReporter
	account  wireGuardCounterAccounting
	bindings []wgnet.PrefixBinding
	last     map[string]wgnet.AccountingCounter
	present  bool
	applied  bool
	revision string
}

func newWireGuardBandwidthAccounting(log *slog.Logger, reporter *bandwidthReporter, account wireGuardCounterAccounting) *wireGuardBandwidthAccounting {
	return &wireGuardBandwidthAccounting{log: log, reporter: reporter, account: account}
}

// prepare drains counters before replacing an attribution table. It reports
// whether the unchanged desired revision can retry a failed install directly.
func (a *wireGuardBandwidthAccounting) prepare(state *relayauth.WireGuardDesiredState) ([]wgnet.PrefixBinding, bool, error) {
	bindings, err := bandwidthBindings(state)
	if err != nil {
		return nil, false, err
	}
	changed := !samePrefixBindings(a.bindings, bindings)
	if !changed {
		if a.present {
			if err := a.collect(); err != nil {
				if errors.Is(err, wgnet.ErrAccountingTableMissing) {
					return bindings, true, nil
				}
				return nil, false, err
			}
		} else if a.applied && a.revision == state.Revision {
			return bindings, true, nil
		}
		return bindings, false, nil
	}

	if a.present {
		if err := a.collect(); err != nil && !errors.Is(err, wgnet.ErrAccountingTableMissing) {
			return nil, false, err
		}
		if !a.present {
			return bindings, false, nil
		}
		if err := a.account.Remove(); err != nil {
			return nil, false, err
		}
		a.present = false
		a.last = nil
	}
	return bindings, false, nil
}

func (a *wireGuardBandwidthAccounting) appliedState(bindings []wgnet.PrefixBinding, revision string) error {
	a.bindings = append(a.bindings[:0], bindings...)
	a.applied = true
	a.revision = revision
	if a.present {
		return nil
	}
	if err := a.account.Install(bindings); err != nil {
		return err
	}
	a.present = true
	a.last = zeroCounterTotals(bindings)
	return nil
}

func (a *wireGuardBandwidthAccounting) collect() error {
	if !a.present {
		return nil
	}
	counters, err := a.account.Read()
	if err != nil {
		if errors.Is(err, wgnet.ErrAccountingTableMissing) {
			a.present = false
			a.last = nil
		}
		return err
	}
	if len(counters) != len(a.bindings) {
		return errors.New("incomplete WireGuard bandwidth counters")
	}
	current := make(map[string]wgnet.AccountingCounter, len(counters))
	expected := zeroCounterTotals(a.bindings)
	for _, counter := range counters {
		if _, exists := expected[counter.SubscriptionID]; !exists || counter.IngressBytes < 0 || counter.EgressBytes < 0 {
			return errors.New("invalid WireGuard bandwidth counter")
		}
		if _, duplicate := current[counter.SubscriptionID]; duplicate {
			return errors.New("duplicate WireGuard bandwidth counter")
		}
		current[counter.SubscriptionID] = counter
	}
	increments := make([]bandwidthIncrement, 0, len(current)*2)
	for subscriptionID, total := range current {
		previous := a.last[subscriptionID]
		increment, ok, err := a.deltaIncrement(subscriptionID, bandwidthIngress, total.IngressBytes-previous.IngressBytes)
		if err != nil {
			return err
		}
		if ok {
			increments = append(increments, increment)
		}
		increment, ok, err = a.deltaIncrement(subscriptionID, bandwidthEgress, total.EgressBytes-previous.EgressBytes)
		if err != nil {
			return err
		}
		if ok {
			increments = append(increments, increment)
		}
	}
	if err := a.reporter.addBatchChecked(increments); err != nil {
		return err
	}
	a.last = current
	return nil
}

func (a *wireGuardBandwidthAccounting) deltaIncrement(subscriptionID string, direction bandwidthDirection, delta int64) (bandwidthIncrement, bool, error) {
	if delta < 0 {
		a.log.Warn("WireGuard bandwidth accounting degraded")
		return bandwidthIncrement{}, false, nil
	}
	if delta > int64(^uint(0)>>1) || delta > math.MaxInt64 {
		return bandwidthIncrement{}, false, errors.New("WireGuard bandwidth counter exceeds platform limit")
	}
	return bandwidthIncrement{subscriptionID: subscriptionID, direction: direction, count: int(delta)}, true, nil
}

// close drains the installed table and removes it before the authorization
// plane is failed closed. Errors are deliberately non-fatal to fail-close.
func (a *wireGuardBandwidthAccounting) close() {
	if !a.present {
		return
	}
	if err := a.collect(); err != nil {
		a.log.Warn("WireGuard bandwidth accounting degraded")
	}
	if err := a.account.Remove(); err != nil {
		a.log.Warn("WireGuard bandwidth accounting degraded")
		return
	}
	a.present = false
	a.last = nil
}

func bandwidthBindings(state *relayauth.WireGuardDesiredState) ([]wgnet.PrefixBinding, error) {
	if state == nil || state.PrefixBindings == nil {
		return nil, errors.New("invalid WireGuard bandwidth bindings")
	}
	active := desiredStateFromResponse(state).ActivePrefixes()
	if len(state.PrefixBindings) != len(active) {
		return nil, errors.New("invalid WireGuard bandwidth bindings")
	}
	bindings := make([]wgnet.PrefixBinding, len(state.PrefixBindings))
	seenPrefix := make(map[string]struct{}, len(bindings))
	seenSubscription := make(map[string]struct{}, len(bindings))
	for index, binding := range state.PrefixBindings {
		if _, err := wgnet.ValidatePrefix(binding.Prefix); err != nil || !canonicalSubscriptionID(binding.SubscriptionID) {
			return nil, errors.New("invalid WireGuard bandwidth bindings")
		}
		if _, exists := seenPrefix[binding.Prefix]; exists {
			return nil, errors.New("invalid WireGuard bandwidth bindings")
		}
		if _, exists := seenSubscription[binding.SubscriptionID]; exists {
			return nil, errors.New("invalid WireGuard bandwidth bindings")
		}
		seenPrefix[binding.Prefix] = struct{}{}
		seenSubscription[binding.SubscriptionID] = struct{}{}
		bindings[index] = wgnet.PrefixBinding{Prefix: binding.Prefix, SubscriptionID: binding.SubscriptionID}
	}
	for _, prefix := range active {
		if _, exists := seenPrefix[prefix]; !exists {
			return nil, errors.New("invalid WireGuard bandwidth bindings")
		}
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].Prefix < bindings[j].Prefix })
	return bindings, nil
}

func samePrefixBindings(left, right []wgnet.PrefixBinding) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func zeroCounterTotals(bindings []wgnet.PrefixBinding) map[string]wgnet.AccountingCounter {
	totals := make(map[string]wgnet.AccountingCounter, len(bindings))
	for _, binding := range bindings {
		totals[binding.SubscriptionID] = wgnet.AccountingCounter{SubscriptionID: binding.SubscriptionID}
	}
	return totals
}
