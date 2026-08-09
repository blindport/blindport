package wgnet

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
)

const maxAccountingJSON = 1 << 20

// ErrAccountingTableMissing indicates that the live accounting table was
// removed outside Blindport and must be reinstalled before traffic continues.
var ErrAccountingTableMissing = errors.New("accounting nft table is missing")

// PrefixBinding is an exact active routed prefix and its canonical subscriber.
// The prefix exists only in live nft rules, never in persisted report state.
type PrefixBinding struct {
	Prefix         string
	SubscriptionID string
}

// AccountingCounter is one subscriber-relative live counter total.
type AccountingCounter struct {
	SubscriptionID string
	IngressBytes   int64
	EgressBytes    int64
}

// NFTBandwidthAccounting owns the separate accounting table.
type NFTBandwidthAccounting struct {
	interfaceName string
	runner        CommandRunner
}

func NewNFTBandwidthAccounting(interfaceName string) (*NFTBandwidthAccounting, error) {
	return newNFTBandwidthAccounting(interfaceName, execCommandRunner{})
}

func newNFTBandwidthAccounting(interfaceName string, runner CommandRunner) (*NFTBandwidthAccounting, error) {
	if err := ValidateInterfaceName(interfaceName); err != nil || runner == nil {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("nft command runner is required")
	}
	return &NFTBandwidthAccounting{interfaceName: interfaceName, runner: runner}, nil
}

func (a *NFTBandwidthAccounting) Install(bindings []PrefixBinding) error {
	rules, err := RenderNFTAccountingPolicy(a.interfaceName, bindings)
	if err != nil {
		return err
	}
	output, err := a.runner.Run(NFTExecutable, []string{"-f", "-"}, rules)
	if err != nil {
		return nftOutputError("install accounting nft policy", err, output)
	}
	return nil
}

func (a *NFTBandwidthAccounting) Remove() error {
	output, err := a.runner.Run(NFTExecutable, []string{"delete", "table", "inet", "blindport-accounting"}, nil)
	if err != nil {
		// Deletion is idempotent when startup has never installed this table.
		if strings.Contains(strings.ToLower(string(output)), "no such file") {
			return nil
		}
		return nftOutputError("remove accounting nft policy", err, output)
	}
	return nil
}

func (a *NFTBandwidthAccounting) Read() ([]AccountingCounter, error) {
	raw, err := a.runner.Run(NFTExecutable, []string{"-j", "list", "counters", "table", "inet", "blindport-accounting"}, nil)
	if err != nil {
		if strings.Contains(strings.ToLower(string(raw)), "no such file") {
			return nil, ErrAccountingTableMissing
		}
		return nil, nftOutputError("read accounting nft counters", err, raw)
	}
	return ParseNFTAccountingCounters(raw)
}

func nftOutputError(operation string, err error, output []byte) error {
	if detail := strings.TrimSpace(string(output)); detail != "" {
		return fmt.Errorf("%s: %w: %s", operation, err, detail)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

// RenderNFTAccountingPolicy renders a distinct postrouting table at a later
// priority than the authorization policy. Therefore rejected traffic is never
// counted.
func RenderNFTAccountingPolicy(interfaceName string, bindings []PrefixBinding) ([]byte, error) {
	if err := ValidateInterfaceName(interfaceName); err != nil {
		return nil, err
	}
	validated, err := validateBindings(bindings)
	if err != nil {
		return nil, err
	}
	var rules strings.Builder
	rules.WriteString("destroy table inet blindport-accounting\n")
	rules.WriteString("table inet blindport-accounting {\n")
	for _, binding := range validated {
		name := strings.ReplaceAll(binding.SubscriptionID, "-", "")
		fmt.Fprintf(&rules, "\tcounter ingress_%s {}\n", name)
		fmt.Fprintf(&rules, "\tcounter egress_%s {}\n", name)
	}
	rules.WriteString("\tchain postrouting {\n")
	rules.WriteString("\t\ttype filter hook postrouting priority filter + 10; policy accept;\n")
	for _, binding := range validated {
		name := strings.ReplaceAll(binding.SubscriptionID, "-", "")
		fmt.Fprintf(&rules, "\t\tiifname %q ip saddr %s counter name egress_%s\n", interfaceName, binding.Prefix, name)
		fmt.Fprintf(&rules, "\t\toifname %q ip daddr %s counter name ingress_%s\n", interfaceName, binding.Prefix, name)
	}
	rules.WriteString("\t}\n}\n")
	return []byte(rules.String()), nil
}

func validateBindings(bindings []PrefixBinding) ([]PrefixBinding, error) {
	if len(bindings) > 10000 {
		return nil, errors.New("too many accounting bindings")
	}
	out := append([]PrefixBinding(nil), bindings...)
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	seenPrefixes := make(map[string]struct{}, len(out))
	seenSubscriptions := make(map[string]struct{}, len(out))
	for _, binding := range out {
		if _, err := ValidatePrefix(binding.Prefix); err != nil || !canonicalUUID(binding.SubscriptionID) {
			return nil, errors.New("invalid accounting binding")
		}
		if _, exists := seenPrefixes[binding.Prefix]; exists {
			return nil, errors.New("duplicate accounting binding")
		}
		if _, exists := seenSubscriptions[binding.SubscriptionID]; exists {
			return nil, errors.New("duplicate accounting subscription")
		}
		seenPrefixes[binding.Prefix] = struct{}{}
		seenSubscriptions[binding.SubscriptionID] = struct{}{}
	}
	return out, nil
}

// ParseNFTAccountingCounters strictly accepts nft JSON counter objects and
// returns only subscription totals. Counter names intentionally encode no IP.
func ParseNFTAccountingCounters(raw []byte) ([]AccountingCounter, error) {
	if len(raw) == 0 || len(raw) > maxAccountingJSON {
		return nil, errors.New("invalid accounting nft JSON size")
	}
	var document struct {
		NFTables []json.RawMessage `json:"nftables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("invalid accounting nft JSON")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("invalid accounting nft JSON")
	}
	if len(document.NFTables) > 20010 {
		return nil, errors.New("too many accounting nft objects")
	}
	totals := map[string]AccountingCounter{}
	seenCounters := make(map[string]struct{})
	directions := make(map[string]uint8)
	for _, rawObject := range document.NFTables {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(rawObject, &object); err != nil || len(object) != 1 {
			return nil, errors.New("invalid accounting nft object")
		}
		counterRaw, exists := object["counter"]
		if !exists {
			// nft emits table and metainfo records alongside named counters.
			if object["table"] != nil || object["metainfo"] != nil {
				continue
			}
			return nil, errors.New("unexpected accounting nft object")
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(counterRaw, &fields); err != nil || len(fields) != 6 {
			return nil, errors.New("invalid accounting nft counter")
		}
		for _, field := range []string{"family", "table", "name", "handle", "packets", "bytes"} {
			if _, exists := fields[field]; !exists {
				return nil, errors.New("invalid accounting nft counter")
			}
		}
		var counter struct {
			Family  string `json:"family"`
			Table   string `json:"table"`
			Name    string `json:"name"`
			Handle  uint64 `json:"handle"`
			Packets uint64 `json:"packets"`
			Bytes   uint64 `json:"bytes"`
		}
		if err := json.Unmarshal(counterRaw, &counter); err != nil || counter.Family != "inet" || counter.Table != "blindport-accounting" || counter.Bytes > math.MaxInt64 {
			return nil, errors.New("invalid accounting nft counter")
		}
		var direction string
		var suffix string
		switch {
		case strings.HasPrefix(counter.Name, "ingress_"):
			direction, suffix = "ingress", strings.TrimPrefix(counter.Name, "ingress_")
		case strings.HasPrefix(counter.Name, "egress_"):
			direction, suffix = "egress", strings.TrimPrefix(counter.Name, "egress_")
		default:
			return nil, errors.New("invalid accounting nft counter name")
		}
		if !canonicalCompactUUID(suffix) {
			return nil, errors.New("invalid accounting nft counter name")
		}
		if _, exists := seenCounters[counter.Name]; exists {
			return nil, errors.New("duplicate accounting nft counter")
		}
		seenCounters[counter.Name] = struct{}{}
		subscriptionID := suffix[:8] + "-" + suffix[8:12] + "-" + suffix[12:16] + "-" + suffix[16:20] + "-" + suffix[20:32]
		current := totals[subscriptionID]
		current.SubscriptionID = subscriptionID
		if direction == "ingress" {
			if current.IngressBytes > math.MaxInt64-int64(counter.Bytes) {
				return nil, errors.New("accounting counter overflow")
			}
			current.IngressBytes += int64(counter.Bytes)
			directions[subscriptionID] |= 1
		} else {
			if current.EgressBytes > math.MaxInt64-int64(counter.Bytes) {
				return nil, errors.New("accounting counter overflow")
			}
			current.EgressBytes += int64(counter.Bytes)
			directions[subscriptionID] |= 2
		}
		totals[subscriptionID] = current
	}
	out := make([]AccountingCounter, 0, len(totals))
	for _, total := range totals {
		if directions[total.SubscriptionID] != 3 {
			return nil, errors.New("incomplete accounting nft counters")
		}
		out = append(out, total)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SubscriptionID < out[j].SubscriptionID })
	return out, nil
}

func canonicalCompactUUID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for i := range value {
		if !(value[i] >= '0' && value[i] <= '9' || value[i] >= 'a' && value[i] <= 'f') {
			return false
		}
	}
	return true
}

func canonicalUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	return canonicalCompactUUID(strings.ReplaceAll(value, "-", ""))
}
