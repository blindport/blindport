package wgnet

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestRenderNFTAccountingPolicyUsesNamedPostroutingCounters(t *testing.T) {
	rules, err := RenderNFTAccountingPolicy("bpwg0", []PrefixBinding{
		{Prefix: "198.51.100.21/32", SubscriptionID: "22222222-2222-4222-8222-222222222222"},
		{Prefix: "198.51.100.20/32", SubscriptionID: "11111111-1111-4111-8111-111111111111"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ruleset := string(rules)
	for _, fragment := range []string{
		"counter ingress_11111111111141118111111111111111 {}",
		"counter egress_22222222222242228222222222222222 {}",
		"type filter hook postrouting priority filter + 10; policy accept;",
		`iifname "bpwg0" ip saddr 198.51.100.20/32 counter name egress_11111111111141118111111111111111`,
		`oifname "bpwg0" ip daddr 198.51.100.21/32 counter name ingress_22222222222242228222222222222222`,
	} {
		if !strings.Contains(ruleset, fragment) {
			t.Fatalf("ruleset missing %q:\n%s", fragment, ruleset)
		}
	}
	if strings.Index(ruleset, "198.51.100.20") > strings.Index(ruleset, "198.51.100.21") {
		t.Fatalf("bindings were not rendered in prefix order:\n%s", ruleset)
	}
}

func TestParseNFTAccountingCountersStrictActualJSON(t *testing.T) {
	raw := []byte(`{"nftables":[{"metainfo":{"version":"1.0.9","release_name":"test"}},{"table":{"family":"inet","name":"blindport-accounting","handle":9}},{"counter":{"family":"inet","table":"blindport-accounting","name":"ingress_11111111111141118111111111111111","handle":10,"packets":2,"bytes":12}},{"counter":{"family":"inet","table":"blindport-accounting","name":"egress_11111111111141118111111111111111","handle":11,"packets":3,"bytes":8}}]}`)
	counters, err := ParseNFTAccountingCounters(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(counters) != 1 || counters[0].SubscriptionID != "11111111-1111-4111-8111-111111111111" || counters[0].IngressBytes != 12 || counters[0].EgressBytes != 8 {
		t.Fatalf("counters = %+v", counters)
	}
}

func TestNFTAccountingRejectsDuplicateBindingsAndInvalidJSON(t *testing.T) {
	duplicatePrefix := []PrefixBinding{
		{Prefix: "198.51.100.20/32", SubscriptionID: "11111111-1111-4111-8111-111111111111"},
		{Prefix: "198.51.100.20/32", SubscriptionID: "22222222-2222-4222-8222-222222222222"},
	}
	duplicateSubscription := []PrefixBinding{
		{Prefix: "198.51.100.20/32", SubscriptionID: "11111111-1111-4111-8111-111111111111"},
		{Prefix: "198.51.100.21/32", SubscriptionID: "11111111-1111-4111-8111-111111111111"},
	}
	if _, err := RenderNFTAccountingPolicy("bpwg0", duplicatePrefix); err == nil {
		t.Fatal("duplicate prefix accepted")
	}
	if _, err := RenderNFTAccountingPolicy("bpwg0", duplicateSubscription); err == nil {
		t.Fatal("duplicate subscription accepted")
	}
	for _, raw := range [][]byte{
		[]byte(`{"nftables":[{"counter":{"family":"inet","table":"blindport-accounting","name":"ingress_11111111111141118111111111111111","packets":0,"bytes":0}}]}`),
		[]byte(`{"nftables":[{"counter":{"family":"inet","table":"blindport-accounting","name":"ingress_11111111111141118111111111111111","handle":1,"packets":0,"bytes":0,"unknown":true}}]}`),
		[]byte(`{"nftables":[{"counter":{"family":"inet","table":"blindport-accounting","name":"ingress_11111111111141118111111111111111","handle":1,"packets":0,"bytes":0}}]}`),
		[]byte(`{"nftables":[{"counter":{"family":"inet","table":"blindport-accounting","name":"ingress_11111111111141118111111111111111","handle":1,"packets":0,"bytes":0}},{"counter":{"family":"inet","table":"blindport-accounting","name":"ingress_11111111111141118111111111111111","handle":2,"packets":0,"bytes":0}}]}`),
		make([]byte, maxAccountingJSON+1),
	} {
		if _, err := ParseNFTAccountingCounters(raw); err == nil {
			t.Fatalf("invalid accounting JSON accepted: %q", raw)
		}
	}
}

func TestNFTAccountingReadClassifiesMissingTable(t *testing.T) {
	runner := &fakeCommandRunner{output: []byte("Error: No such file or directory"), err: errors.New("exit status 1")}
	accounting, err := newNFTBandwidthAccounting("bpwg0", runner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accounting.Read(); !errors.Is(err, ErrAccountingTableMissing) {
		t.Fatalf("read error = %v", err)
	}
}

func TestNFTAccountingLiveRoundTrip(t *testing.T) {
	if os.Getenv("BLINDPORT_NFT_INTEGRATION") != "1" {
		t.Skip("set BLINDPORT_NFT_INTEGRATION=1 in an isolated network namespace with CAP_NET_ADMIN")
	}
	accounting, err := NewNFTBandwidthAccounting("bpwg0")
	if err != nil {
		t.Fatal(err)
	}
	_ = accounting.Remove()
	t.Cleanup(func() {
		if err := accounting.Remove(); err != nil {
			t.Errorf("remove accounting policy: %v", err)
		}
	})
	bindings := []PrefixBinding{{Prefix: "198.51.100.20/32", SubscriptionID: "11111111-1111-4111-8111-111111111111"}}
	if err := accounting.Install(bindings); err != nil {
		t.Fatal(err)
	}
	counters, err := accounting.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(counters) != 1 || counters[0].SubscriptionID != bindings[0].SubscriptionID || counters[0].IngressBytes != 0 || counters[0].EgressBytes != 0 {
		t.Fatalf("live counters = %+v", counters)
	}
}
