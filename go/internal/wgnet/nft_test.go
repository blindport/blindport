package wgnet

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type fakeCommandRunner struct {
	name   string
	args   []string
	stdin  string
	output []byte
	err    error
}

func (f *fakeCommandRunner) Run(name string, args []string, stdin []byte) ([]byte, error) {
	f.name = name
	f.args = append([]string(nil), args...)
	f.stdin = string(stdin)
	return f.output, f.err
}

func TestRenderNFTPolicyHasExactRoutedSemantics(t *testing.T) {
	rules, err := RenderNFTPolicy("bpwg0", []string{"203.0.114.21/32", "203.0.114.20/32"}, []string{"203.0.114.21/32"})
	if err != nil {
		t.Fatal(err)
	}
	ruleset := string(rules)
	required := []string{
		"destroy table inet blindport\n",
		"table inet blindport {",
		"elements = { 203.0.114.20, 203.0.114.21 }",
		`iifname "bpwg0" ct state established,related counter accept comment "blindport_relay_return_traffic"`,
		`iifname "bpwg0" counter drop comment "blindport_relay_input"`,
		`iifname "bpwg0" meta nfproto ipv6 counter reject with icmpv6 type admin-prohibited comment "blindport_invalid_source"`,
		`iifname "bpwg0" ip saddr != @active_ipv4 counter reject with icmp type admin-prohibited comment "blindport_invalid_source"`,
		`ip saddr @smtp_allowed_ipv4 counter return comment "blindport_smtp_allowed"`,
		`counter drop comment "blindport_smtp_denied"`,
		`type filter hook postrouting priority filter; policy accept;`,
		`ct direction original ip saddr @active_ipv4 tcp dport 25 jump smtp_policy`,
		`iifname "bpwg0" ct state established,related counter accept comment "blindport_return_traffic"`,
		`ct direction original ip saddr @active_ipv4 ip daddr @non_global_ipv4 counter drop comment "blindport_non_global_destination"`,
		"type filter hook forward priority filter; policy accept;",
	}
	for _, fragment := range required {
		if !strings.Contains(ruleset, fragment) {
			t.Errorf("ruleset missing %q:\n%s", fragment, ruleset)
		}
	}
	if strings.Contains(ruleset, "flush ruleset") || strings.Contains(ruleset, "flush table") {
		t.Fatalf("ruleset modifies tables outside its atomic replacement:\n%s", ruleset)
	}
}

func TestNonGlobalIPv4DenylistIsExplicit(t *testing.T) {
	want := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	}
	if !reflect.DeepEqual(nonGlobalIPv4Prefixes, want) {
		t.Fatalf("nonGlobalIPv4Prefixes = %v", nonGlobalIPv4Prefixes)
	}
}

func TestNFTFirewallRunsOneAtomicTransaction(t *testing.T) {
	runner := &fakeCommandRunner{}
	firewall, err := newNFTFirewall("bpwg0", false, runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := firewall.Apply(nil, nil); err != nil {
		t.Fatal(err)
	}
	if runner.name != NFTExecutable || !reflect.DeepEqual(runner.args, []string{"-f", "-"}) || !strings.Contains(runner.stdin, "table inet blindport") {
		t.Fatalf("command = %q %v, stdin=%q", runner.name, runner.args, runner.stdin)
	}
}

func TestNFTFirewallPropagatesCommandErrors(t *testing.T) {
	runner := &fakeCommandRunner{output: []byte("syntax failure\n"), err: errors.New("exit status 1")}
	firewall, err := newNFTFirewall("bpwg0", false, runner)
	if err != nil {
		t.Fatal(err)
	}
	err = firewall.Apply(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "exit status 1") || !strings.Contains(err.Error(), "syntax failure") {
		t.Fatalf("Apply() error = %v", err)
	}
}

func TestNFTPolicyRejectsUnsafeInputs(t *testing.T) {
	for _, name := range []string{"", "interface-name-is-too-long", "bpwg0\nadd table ip x"} {
		if _, err := RenderNFTPolicy(name, nil, nil); err == nil {
			t.Fatalf("RenderNFTPolicy(%q) accepted unsafe interface", name)
		}
	}
	if _, err := RenderNFTPolicy("bpwg0", []string{"203.0.114.20/24"}, nil); err == nil {
		t.Fatal("RenderNFTPolicy accepted a non-/32 active prefix")
	}
}

func TestNFTPolicyPrivateDestinationExceptionIsExplicit(t *testing.T) {
	rules, err := renderNFTPolicy("bpwg0", []string{"203.0.114.20/32"}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rules), "non_global_ipv4") {
		t.Fatalf("private-destination test policy retained production denylist:\n%s", rules)
	}
}
