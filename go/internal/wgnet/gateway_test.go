package wgnet

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParsePortRangesRequiresCanonicalBoundedInput(t *testing.T) {
	ranges, err := ParsePortRanges("25,80,443,8000-8010")
	if err != nil {
		t.Fatal(err)
	}
	want := []PortRange{{Start: 25, End: 25}, {Start: 80, End: 80}, {Start: 443, End: 443}, {Start: 8000, End: 8010}}
	if !reflect.DeepEqual(ranges, want) {
		t.Fatalf("ParsePortRanges() = %#v, want %#v", ranges, want)
	}
	for _, value := range []string{" 80", "080", "80,80", "81,80", "80-80", "80-79", "80-81,81", "80,,81", "80-", "0", "65536", "1-1025"} {
		if _, err := ParsePortRanges(value); err == nil {
			t.Errorf("ParsePortRanges(%q) succeeded", value)
		}
	}
}

func TestRenderGatewayNFTPolicyFailsClosedWithExactExceptions(t *testing.T) {
	rules, err := RenderGatewayNFTPolicy(GatewayFirewallConfig{
		InterfaceName: "bpwg0", RelayInterface: "eth0", RelayEndpoint: netip.MustParseAddr("198.18.0.10"), RelayPort: 51820,
		TCPPorts: []PortRange{{Start: 25, End: 25}, {Start: 443, End: 443}}, UDPPorts: []PortRange{{Start: 53, End: 53}}, AllowICMP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ruleset := string(rules)
	for _, fragment := range []string{
		"destroy table inet blindport-agent", "table inet blindport-agent", "policy drop;",
		`iifname "bpwg0" tcp dport @gateway_tcp_ports counter accept`,
		`iifname "bpwg0" udp dport @gateway_udp_ports counter accept`,
		`iifname "bpwg0" icmp type echo-request counter accept`,
		`iifname "bpwg0" counter drop comment "blindport_gateway_input_default_deny"`,
		`ip daddr 127.0.0.11 udp dport 53 counter accept`,
		`ip daddr 127.0.0.11 tcp dport 53 counter accept`,
		`ip daddr 198.18.0.10 oifname "eth0" udp dport 51820 counter accept`,
		`blindport_gateway_ipv4_leak`, `blindport_gateway_ipv6_leak`,
	} {
		if !strings.Contains(ruleset, fragment) {
			t.Errorf("ruleset missing %q:\n%s", fragment, ruleset)
		}
	}
	if strings.Contains(ruleset, `oifname "eth0" counter accept`) {
		t.Fatalf("gateway permits general original-interface egress:\n%s", ruleset)
	}
	if count := strings.Count(ruleset, `ct state established,related counter accept comment "blindport_gateway_return_traffic"`); count != 1 {
		t.Fatalf("gateway return-traffic rule count = %d, want input-only rule:\n%s", count, ruleset)
	}
	if strings.Index(ruleset, "blindport_gateway_ipv6_leak") > strings.Index(ruleset, "blindport_gateway_tunnel") {
		t.Fatalf("IPv6 is not blocked before the tunnel allow:\n%s", ruleset)
	}
}

func TestRenderGatewayNFTPolicyEmptyAllowlistsDenyTunnelInput(t *testing.T) {
	rules, err := RenderGatewayNFTPolicy(GatewayFirewallConfig{
		InterfaceName: "bpwg0", RelayInterface: "eth0", RelayEndpoint: netip.MustParseAddr("198.18.0.10"), RelayPort: 51820,
	})
	if err != nil {
		t.Fatal(err)
	}
	ruleset := string(rules)
	if strings.Contains(ruleset, "elements =") {
		t.Fatalf("empty gateway allowlists populated an nft set:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, `iifname "bpwg0" counter drop comment "blindport_gateway_input_default_deny"`) {
		t.Fatalf("empty gateway allowlists lack default deny:\n%s", ruleset)
	}
}

type fakeGatewayPolicyApplier struct {
	operations []string
	firewall   error
	endpoint   error
	allTraffic error
}

func (f *fakeGatewayPolicyApplier) ApplyFirewall() error {
	f.operations = append(f.operations, "firewall")
	return f.firewall
}

func (f *fakeGatewayPolicyApplier) AddEndpointException() error {
	f.operations = append(f.operations, "endpoint")
	return f.endpoint
}

func (f *fakeGatewayPolicyApplier) AddAllTrafficRule() error {
	f.operations = append(f.operations, "all-traffic")
	return f.allTraffic
}

func TestApplyGatewayPolicyKeepsKillSwitchAfterRoutingFailures(t *testing.T) {
	for _, test := range []struct {
		name       string
		applier    fakeGatewayPolicyApplier
		operations string
	}{
		{name: "firewall", applier: fakeGatewayPolicyApplier{firewall: errors.New("nft")}, operations: "firewall"},
		{name: "endpoint", applier: fakeGatewayPolicyApplier{endpoint: errors.New("endpoint")}, operations: "firewall,endpoint"},
		{name: "all traffic", applier: fakeGatewayPolicyApplier{allTraffic: errors.New("rule")}, operations: "firewall,endpoint,all-traffic"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := applyGatewayPolicy(&test.applier); err == nil {
				t.Fatal("applyGatewayPolicy() succeeded")
			}
			if got := strings.Join(test.applier.operations, ","); got != test.operations {
				t.Fatalf("operations = %q, want %q", got, test.operations)
			}
		})
	}
}
