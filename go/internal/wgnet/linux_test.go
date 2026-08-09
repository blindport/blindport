//go:build linux

package wgnet

import (
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func testWireGuardKey(t *testing.T, start byte) wgtypes.Key {
	t.Helper()
	raw := make([]byte, 32)
	for index := range raw {
		raw[index] = start + byte(index)
	}
	key, err := wgtypes.ParseKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type fakeRelayStartupDataplane struct {
	operations []string
	policyErr  error
	routeErr   error
	peerErr    error
}

func (f *fakeRelayStartupDataplane) ApplyRoutedPolicy(active, smtp []string) error {
	f.operations = append(f.operations, "policy")
	return f.policyErr
}

func (f *fakeRelayStartupDataplane) blackholeActiveOwnedRoutes() error {
	f.operations = append(f.operations, "routes")
	return f.routeErr
}

func (f *fakeRelayStartupDataplane) ReplacePeers(peers []Peer) error {
	f.operations = append(f.operations, "peers")
	return f.peerErr
}

func TestFailCloseRelayStartupOrdersAndAttemptsEveryLayer(t *testing.T) {
	dataplane := &fakeRelayStartupDataplane{
		policyErr: errors.New("nft unavailable"),
		routeErr:  errors.New("route failure"),
		peerErr:   errors.New("peer failure"),
	}
	err := failCloseRelayStartup(dataplane)
	if strings.Join(dataplane.operations, ",") != "peers,policy,routes" {
		t.Fatalf("startup operations = %v", dataplane.operations)
	}
	for _, message := range []string{"nft unavailable", "route failure", "peer failure"} {
		if err == nil || !strings.Contains(err.Error(), message) {
			t.Fatalf("startup error = %v, want %q", err, message)
		}
	}
}

func TestRelayPeerConfigsUpdatesDesiredPeersWithoutReplacingRuntimeState(t *testing.T) {
	desiredKey := testWireGuardKey(t, 1)
	staleKey := testWireGuardKey(t, 33)
	endpoint := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 51820}
	configs, err := relayPeerConfigs(
		[]wgtypes.Peer{
			{PublicKey: desiredKey, Endpoint: endpoint},
			{PublicKey: staleKey},
		},
		[]Peer{{PublicKey: desiredKey.String(), AllowedPrefixes: []string{"198.51.100.20/32"}}},
	)
	if err != nil {
		t.Fatalf("relayPeerConfigs() error = %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("config count = %d, want 2", len(configs))
	}
	if configs[0].PublicKey != staleKey || !configs[0].Remove {
		t.Fatalf("stale peer config = %+v", configs[0])
	}
	updated := configs[1]
	if updated.PublicKey != desiredKey || updated.Remove || updated.Endpoint != nil {
		t.Fatalf("desired peer config = %+v", updated)
	}
	if !updated.ReplaceAllowedIPs || len(updated.AllowedIPs) != 1 || updated.AllowedIPs[0].String() != "198.51.100.20/32" {
		t.Fatalf("desired allowed IPs = %+v", updated.AllowedIPs)
	}
}

func TestOwnedAgentRuleRecognizesTaggedAndLegacyRules(t *testing.T) {
	previous := map[string]struct{}{"198.51.100.20/32": {}}
	tagged := *netlink.NewRule()
	tagged.Protocol = RouteProtocol
	if !isOwnedAgentRule(tagged, nil, 51820) {
		t.Fatal("tagged Blindport rule was not recognized")
	}
	_, source, err := net.ParseCIDR("198.51.100.20/32")
	if err != nil {
		t.Fatal(err)
	}
	legacy := *netlink.NewRule()
	legacy.Table = 51820
	legacy.Src = source
	if !isOwnedAgentRule(legacy, previous, 51820) {
		t.Fatal("legacy leased-source rule was not recognized")
	}
	legacy.Table = 100
	if isOwnedAgentRule(legacy, previous, 51820) {
		t.Fatal("rule from an operator table was treated as Blindport-owned")
	}
	legacy.Table = 51820
	_, legacy.Src, err = net.ParseCIDR("198.51.100.21/32")
	if err != nil {
		t.Fatal(err)
	}
	if isOwnedAgentRule(legacy, previous, 51820) {
		t.Fatal("rule for an address absent from the Blindport interface was treated as owned")
	}
}

func TestConfigureGatewayAgentRejectsOtherThanOnePrefixBeforeNetworkChanges(t *testing.T) {
	for _, prefixes := range [][]string{nil, {"198.51.100.20/32", "198.51.100.21/32"}} {
		err := ConfigureGatewayAgent(GatewayConfig{AgentConfig: AgentConfig{Prefixes: prefixes}})
		if err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("ConfigureGatewayAgent(%v) error = %v", prefixes, err)
		}
	}
	if err := ConfigureGatewayAgent(GatewayConfig{AgentConfig: AgentConfig{Prefixes: []string{"198.51.100.0/24"}}}); err == nil {
		t.Fatal("gateway accepted a non-/32 before network setup")
	}
}
