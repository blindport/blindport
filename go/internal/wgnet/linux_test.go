//go:build linux

package wgnet

import (
	"encoding/base64"
	"net"
	"testing"

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
