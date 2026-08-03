package wgnet

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func testKey(fill byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = fill + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestValidateKeyRequiresCanonicalNonzero32Bytes(t *testing.T) {
	if err := ValidateKey(testKey(1)); err != nil {
		t.Fatalf("ValidateKey() error = %v", err)
	}
	invalid := []string{
		"",
		"not-base64!!",
		base64.StdEncoding.EncodeToString(make([]byte, 31)),
		base64.StdEncoding.EncodeToString(make([]byte, 32)),
		strings.Replace(testKey(1), "=", " ", 1),
	}
	for _, value := range invalid {
		if err := ValidateKey(value); err == nil {
			t.Fatalf("ValidateKey(%q) accepted invalid key", value)
		}
	}
}

func TestValidatePrefixRequiresCanonicalIPv4Slash32(t *testing.T) {
	if _, err := ValidatePrefix("198.51.100.20/32"); err != nil {
		t.Fatalf("ValidatePrefix() error = %v", err)
	}
	for _, value := range []string{"198.51.100.20", "198.51.100.0/24", "2001:db8::1/128", "198.051.100.20/32"} {
		if _, err := ValidatePrefix(value); err == nil {
			t.Fatalf("ValidatePrefix(%q) accepted invalid prefix", value)
		}
	}
}

func TestDesiredStateValidation(t *testing.T) {
	valid := &DesiredState{
		Revision:        "r1",
		ManagedPrefixes: []string{"198.51.100.20/32", "198.51.100.21/32"},
		Peers:           []Peer{{PublicKey: testKey(1), AllowedPrefixes: []string{"198.51.100.20/32"}}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	invalid := []*DesiredState{
		nil,
		{ManagedPrefixes: []string{"198.51.100.20/32", "198.51.100.20/32"}},
		{ManagedPrefixes: []string{"198.51.100.20/32"}, Peers: []Peer{{PublicKey: "bad", AllowedPrefixes: []string{"198.51.100.20/32"}}}},
		{ManagedPrefixes: []string{"198.51.100.20/32"}, Peers: []Peer{{PublicKey: testKey(1)}}},
		{ManagedPrefixes: []string{"198.51.100.20/32"}, Peers: []Peer{{PublicKey: testKey(1), AllowedPrefixes: []string{"198.51.100.99/32"}}}},
		{
			ManagedPrefixes: []string{"198.51.100.20/32"},
			Peers: []Peer{
				{PublicKey: testKey(1), AllowedPrefixes: []string{"198.51.100.20/32"}},
				{PublicKey: testKey(9), AllowedPrefixes: []string{"198.51.100.20/32"}},
			},
		},
	}
	for index, state := range invalid {
		if err := state.Validate(); err == nil {
			t.Fatalf("Validate() case %d accepted invalid state", index)
		}
	}
}

type fakeDataplane struct {
	operations []string
	failOn     string
}

func (f *fakeDataplane) ReplacePeers(peers []Peer) error {
	keys := make([]string, 0, len(peers))
	for _, peer := range peers {
		keys = append(keys, peer.PublicKey[:4])
	}
	operation := "peers:" + strings.Join(keys, ",")
	f.operations = append(f.operations, operation)
	if f.failOn == "peers" {
		return errors.New("injected peer failure")
	}
	return nil
}

func (f *fakeDataplane) ActivateRoute(prefix string) error {
	f.operations = append(f.operations, "activate:"+prefix)
	return nil
}

func (f *fakeDataplane) BlackholeRoute(prefix string) error {
	f.operations = append(f.operations, "blackhole:"+prefix)
	return nil
}

func TestReconcilerAppliesRevocationSafeOrder(t *testing.T) {
	dataplane := &fakeDataplane{}
	reconciler := NewReconciler(dataplane)
	err := reconciler.Apply(&DesiredState{
		Revision:        "r1",
		ManagedPrefixes: []string{"198.51.100.21/32", "198.51.100.20/32"},
		Peers:           []Peer{{PublicKey: testKey(1), AllowedPrefixes: []string{"198.51.100.20/32"}}},
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	want := []string{
		"blackhole:198.51.100.21/32",
		"peers:" + testKey(1)[:4],
		"activate:198.51.100.20/32",
	}
	if strings.Join(dataplane.operations, "|") != strings.Join(want, "|") {
		t.Fatalf("operations = %v, want %v", dataplane.operations, want)
	}
}

func TestReconcilerFailClosedBlackholesAllManagedInventory(t *testing.T) {
	dataplane := &fakeDataplane{}
	reconciler := NewReconciler(dataplane)
	if err := reconciler.Apply(&DesiredState{
		Revision:        "r1",
		ManagedPrefixes: []string{"198.51.100.20/32"},
		Peers:           []Peer{{PublicKey: testKey(1), AllowedPrefixes: []string{"198.51.100.20/32"}}},
	}); err != nil {
		t.Fatal(err)
	}
	dataplane.operations = nil
	if err := reconciler.FailClosed(); err != nil {
		t.Fatalf("FailClosed() error = %v", err)
	}
	want := []string{"blackhole:198.51.100.20/32", "peers:"}
	if strings.Join(dataplane.operations, "|") != strings.Join(want, "|") {
		t.Fatalf("fail-closed operations = %v, want %v", dataplane.operations, want)
	}
}

func TestReconcilerRejectsInvalidStateBeforeAnyOperation(t *testing.T) {
	dataplane := &fakeDataplane{}
	reconciler := NewReconciler(dataplane)
	err := reconciler.Apply(&DesiredState{
		ManagedPrefixes: []string{"198.51.100.20/32"},
		Peers:           []Peer{{PublicKey: "bad", AllowedPrefixes: []string{"198.51.100.20/32"}}},
	})
	if err == nil || len(dataplane.operations) != 0 {
		t.Fatalf("Apply() err=%v operations=%v", err, dataplane.operations)
	}
}
