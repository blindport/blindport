package main

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func agentWireGuardTestKey() string {
	raw := make([]byte, 32)
	for index := range raw {
		raw[index] = byte(index + 1)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestWireGuardEnrollmentMessageMatchesBackendFormat(t *testing.T) {
	message := wireGuardEnrollmentMessage("11111111-2222-4333-8444-555555555555", 3, "KEY=")
	want := "blindport-wireguard-key-v1\n" +
		"instance_id=11111111-2222-4333-8444-555555555555\n" +
		"generation=3\n" +
		"public_key=KEY=\n"
	if string(message) != want {
		t.Fatalf("message = %q, want %q", message, want)
	}
}

func TestLoadOrCreateAgentWireGuardKeyPersistsPrivately(t *testing.T) {
	stateDir := t.TempDir()
	created, err := loadOrCreateAgentWireGuardKey(stateDir)
	if err != nil {
		t.Fatalf("loadOrCreateAgentWireGuardKey() error = %v", err)
	}
	reloaded, err := loadOrCreateAgentWireGuardKey(stateDir)
	if err != nil || reloaded.String() != created.String() {
		t.Fatalf("reloaded key = %v, %v", reloaded, err)
	}
	statePath := filepath.Join(stateDir, wireGuardStateName)
	info, err := os.Stat(statePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %v, %v", info.Mode(), err)
	}

	if err := os.Chmod(statePath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateAgentWireGuardKey(stateDir); err == nil {
		t.Fatal("exposed WireGuard state accepted")
	}
	if err := os.Chmod(statePath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte(`{"version":1,"private_key":"`+created.String()+`","extra":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateAgentWireGuardKey(stateDir); err == nil {
		t.Fatal("unknown state field accepted")
	}
}

func TestFetchAndEnrollWireGuardConfigAreStrict(t *testing.T) {
	key := agentWireGuardTestKey()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v2/client/wireguard":
			_, _ = io.WriteString(w, `{"instance_id":"11111111-2222-4333-8444-555555555555",`+
				`"generation":0,"public_key":null,"assigned_prefixes":["198.51.100.20/32"],`+
				`"relay_public_key":"`+key+`","endpoint":"relay:51820","mtu":1420,`+
				`"persistent_keepalive_seconds":25}`)
		case "POST /api/v2/client/wireguard/key":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"generation":1`) {
				t.Errorf("enroll body = %s", body)
			}
			_, _ = io.WriteString(w, `{"instance_id":"11111111-2222-4333-8444-555555555555",`+
				`"generation":1,"public_key":"`+key+`","assigned_prefixes":["198.51.100.20/32"],`+
				`"relay_public_key":"`+key+`","endpoint":"relay:51820","mtu":1420,`+
				`"persistent_keepalive_seconds":25}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	config, err := fetchWireGuardConfig(context.Background(), server.Client(), server.URL, "token")
	if err != nil || config.Generation != 0 || config.PublicKey != nil {
		t.Fatalf("fetch config = %+v, %v", config, err)
	}
	enrolled, err := enrollWireGuardKey(context.Background(), server.Client(), server.URL, "token", wireGuardKeyRequestV2{
		InstanceID: "11111111-2222-4333-8444-555555555555",
		Generation: 1,
		PublicKey:  key,
		Signature:  base64.StdEncoding.EncodeToString(make([]byte, 64)),
	})
	if err != nil || enrolled.Generation != 1 {
		t.Fatalf("enroll config = %+v, %v", enrolled, err)
	}

	loose := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"instance_id":"x","unknown":true}`)
	}))
	defer loose.Close()
	if _, err := fetchWireGuardConfig(context.Background(), loose.Client(), loose.URL, "token"); err == nil {
		t.Fatal("unknown response field accepted")
	}
}

func TestValidateWireGuardClientConfig(t *testing.T) {
	key := agentWireGuardTestKey()
	valid := &wireGuardConfigV2{
		PublicKey:                  &key,
		AssignedPrefixes:           []string{"198.51.100.20/32"},
		RelayPublicKey:             key,
		Endpoint:                   "relay:51820",
		MTU:                        1420,
		PersistentKeepaliveSeconds: 25,
	}
	if err := validateWireGuardClientConfig(valid, key); err != nil {
		t.Fatalf("validateWireGuardClientConfig() error = %v", err)
	}

	other := "different"
	cases := []func(config *wireGuardConfigV2){
		func(config *wireGuardConfigV2) { config.PublicKey = nil },
		func(config *wireGuardConfigV2) { config.PublicKey = &other },
		func(config *wireGuardConfigV2) { config.RelayPublicKey = "invalid" },
		func(config *wireGuardConfigV2) { config.Endpoint = "relay" },
		func(config *wireGuardConfigV2) { config.AssignedPrefixes = nil },
		func(config *wireGuardConfigV2) { config.AssignedPrefixes = []string{"198.51.100.0/24"} },
		func(config *wireGuardConfigV2) { config.MTU = 900 },
		func(config *wireGuardConfigV2) { config.PersistentKeepaliveSeconds = 500 },
	}
	for index, mutate := range cases {
		config := *valid
		config.AssignedPrefixes = append([]string(nil), valid.AssignedPrefixes...)
		mutate(&config)
		if err := validateWireGuardClientConfig(&config, key); err == nil {
			t.Fatalf("case %d accepted invalid config", index)
		}
	}
}

func TestValidateWireGuardAgentOptionsAcceptsShippedDefaults(t *testing.T) {
	defaults := wireGuardAgentOptions{httpClient: http.DefaultClient, routeTable: 51820, rulePriority: 51820}
	if err := validateWireGuardAgentOptions(defaults); err != nil {
		t.Fatalf("default WireGuard routing options rejected: %v", err)
	}
	for _, options := range []wireGuardAgentOptions{
		{httpClient: http.DefaultClient, routeTable: 0, rulePriority: 51820},
		{httpClient: http.DefaultClient, routeTable: 51820, rulePriority: 0},
		{httpClient: http.DefaultClient, routeTable: maxLinuxRoutingID + 1, rulePriority: 51820},
		{httpClient: http.DefaultClient, routeTable: 51820, rulePriority: maxLinuxRoutingID + 1},
	} {
		if err := validateWireGuardAgentOptions(options); err == nil {
			t.Fatalf("invalid WireGuard routing options accepted: %+v", options)
		}
	}
}
