package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testSubscriptionID1   = "11111111-1111-4111-8111-111111111111"
	testSubscriptionID2   = "22222222-2222-4222-8222-222222222222"
	testSubscriptionID3   = "33333333-3333-4333-8333-333333333333"
	testSubscriptionID10  = "10101010-1010-4010-8010-101010101010"
	testSubscriptionID11  = "11111111-1111-4111-8111-111111111112"
	testSubscriptionID20  = "20202020-2020-4020-8020-202020202020"
	testSubscriptionID42  = "42424242-4242-4242-8242-424242424242"
	testSubscriptionID99  = "99999999-9999-4999-8999-999999999999"
	testSubscriptionID123 = "12312312-3123-4123-8123-123123123123"
	testSubscriptionID456 = "45645645-6456-4456-8456-456456456456"
)

func writeConfig(t *testing.T, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blindport.json")
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadStaticConfig(t *testing.T) {
	path := writeConfig(t, `{
  "version": 1,
  "mappings": [
    {"subscription_id": "12312312-3123-4123-8123-123123123123", "upstream": "traefik:443", "http_challenge_upstream": "solver:80"},
    {"subscription_id": "45645645-6456-4456-8456-456456456456", "upstream": "[2001:db8::1]:8443"}
  ]
}`, 0o600)

	mappings, err := loadStaticConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 2 || mappings[0].SubscriptionID != testSubscriptionID123 || mappings[0].HTTPChallengeUpstream != "solver:80" || mappings[1].Upstream != "[2001:db8::1]:8443" {
		t.Fatalf("loadStaticConfig() = %+v", mappings)
	}
}

func TestLoadStaticConfigKeepsVersion1WithoutChallengeUpstreamCompatible(t *testing.T) {
	path := writeConfig(t, `{"version":1,"mappings":[{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"app:443"}]}`, 0o600)
	mappings, err := loadStaticConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 1 || mappings[0].HTTPChallengeUpstream != "" {
		t.Fatalf("legacy version-1 mapping = %+v", mappings)
	}
}

func TestLoadStaticConfigRejectsInvalidDocuments(t *testing.T) {
	tests := map[string]string{
		"unknown top-level field": `{"version":1,"mappings":[{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"app:80"}],"extra":true}`,
		"unknown mapping field":   `{"version":1,"mappings":[{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"app:80","extra":true}]}`,
		"unsupported version":     `{"version":3,"mappings":[{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"app:80"}]}`,
		"v2 missing TLS mode":     `{"version":2,"mappings":[{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"app:80"}]}`,
		"automatic without terms": `{"version":2,"mappings":[{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"app:80","tls_mode":"automatic"}]}`,
		"ambiguous automatic":     `{"version":2,"mappings":[{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"app:80","tls_mode":"automatic","acme_terms_accepted":true,"http_challenge_upstream":"solver:80"}]}`,
		"empty mappings":          `{"version":1,"mappings":[]}`,
		"malformed ID":            `{"version":1,"mappings":[{"subscription_id":"1","upstream":"app:80"}]}`,
		"noncanonical ID":         `{"version":1,"mappings":[{"subscription_id":"11111111-1111-4111-8111-11111111111A","upstream":"app:80"}]}`,
		"non-RFC variant ID":      `{"version":1,"mappings":[{"subscription_id":"11111111-1111-4111-0111-111111111111","upstream":"app:80"}]}`,
		"duplicate ID":            `{"version":1,"mappings":[{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"app:80"},{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"other:80"}]}`,
		"invalid upstream":        `{"version":1,"mappings":[{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"http://app:80"}]}`,
		"invalid challenge":       `{"version":1,"mappings":[{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"app:443","http_challenge_upstream":"http://app:80"}]}`,
		"trailing JSON":           `{"version":1,"mappings":[{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"app:80"}]} {}`,
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, document, 0o600)
			if _, err := loadStaticConfig(path); err == nil {
				t.Fatal("loadStaticConfig() succeeded, want error")
			}
		})
	}
}

func TestLoadStaticConfigVersion2TLSModes(t *testing.T) {
	path := writeConfig(t, `{"version":2,"mappings":[
{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"app:80","tls_mode":"automatic","acme_terms_accepted":true},
{"subscription_id":"22222222-2222-4222-8222-222222222222","upstream":"tls:443","tls_mode":"passthrough"}
]}`, 0o600)
	mappings, err := loadStaticConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 2 || mappings[0].TLSMode != tlsModeAutomatic || !mappings[0].ACMETermsAccepted || mappings[1].TLSMode != tlsModePassthrough {
		t.Fatalf("version 2 mappings = %+v", mappings)
	}
}

func TestLoadStaticConfigRejectsUnsafeFiles(t *testing.T) {
	t.Run("group writable", func(t *testing.T) {
		path := writeConfig(t, `{"version":1,"mappings":[{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"app:80"}]}`, 0o620)
		if _, err := loadStaticConfig(path); err == nil || !strings.Contains(err.Error(), "writable by group") {
			t.Fatalf("loadStaticConfig() error = %v", err)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		path := writeConfig(t, strings.Repeat(" ", maxConfigSize+1), 0o600)
		if _, err := loadStaticConfig(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("loadStaticConfig() error = %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		target := writeConfig(t, `{"version":1,"mappings":[{"subscription_id":"11111111-1111-4111-8111-111111111111","upstream":"app:80"}]}`, 0o600)
		link := filepath.Join(t.TempDir(), "config-link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := loadStaticConfig(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("loadStaticConfig() error = %v", err)
		}
	})
}

func TestValidateHostPort(t *testing.T) {
	valid := []string{"traefik:443", "app.internal:8080", "127.0.0.1:80", "[2001:db8::1]:443"}
	for _, value := range valid {
		if err := validateHostPort(value); err != nil {
			t.Errorf("validateHostPort(%q) = %v", value, err)
		}
	}
	invalid := []string{"", "traefik", "http://traefik:443", ":443", "bad_host:80", "app:0", "app:080", "2001:db8::1:443"}
	for _, value := range invalid {
		if err := validateHostPort(value); err == nil {
			t.Errorf("validateHostPort(%q) succeeded", value)
		}
	}
}

func TestBuildMappingPlansExpandsOneMappingAcrossRelayEndpoints(t *testing.T) {
	mappings := []mapping{{SubscriptionID: testSubscriptionID123, Upstream: "traefik:443", HTTPChallengeUpstream: "solver:80"}}
	cfg := []provisioning{{
		SubscriptionID: testSubscriptionID123,
		Product:        "relay",
		Domain:         "service.example",
		RelayEndpoint:  "edge-b.example:5443",
		RelayEndpoints: []string{"edge-b.example:5443", "edge-a.example:5443", "edge-b.example:5443"},
	}}

	plans, err := buildMappingPlans(mappings, cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 2 {
		t.Fatalf("len(plans) = %d, want 2: %+v", len(plans), plans)
	}
	if plans[0].RelayAddr != "edge-a.example:5443" || plans[1].RelayAddr != "edge-b.example:5443" {
		t.Fatalf("plan relays = %q, %q", plans[0].RelayAddr, plans[1].RelayAddr)
	}
	if plans[0].Claim == plans[1].Claim {
		t.Fatal("plans share a mutable claim pointer")
	}
	if plans[0].Claim.Domain != "service.example" || plans[0].Upstream != "traefik:443" || plans[0].HTTPChallengeUpstream != "solver:80" {
		t.Fatalf("plan = %+v", plans[0])
	}
}

func TestBuildMappingPlansUsesPerEdgePortClaims(t *testing.T) {
	mappings := []mapping{{SubscriptionID: testSubscriptionID123, Upstream: "app:8080"}}
	cfg := []provisioning{{
		SubscriptionID: testSubscriptionID123,
		Product:        "port",
		AssignedIP:     "203.0.113.20",
		AssignedPort:   10000,
		Transport:      "tcp",
		RelayEndpoint:  "primary.example:5443",
		RelayEndpoints: []string{"primary.example:5443"},
		RelayAssignments: []relayAssignment{
			{RelayEndpoint: "primary.example:5443", AssignedIP: "203.0.113.20"},
			{RelayEndpoint: "secondary.example:5443", AssignedIP: "203.0.113.21"},
		},
	}}

	plans, err := buildMappingPlans(mappings, cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 2 {
		t.Fatalf("len(plans) = %d, want 2: %+v", len(plans), plans)
	}
	if plans[0].RelayAddr != "primary.example:5443" || plans[0].Claim.IP != "203.0.113.20" {
		t.Fatalf("primary plan = %+v", plans[0])
	}
	if plans[1].RelayAddr != "secondary.example:5443" || plans[1].Claim.IP != "203.0.113.21" {
		t.Fatalf("secondary plan = %+v", plans[1])
	}
}

func TestBuildMappingPlansMatchesOverrideToEdgeClaim(t *testing.T) {
	mappings := []mapping{{SubscriptionID: testSubscriptionID123, Upstream: "app:8080"}}
	cfg := []provisioning{{
		SubscriptionID: testSubscriptionID123,
		Product:        "port",
		AssignedIP:     "203.0.113.20",
		AssignedPort:   10000,
		Transport:      "tcp",
		RelayAssignments: []relayAssignment{
			{RelayEndpoint: "primary.example:5443", AssignedIP: "203.0.113.20"},
			{RelayEndpoint: "secondary.example:5443", AssignedIP: "203.0.113.21"},
		},
	}}

	plans, err := buildMappingPlans(mappings, cfg, "secondary.example:5443")
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 || plans[0].Claim.IP != "203.0.113.21" {
		t.Fatalf("plans = %+v", plans)
	}
}

func TestBuildMappingPlansRejectsChallengeUpstreamForNonRelay(t *testing.T) {
	mappings := []mapping{{SubscriptionID: testSubscriptionID1, Upstream: "app:443", HTTPChallengeUpstream: "solver:80"}}
	cfg := []provisioning{{
		SubscriptionID: testSubscriptionID1, Product: "ip", AssignedIP: "203.0.113.10",
		RelayEndpoint: "relay.example:5443",
	}}
	if _, err := buildMappingPlans(mappings, cfg, ""); err == nil || !strings.Contains(err.Error(), "only valid for Blindport Relay") {
		t.Fatalf("buildMappingPlans() error = %v", err)
	}
}

func TestBuildMappingPlansRequiresActiveProvisioning(t *testing.T) {
	_, err := buildMappingPlans([]mapping{{SubscriptionID: testSubscriptionID99, Upstream: "app:80"}}, nil, "")
	if err == nil || !strings.Contains(err.Error(), "does not exist or is not active") {
		t.Fatalf("buildMappingPlans() error = %v", err)
	}
}

func TestBuildAvailableMappingPlansSkipsPendingSubscriptions(t *testing.T) {
	mappings := []mapping{
		{SubscriptionID: testSubscriptionID1, Upstream: "active:80"},
		{SubscriptionID: testSubscriptionID2, Upstream: "pending:80"},
	}
	cfg := []provisioning{{
		SubscriptionID: testSubscriptionID1, Product: "ip", AssignedIP: "203.0.113.10",
		RelayEndpoint: "relay.example:5443",
	}}
	plans, err := buildAvailableMappingPlans(mappings, cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 || plans[0].SubscriptionID != testSubscriptionID1 {
		t.Fatalf("plans = %+v", plans)
	}
}

func TestProvisioningEndpointsSupportsV0AndOverride(t *testing.T) {
	row := provisioning{RelayEndpoint: "legacy.example:5443"}
	got, err := provisioningEndpoints(row, "")
	if err != nil || len(got) != 1 || got[0] != "legacy.example:5443" {
		t.Fatalf("provisioningEndpoints() = %v, %v", got, err)
	}
	got, err = provisioningEndpoints(row, "override.example:5443")
	if err != nil || len(got) != 1 || got[0] != "override.example:5443" {
		t.Fatalf("provisioningEndpoints(override) = %v, %v", got, err)
	}
}
