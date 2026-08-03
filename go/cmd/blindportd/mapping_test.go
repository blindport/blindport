package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
    {"subscription_id": 123, "upstream": "traefik:443", "http_challenge_upstream": "solver:80"},
    {"subscription_id": 456, "upstream": "[2001:db8::1]:8443"}
  ]
}`, 0o600)

	mappings, err := loadStaticConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 2 || mappings[0].SubscriptionID != 123 || mappings[0].HTTPChallengeUpstream != "solver:80" || mappings[1].Upstream != "[2001:db8::1]:8443" {
		t.Fatalf("loadStaticConfig() = %+v", mappings)
	}
}

func TestLoadStaticConfigKeepsVersion1WithoutChallengeUpstreamCompatible(t *testing.T) {
	path := writeConfig(t, `{"version":1,"mappings":[{"subscription_id":1,"upstream":"app:443"}]}`, 0o600)
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
		"unknown top-level field": `{"version":1,"mappings":[{"subscription_id":1,"upstream":"app:80"}],"extra":true}`,
		"unknown mapping field":   `{"version":1,"mappings":[{"subscription_id":1,"upstream":"app:80","extra":true}]}`,
		"unsupported version":     `{"version":2,"mappings":[{"subscription_id":1,"upstream":"app:80"}]}`,
		"empty mappings":          `{"version":1,"mappings":[]}`,
		"nonpositive ID":          `{"version":1,"mappings":[{"subscription_id":0,"upstream":"app:80"}]}`,
		"duplicate ID":            `{"version":1,"mappings":[{"subscription_id":1,"upstream":"app:80"},{"subscription_id":1,"upstream":"other:80"}]}`,
		"invalid upstream":        `{"version":1,"mappings":[{"subscription_id":1,"upstream":"http://app:80"}]}`,
		"invalid challenge":       `{"version":1,"mappings":[{"subscription_id":1,"upstream":"app:443","http_challenge_upstream":"http://app:80"}]}`,
		"trailing JSON":           `{"version":1,"mappings":[{"subscription_id":1,"upstream":"app:80"}]} {}`,
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

func TestLoadStaticConfigRejectsUnsafeFiles(t *testing.T) {
	t.Run("group writable", func(t *testing.T) {
		path := writeConfig(t, `{"version":1,"mappings":[{"subscription_id":1,"upstream":"app:80"}]}`, 0o620)
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
		target := writeConfig(t, `{"version":1,"mappings":[{"subscription_id":1,"upstream":"app:80"}]}`, 0o600)
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
	mappings := []mapping{{SubscriptionID: 123, Upstream: "traefik:443", HTTPChallengeUpstream: "solver:80"}}
	cfg := []provisioning{{
		SubscriptionID: 123,
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

func TestBuildMappingPlansRejectsChallengeUpstreamForNonRelay(t *testing.T) {
	mappings := []mapping{{SubscriptionID: 1, Upstream: "app:443", HTTPChallengeUpstream: "solver:80"}}
	cfg := []provisioning{{
		SubscriptionID: 1, Product: "ip", AssignedIP: "203.0.113.10",
		RelayEndpoint: "relay.example:5443",
	}}
	if _, err := buildMappingPlans(mappings, cfg, ""); err == nil || !strings.Contains(err.Error(), "only valid for Blindport Relay") {
		t.Fatalf("buildMappingPlans() error = %v", err)
	}
}

func TestBuildMappingPlansRequiresActiveProvisioning(t *testing.T) {
	_, err := buildMappingPlans([]mapping{{SubscriptionID: 99, Upstream: "app:80"}}, nil, "")
	if err == nil || !strings.Contains(err.Error(), "does not exist or is not active") {
		t.Fatalf("buildMappingPlans() error = %v", err)
	}
}

func TestBuildAvailableMappingPlansSkipsPendingSubscriptions(t *testing.T) {
	mappings := []mapping{
		{SubscriptionID: 1, Upstream: "active:80"},
		{SubscriptionID: 2, Upstream: "pending:80"},
	}
	cfg := []provisioning{{
		SubscriptionID: 1, Product: "ip", AssignedIP: "203.0.113.10",
		RelayEndpoint: "relay.example:5443",
	}}
	plans, err := buildAvailableMappingPlans(mappings, cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 || plans[0].SubscriptionID != 1 {
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
