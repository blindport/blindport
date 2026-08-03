package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	containertypes "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

type fakeDockerClient struct {
	containers []containertypes.Summary
	err        error
	options    client.ContainerListOptions
	wait       bool
}

func (f *fakeDockerClient) ContainerList(ctx context.Context, options client.ContainerListOptions) (client.ContainerListResult, error) {
	f.options = options
	if f.wait {
		<-ctx.Done()
		return client.ContainerListResult{}, ctx.Err()
	}
	return client.ContainerListResult{Items: f.containers}, f.err
}

func TestValidateDockerHostAllowsOnlyAbsoluteLocalUnixSockets(t *testing.T) {
	if err := validateDockerHost("unix:///var/run/docker.sock"); err != nil {
		t.Fatal(err)
	}
	dockerClient, err := newDockerClient("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer dockerClient.Close()
	invalid := []string{
		"", "unix://", "unix://docker/var/run/docker.sock", "unix://relative.sock",
		"unix:///", "unix:////var/run/docker.sock", "unix:///var/../run/docker.sock",
		"unix:///var/run/docker%2Esock", "unix:///var/run/docker.sock?x=1",
		"tcp://127.0.0.1:2375", "http://127.0.0.1", "ssh://host", "npipe:////./pipe/docker_engine",
	}
	for _, host := range invalid {
		t.Run(host, func(t *testing.T) {
			if _, err := newDockerClient(host); err == nil {
				t.Fatalf("newDockerClient(%q) succeeded", host)
			}
		})
	}
}

func TestDiscoverDockerMappingsTimeout(t *testing.T) {
	fake := &fakeDockerClient{wait: true}
	started := time.Now()
	_, err := discoverDockerMappingsWithin(context.Background(), fake, 25*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("discoverDockerMappingsWithin() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("discovery timeout took %s", elapsed)
	}
}

func TestDiscoverDockerMappings(t *testing.T) {
	fake := &fakeDockerClient{containers: []containertypes.Summary{
		{ID: "bbbbbbbbbbbbbbbb", Labels: map[string]string{
			"unrelated": "ignored",
			"tech.blindport.mapping.web.subscription":            "20",
			"tech.blindport.mapping.web.upstream":                "web:443",
			"tech.blindport.mapping.web.http_challenge_upstream": "solver:80",
		}},
		{ID: "aaaaaaaaaaaaaaaa", Labels: map[string]string{
			"tech.blindport.mapping.admin.subscription": "10",
			"tech.blindport.mapping.admin.upstream":     "admin:8443",
			"tech.blindport.mapping.api.subscription":   "11",
			"tech.blindport.mapping.api.upstream":       "api:8080",
		}},
		{ID: "cccccccccccccccc", Labels: map[string]string{"other": "label"}},
	}}

	got, err := discoverDockerMappings(context.Background(), fake)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].SubscriptionID != 10 || got[1].SubscriptionID != 11 || got[2].SubscriptionID != 20 {
		t.Fatalf("discoverDockerMappings() = %+v", got)
	}
	if fake.options.All {
		t.Fatal("ContainerList requested stopped containers")
	}
	if got[2].HTTPChallengeUpstream != "solver:80" {
		t.Fatalf("HTTP challenge upstream = %q", got[2].HTTPChallengeUpstream)
	}
}

func TestParseDockerOrderLabelsDefaultsAndFields(t *testing.T) {
	mappings, err := parseDockerLabels("container-id", map[string]string{
		dockerMappingPrefix + "web.product":                 "relay",
		dockerMappingPrefix + "web.domain":                  "web.example",
		dockerMappingPrefix + "web.upstream":                "web:443",
		dockerMappingPrefix + "web.http_challenge_upstream": "solver:80",
		dockerMappingPrefix + "datagrams.product":           "port",
		dockerMappingPrefix + "datagrams.transport":         "udp",
		dockerMappingPrefix + "datagrams.billing_term":      "yearly",
		dockerMappingPrefix + "datagrams.upstream":          "collector:9000",
		dockerMappingPrefix + "framed-address.product":      "ip",
		dockerMappingPrefix + "framed-address.upstream":     "gateway:8080",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 3 {
		t.Fatalf("len(mappings) = %d, want 3", len(mappings))
	}
	byKey := make(map[string]mapping)
	for _, item := range mappings {
		byKey[item.OrderKey] = item
	}
	web := byKey["web"]
	if web.Product != "relay" || web.Domain != "web.example" || web.Transport != "tcp" || web.BillingTerm != "monthly" || web.HTTPChallengeUpstream != "solver:80" {
		t.Fatalf("relay declaration = %+v", web)
	}
	port := byKey["datagrams"]
	if port.Product != "port" || port.Transport != "udp" || port.BillingTerm != "yearly" {
		t.Fatalf("port declaration = %+v", port)
	}
	ip := byKey["framed-address"]
	if ip.Product != "ip" || ip.Transport != "tcp" || ip.BillingTerm != "monthly" {
		t.Fatalf("IP declaration = %+v", ip)
	}
}

func TestParseDockerLabelsRejectsIncompleteUnsafeAndUnknownLabels(t *testing.T) {
	tests := map[string]map[string]string{
		"incomplete": {
			"tech.blindport.mapping.web.subscription": "1",
		},
		"unsafe name": {
			"tech.blindport.mapping.Web.subscription": "1",
			"tech.blindport.mapping.Web.upstream":     "web:80",
		},
		"unknown field": {
			"tech.blindport.mapping.web.target": "web:80",
		},
		"bad subscription": {
			"tech.blindport.mapping.web.subscription": "01",
			"tech.blindport.mapping.web.upstream":     "web:80",
		},
		"bad upstream": {
			"tech.blindport.mapping.web.subscription": "1",
			"tech.blindport.mapping.web.upstream":     "http://web:80",
		},
		"bad challenge upstream": {
			"tech.blindport.mapping.web.subscription":            "1",
			"tech.blindport.mapping.web.upstream":                "web:443",
			"tech.blindport.mapping.web.http_challenge_upstream": "http://solver:80",
		},
		"subscription and product": {
			"tech.blindport.mapping.web.subscription": "1",
			"tech.blindport.mapping.web.product":      "relay",
			"tech.blindport.mapping.web.domain":       "web.example",
			"tech.blindport.mapping.web.upstream":     "web:443",
		},
		"relay without domain": {
			"tech.blindport.mapping.web.product":  "relay",
			"tech.blindport.mapping.web.upstream": "web:443",
		},
		"invalid relay domain": {
			"tech.blindport.mapping.web.product":  "relay",
			"tech.blindport.mapping.web.domain":   "Not Canonical.example",
			"tech.blindport.mapping.web.upstream": "web:443",
		},
		"domain on port": {
			"tech.blindport.mapping.web.product":  "port",
			"tech.blindport.mapping.web.domain":   "web.example",
			"tech.blindport.mapping.web.upstream": "web:443",
		},
		"udp relay": {
			"tech.blindport.mapping.web.product":   "relay",
			"tech.blindport.mapping.web.domain":    "web.example",
			"tech.blindport.mapping.web.transport": "udp",
			"tech.blindport.mapping.web.upstream":  "web:443",
		},
		"unknown product": {
			"tech.blindport.mapping.web.product":  "other",
			"tech.blindport.mapping.web.upstream": "web:443",
		},
		"unknown transport": {
			"tech.blindport.mapping.web.product":   "port",
			"tech.blindport.mapping.web.transport": "sctp",
			"tech.blindport.mapping.web.upstream":  "web:443",
		},
		"unknown billing term": {
			"tech.blindport.mapping.web.product":      "ip",
			"tech.blindport.mapping.web.billing_term": "weekly",
			"tech.blindport.mapping.web.upstream":     "web:443",
		},
		"challenge on ip": {
			"tech.blindport.mapping.web.product":                 "ip",
			"tech.blindport.mapping.web.upstream":                "web:443",
			"tech.blindport.mapping.web.http_challenge_upstream": "solver:80",
		},
	}
	for name, labels := range tests {
		t.Run(name, func(t *testing.T) {
			mappings, err := parseDockerLabels("container-id", labels)
			if err == nil {
				err = validateMappings(mappings)
			}
			if err == nil {
				t.Fatal("labels accepted, want error")
			}
		})
	}
}

func TestDiscoverDockerMappingsCoalescesIdenticalRollingDeclarations(t *testing.T) {
	labels := map[string]string{
		dockerMappingPrefix + "web.product":  "relay",
		dockerMappingPrefix + "web.domain":   "web.example",
		dockerMappingPrefix + "web.upstream": "web:443",
	}
	fake := &fakeDockerClient{containers: []containertypes.Summary{
		{ID: "old", Labels: labels},
		{ID: "new", Labels: labels},
	}}
	mappings, err := discoverDockerMappings(context.Background(), fake)
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 1 || mappings[0].OrderKey != "web" {
		t.Fatalf("rolling declarations = %+v", mappings)
	}
}

func TestDiscoverDockerMappingsRejectsConflictingRollingDeclarations(t *testing.T) {
	fake := &fakeDockerClient{containers: []containertypes.Summary{
		{ID: "old", Labels: map[string]string{
			dockerMappingPrefix + "web.product":  "relay",
			dockerMappingPrefix + "web.domain":   "web.example",
			dockerMappingPrefix + "web.upstream": "old:443",
		}},
		{ID: "new", Labels: map[string]string{
			dockerMappingPrefix + "web.product":  "relay",
			dockerMappingPrefix + "web.domain":   "web.example",
			dockerMappingPrefix + "web.upstream": "new:443",
		}},
	}}
	_, err := discoverDockerMappings(context.Background(), fake)
	if err == nil || !strings.Contains(err.Error(), "conflicting Docker declarations") {
		t.Fatalf("discoverDockerMappings() error = %v", err)
	}
}

func TestValidateDockerPollIntervalBounds(t *testing.T) {
	for _, interval := range []time.Duration{time.Second, 10 * time.Second, 5 * time.Minute} {
		if err := validateDockerPollInterval(interval); err != nil {
			t.Errorf("validateDockerPollInterval(%s) = %v", interval, err)
		}
	}
	for _, interval := range []time.Duration{0, time.Second - 1, 5*time.Minute + 1} {
		if err := validateDockerPollInterval(interval); err == nil {
			t.Errorf("validateDockerPollInterval(%s) succeeded", interval)
		}
	}
}

func TestDiscoverDockerMappingsRejectsDuplicateSubscriptionsAcrossContainers(t *testing.T) {
	fake := &fakeDockerClient{containers: []containertypes.Summary{
		{ID: "a", Labels: dockerLabels("first", "42", "one:80")},
		{ID: "b", Labels: dockerLabels("second", "42", "two:80")},
	}}
	_, err := discoverDockerMappings(context.Background(), fake)
	if err == nil || !strings.Contains(err.Error(), "duplicate subscription_id 42") {
		t.Fatalf("discoverDockerMappings() error = %v", err)
	}
}

func TestValidateMappingsRejectsStaticDockerDuplicate(t *testing.T) {
	mappings := []mapping{
		{SubscriptionID: 42, Upstream: "static:80", Source: "static config"},
		{SubscriptionID: 42, Upstream: "docker:80", Source: "container abc mapping web"},
	}
	if err := validateMappings(mappings); err == nil || !strings.Contains(err.Error(), "static config") || !strings.Contains(err.Error(), "container abc") {
		t.Fatalf("validateMappings() error = %v", err)
	}
}

func dockerLabels(name, subscription, upstream string) map[string]string {
	return map[string]string{
		dockerMappingPrefix + name + ".subscription": subscription,
		dockerMappingPrefix + name + ".upstream":     upstream,
	}
}
