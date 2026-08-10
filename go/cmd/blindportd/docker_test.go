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
	calls      int
}

func (f *fakeDockerClient) ContainerList(ctx context.Context, options client.ContainerListOptions) (client.ContainerListResult, error) {
	f.calls++
	f.options = options
	if f.wait {
		<-ctx.Done()
		return client.ContainerListResult{}, ctx.Err()
	}
	return client.ContainerListResult{Items: f.containers}, f.err
}

func TestSharedDockerDiscoveryCachesImmutableGloballyValidatedSnapshot(t *testing.T) {
	fake := &fakeDockerClient{containers: []containertypes.Summary{
		{ID: "public", Labels: accountOrderLabels("public", "web", "public:443")},
		{ID: "private", Labels: accountOrderLabels("private", "api", "private:443")},
	}}
	accounts := []staticAccount{
		{Name: "public", Mappings: []mapping{{AccountName: "public", SubscriptionID: testSubscriptionID1, Upstream: "static:80", Source: "public static"}}},
		{Name: "private"},
	}
	now := time.Unix(1_700_000_000, 0)
	discovery, err := newSharedDockerDiscovery(fake, accounts, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	discovery.now = func() time.Time { return now }
	first, err := discovery.discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first[0].Upstream = "mutated:443"
	second, err := discovery.discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls != 1 || len(second) != 2 || second[0].Upstream == "mutated:443" {
		t.Fatalf("cached snapshot/calls = %+v/%d", second, fake.calls)
	}
	now = now.Add(time.Second)
	if _, err := discovery.discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.calls != 2 {
		t.Fatalf("refresh calls = %d", fake.calls)
	}

	fake.containers = []containertypes.Summary{{ID: "private", Labels: map[string]string{
		dockerMappingPrefix + "existing.account":      "private",
		dockerMappingPrefix + "existing.subscription": testSubscriptionID1,
		dockerMappingPrefix + "existing.upstream":     "private:80",
	}}}
	now = now.Add(time.Second)
	if _, err := discovery.discover(context.Background()); err == nil || !strings.Contains(err.Error(), "duplicate subscription_id") {
		t.Fatalf("cross-account duplicate error = %v", err)
	}
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
			"tech.blindport.mapping.web.subscription":            testSubscriptionID20,
			"tech.blindport.mapping.web.upstream":                "web:443",
			"tech.blindport.mapping.web.http_challenge_upstream": "solver:80",
		}},
		{ID: "aaaaaaaaaaaaaaaa", Labels: map[string]string{
			"tech.blindport.mapping.admin.subscription": testSubscriptionID10,
			"tech.blindport.mapping.admin.upstream":     "admin:8443",
			"tech.blindport.mapping.api.subscription":   testSubscriptionID11,
			"tech.blindport.mapping.api.upstream":       "api:8080",
		}},
		{ID: "cccccccccccccccc", Labels: map[string]string{"other": "label"}},
	}}

	got, err := discoverDockerMappings(context.Background(), fake)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].SubscriptionID != testSubscriptionID10 || got[1].SubscriptionID != testSubscriptionID11 || got[2].SubscriptionID != testSubscriptionID20 {
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
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 2 {
		t.Fatalf("len(mappings) = %d, want 2", len(mappings))
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
}

func TestParseDockerLabelsRejectsIPOrderLocally(t *testing.T) {
	_, err := parseDockerLabels("container-id", map[string]string{
		dockerMappingPrefix + "address.product":  "ip",
		dockerMappingPrefix + "address.upstream": "gateway:8080",
	})
	if err == nil || !strings.Contains(err.Error(), "product ip is not supported for Docker orders") {
		t.Fatalf("IP order error = %v", err)
	}
}

func TestParseDockerLabelsRequiresConfiguredAccountInV3(t *testing.T) {
	scope, err := newDockerAccountScope([]string{"public", "private"})
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{
		dockerMappingPrefix + "web.account":  "public",
		dockerMappingPrefix + "web.product":  "relay",
		dockerMappingPrefix + "web.domain":   "web.example",
		dockerMappingPrefix + "web.upstream": "web:443",
	}
	mappings, err := parseDockerLabelsWithinScope("container-id", labels, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 1 || mappings[0].AccountName != "public" || mappings[0].OrderKey != "web" {
		t.Fatalf("account mapping = %+v", mappings)
	}
	if _, err := parseDockerLabels("container-id", labels); err == nil || !strings.Contains(err.Error(), "config version 3") {
		t.Fatalf("legacy account label error = %v", err)
	}
	delete(labels, dockerMappingPrefix+"web.account")
	if _, err := parseDockerLabelsWithinScope("container-id", labels, scope); err == nil || !strings.Contains(err.Error(), "requires an account") {
		t.Fatalf("missing account error = %v", err)
	}
	labels[dockerMappingPrefix+"web.account"] = "other"
	if _, err := parseDockerLabelsWithinScope("container-id", labels, scope); err == nil || !strings.Contains(err.Error(), `unknown account "other"`) {
		t.Fatalf("unknown account error = %v", err)
	}
}

func TestDiscoverDockerMappingsScopesSameOrderKeyByAccount(t *testing.T) {
	fake := &fakeDockerClient{containers: []containertypes.Summary{
		{ID: "public", Labels: accountOrderLabels("public", "web", "public:443")},
		{ID: "private", Labels: accountOrderLabels("private", "web", "private:443")},
	}}
	mappings, err := discoverDockerMappingsForAccounts(context.Background(), fake, []string{"public", "private"})
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 2 || mappings[0].AccountName != "private" || mappings[1].AccountName != "public" || mappings[0].OrderKey != "web" || mappings[1].OrderKey != "web" {
		t.Fatalf("account-scoped declarations = %+v", mappings)
	}
	if got := dockerMappingsForAccount(mappings, "public"); len(got) != 1 || got[0].Upstream != "public:443" {
		t.Fatalf("public declarations = %+v", got)
	}
}

func TestParseDockerAutomaticTLSLabels(t *testing.T) {
	mappings, err := parseDockerLabels("container-id", map[string]string{
		dockerMappingPrefix + "web.product":             "relay",
		dockerMappingPrefix + "web.domain":              "web.example",
		dockerMappingPrefix + "web.upstream":            "web:8080",
		dockerMappingPrefix + "web.tls_mode":            "automatic",
		dockerMappingPrefix + "web.acme_terms_accepted": "true",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 1 || mappings[0].TLSMode != tlsModeAutomatic || !mappings[0].ACMETermsAccepted {
		t.Fatalf("automatic TLS labels = %+v", mappings)
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
		"automatic TLS on port": {
			"tech.blindport.mapping.web.product":             "port",
			"tech.blindport.mapping.web.upstream":            "web:8080",
			"tech.blindport.mapping.web.tls_mode":            "automatic",
			"tech.blindport.mapping.web.acme_terms_accepted": "true",
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
		{ID: "a", Labels: dockerLabels("first", testSubscriptionID42, "one:80")},
		{ID: "b", Labels: dockerLabels("second", testSubscriptionID42, "two:80")},
	}}
	_, err := discoverDockerMappings(context.Background(), fake)
	if err == nil || !strings.Contains(err.Error(), "duplicate subscription_id "+testSubscriptionID42) {
		t.Fatalf("discoverDockerMappings() error = %v", err)
	}
}

func TestValidateMappingsRejectsStaticDockerDuplicate(t *testing.T) {
	mappings := []mapping{
		{SubscriptionID: testSubscriptionID42, Upstream: "static:80", Source: "static config"},
		{SubscriptionID: testSubscriptionID42, Upstream: "docker:80", Source: "container abc mapping web"},
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

func accountOrderLabels(account, name, upstream string) map[string]string {
	return map[string]string{
		dockerMappingPrefix + name + ".account":  account,
		dockerMappingPrefix + name + ".product":  "relay",
		dockerMappingPrefix + name + ".domain":   "web.example",
		dockerMappingPrefix + name + ".upstream": upstream,
	}
}
