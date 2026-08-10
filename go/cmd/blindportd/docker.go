package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blindport/blindport/internal/protocol"
	"github.com/moby/moby/client"
)

const (
	dockerMappingPrefix    = "tech.blindport.mapping."
	dockerDiscoveryTimeout = 10 * time.Second
)

var dockerMappingName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]{0,62})$`)

type dockerContainerLister interface {
	ContainerList(context.Context, client.ContainerListOptions) (client.ContainerListResult, error)
}

type dockerAccountScope struct {
	allowed map[string]struct{}
}

type dockerMappingDiscovery interface {
	discover(context.Context) ([]mapping, error)
}

type sharedDockerDiscovery struct {
	docker       dockerContainerLister
	accountNames []string
	static       []mapping
	interval     time.Duration
	now          func() time.Time

	mu         sync.Mutex
	validUntil time.Time
	snapshot   []mapping
	err        error
}

func newSharedDockerDiscovery(docker dockerContainerLister, accounts []staticAccount, interval time.Duration) (*sharedDockerDiscovery, error) {
	if docker == nil || validateDockerPollInterval(interval) != nil {
		return nil, errors.New("invalid shared Docker discovery configuration")
	}
	accountNames := make([]string, len(accounts))
	var static []mapping
	for index, account := range accounts {
		accountNames[index] = account.Name
		static = append(static, account.Mappings...)
	}
	if _, err := newDockerAccountScope(accountNames); err != nil {
		return nil, err
	}
	return &sharedDockerDiscovery{
		docker: docker, accountNames: accountNames, static: append([]mapping(nil), static...),
		interval: interval, now: time.Now,
	}, nil
}

func (d *sharedDockerDiscovery) discover(ctx context.Context) ([]mapping, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if d.validUntil.IsZero() || !now.Before(d.validUntil) {
		d.snapshot, d.err = discoverDockerMappingsForAccounts(ctx, d.docker, d.accountNames)
		if d.err == nil {
			d.err = validateDockerSnapshot(d.static, d.snapshot)
		}
		d.validUntil = d.now().Add(d.interval)
	}
	return append([]mapping(nil), d.snapshot...), d.err
}

func discoverDockerMappings(ctx context.Context, dockerClient dockerContainerLister) ([]mapping, error) {
	return discoverDockerMappingsWithinScope(ctx, dockerClient, dockerDiscoveryTimeout, nil)
}

func discoverDockerMappingsWithin(ctx context.Context, dockerClient dockerContainerLister, timeout time.Duration) ([]mapping, error) {
	return discoverDockerMappingsWithinScope(ctx, dockerClient, timeout, nil)
}

func discoverDockerMappingsForAccounts(ctx context.Context, dockerClient dockerContainerLister, accountNames []string) ([]mapping, error) {
	scope, err := newDockerAccountScope(accountNames)
	if err != nil {
		return nil, err
	}
	return discoverDockerMappingsWithinScope(ctx, dockerClient, dockerDiscoveryTimeout, scope)
}

func discoverDockerMappingsWithinScope(ctx context.Context, dockerClient dockerContainerLister, timeout time.Duration, scope *dockerAccountScope) ([]mapping, error) {
	discoveryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := dockerClient.ContainerList(discoveryCtx, client.ContainerListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list running Docker containers: %w", err)
	}
	containers := append(result.Items[:0:0], result.Items...)
	sort.Slice(containers, func(i, j int) bool { return containers[i].ID < containers[j].ID })
	var mappings []mapping
	for _, container := range containers {
		parsed, err := parseDockerLabelsWithinScope(container.ID, container.Labels, scope)
		if err != nil {
			return nil, err
		}
		mappings = append(mappings, parsed...)
	}
	mappings, err = normalizeDockerMappings(mappings)
	if err != nil {
		return nil, err
	}
	return mappings, nil
}

func newDockerAccountScope(accountNames []string) (*dockerAccountScope, error) {
	if len(accountNames) == 0 || len(accountNames) > maxStaticAccounts {
		return nil, errors.New("Docker account names are required")
	}
	allowed := make(map[string]struct{}, len(accountNames))
	for _, name := range accountNames {
		if !staticAccountName.MatchString(name) {
			return nil, fmt.Errorf("invalid Docker account name %q", name)
		}
		if _, duplicate := allowed[name]; duplicate {
			return nil, fmt.Errorf("duplicate Docker account name %q", name)
		}
		allowed[name] = struct{}{}
	}
	return &dockerAccountScope{allowed: allowed}, nil
}

func newDockerClient(host string) (*client.Client, error) {
	if err := validateDockerHost(host); err != nil {
		return nil, err
	}
	return client.New(
		client.WithHost(host),
		client.WithTimeout(dockerDiscoveryTimeout),
	)
}

func validateDockerHost(host string) error {
	u, err := url.Parse(host)
	if err != nil {
		return fmt.Errorf("invalid Docker host: %w", err)
	}
	if u.Scheme != "unix" || u.Host != "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("Docker host must be an absolute local unix:// socket URL")
	}
	if u.RawPath != "" || !path.IsAbs(u.Path) || u.Path == "/" || path.Clean(u.Path) != u.Path || !strings.HasPrefix(host, "unix:///") {
		return fmt.Errorf("Docker host must contain a canonical absolute socket path")
	}
	return nil
}

func parseDockerLabels(containerID string, labels map[string]string) ([]mapping, error) {
	return parseDockerLabelsWithinScope(containerID, labels, nil)
}

func parseDockerLabelsWithinScope(containerID string, labels map[string]string, scope *dockerAccountScope) ([]mapping, error) {
	type labelPair struct {
		account       string
		subscription  string
		product       string
		domain        string
		transport     string
		billingTerm   string
		upstream      string
		httpChallenge string
		tlsMode       string
		acmeTerms     string
		hasSub        bool
		hasAccount    bool
		hasProduct    bool
		hasDomain     bool
		hasTransport  bool
		hasBilling    bool
		hasUpstream   bool
	}
	pairs := make(map[string]labelPair)
	for key, value := range labels {
		if !strings.HasPrefix(key, dockerMappingPrefix) {
			continue
		}
		remainder := strings.TrimPrefix(key, dockerMappingPrefix)
		separator := strings.LastIndexByte(remainder, '.')
		if separator <= 0 {
			return nil, fmt.Errorf("container %s has malformed Blindport label %q", shortContainerID(containerID), key)
		}
		name, field := remainder[:separator], remainder[separator+1:]
		if !dockerMappingName.MatchString(name) {
			return nil, fmt.Errorf("container %s has unsafe mapping name %q", shortContainerID(containerID), name)
		}
		pair := pairs[name]
		switch field {
		case "account":
			pair.account, pair.hasAccount = value, true
		case "subscription":
			pair.subscription, pair.hasSub = value, true
		case "product":
			pair.product, pair.hasProduct = value, true
		case "domain":
			pair.domain, pair.hasDomain = value, true
		case "transport":
			pair.transport, pair.hasTransport = value, true
		case "billing_term":
			pair.billingTerm, pair.hasBilling = value, true
		case "upstream":
			pair.upstream, pair.hasUpstream = value, true
		case "http_challenge_upstream":
			pair.httpChallenge = value
		case "tls_mode":
			pair.tlsMode = value
		case "acme_terms_accepted":
			pair.acmeTerms = value
		default:
			return nil, fmt.Errorf("container %s has unknown Blindport mapping field %q", shortContainerID(containerID), field)
		}
		pairs[name] = pair
	}

	names := make([]string, 0, len(pairs))
	for name := range pairs {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]mapping, 0, len(names))
	for _, name := range names {
		pair := pairs[name]
		if scope == nil {
			if pair.hasAccount {
				return nil, fmt.Errorf("container %s mapping %q: account requires config version 3 Docker discovery", shortContainerID(containerID), name)
			}
		} else {
			if !pair.hasAccount {
				return nil, fmt.Errorf("container %s mapping %q requires an account label", shortContainerID(containerID), name)
			}
			if _, allowed := scope.allowed[pair.account]; !allowed {
				return nil, fmt.Errorf("container %s mapping %q selects unknown account %q", shortContainerID(containerID), name, pair.account)
			}
		}
		if pair.hasSub == pair.hasProduct {
			return nil, fmt.Errorf("container %s mapping %q requires exactly one of subscription or product", shortContainerID(containerID), name)
		}
		if !pair.hasUpstream {
			return nil, fmt.Errorf("container %s mapping %q requires an upstream label", shortContainerID(containerID), name)
		}
		item := mapping{
			AccountName:           pair.account,
			OrderKey:              name,
			Upstream:              pair.upstream,
			HTTPChallengeUpstream: pair.httpChallenge,
			TLSMode:               pair.tlsMode,
			Source:                fmt.Sprintf("container %s mapping %q", shortContainerID(containerID), name),
		}
		switch pair.acmeTerms {
		case "":
		case "true":
			item.ACMETermsAccepted = true
		case "false":
		default:
			return nil, fmt.Errorf("%s: acme_terms_accepted must be true or false", item.Source)
		}
		if pair.hasSub {
			if pair.hasDomain || pair.hasTransport || pair.hasBilling {
				return nil, fmt.Errorf("%s: domain, transport, and billing_term require a product declaration", item.Source)
			}
			if err := validateSubscriptionID(pair.subscription); err != nil {
				return nil, fmt.Errorf("container %s mapping %q has invalid subscription ID %q", shortContainerID(containerID), name, pair.subscription)
			}
			item.SubscriptionID = pair.subscription
		} else {
			item.Product = pair.product
			item.Domain = pair.domain
			item.Transport = pair.transport
			item.BillingTerm = pair.billingTerm
			if item.Transport == "" {
				item.Transport = "tcp"
			}
			if item.BillingTerm == "" {
				item.BillingTerm = "monthly"
			}
		}
		result = append(result, item)
	}
	if _, err := normalizeDockerMappings(result); err != nil {
		return nil, err
	}
	return result, nil
}

func normalizeDockerMappings(mappings []mapping) ([]mapping, error) {
	legacy := make([]mapping, 0, len(mappings))
	declarations := make(map[string]mapping)
	result := make([]mapping, 0, len(mappings))
	for _, item := range mappings {
		if item.Product == "" {
			legacy = append(legacy, item)
			result = append(result, item)
			continue
		}
		if err := validateOrderDeclaration(item); err != nil {
			return nil, err
		}
		declarationKey := item.AccountName + "\x00" + item.OrderKey
		if previous, ok := declarations[declarationKey]; ok {
			if !sameOrderDeclaration(previous, item) {
				return nil, fmt.Errorf("conflicting Docker declarations for order key %q in %s and %s", item.OrderKey, previous.Source, item.Source)
			}
			continue
		}
		declarations[declarationKey] = item
		result = append(result, item)
	}
	if err := validateMappings(legacy); err != nil {
		return nil, err
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].AccountName != result[j].AccountName {
			return result[i].AccountName < result[j].AccountName
		}
		if result[i].OrderKey != result[j].OrderKey {
			return result[i].OrderKey < result[j].OrderKey
		}
		return result[i].SubscriptionID < result[j].SubscriptionID
	})
	return result, nil
}

func validateOrderDeclaration(item mapping) error {
	if item.OrderKey == "" || !dockerMappingName.MatchString(item.OrderKey) {
		return fmt.Errorf("%s: invalid order key %q", item.Source, item.OrderKey)
	}
	if item.SubscriptionID != "" {
		return fmt.Errorf("%s: subscription and product are mutually exclusive", item.Source)
	}
	if err := validateHostPort(item.Upstream); err != nil {
		return fmt.Errorf("%s: invalid upstream: %w", item.Source, err)
	}
	if item.Product == "ip" {
		return fmt.Errorf("%s: product ip is not supported for Docker orders because routed WireGuard has no upstream mapping", item.Source)
	}
	if err := validateTLSMapping(item, item.Source); err != nil {
		return err
	}
	switch item.Product {
	case "relay":
		if item.Domain == "" || item.Domain != strings.TrimSpace(item.Domain) {
			return fmt.Errorf("%s: relay product requires a non-empty domain without surrounding whitespace", item.Source)
		}
		if err := protocol.ValidateClaim(&protocol.Claim{Kind: protocol.ClaimRelay, Domain: item.Domain}); err != nil {
			return fmt.Errorf("%s: invalid relay domain: %w", item.Source, err)
		}
	case "port":
		if item.TLSMode == tlsModeAutomatic {
			return fmt.Errorf("%s: automatic TLS is only valid for relay", item.Source)
		}
		if item.Domain != "" {
			return fmt.Errorf("%s: domain is only valid for relay", item.Source)
		}
	default:
		return fmt.Errorf("%s: product must be relay or port", item.Source)
	}
	if item.Transport != "tcp" && item.Transport != "udp" {
		return fmt.Errorf("%s: transport must be tcp or udp", item.Source)
	}
	if item.Transport == "udp" && item.Product != "port" {
		return fmt.Errorf("%s: UDP transport is only valid for port", item.Source)
	}
	if item.BillingTerm != "monthly" && item.BillingTerm != "yearly" {
		return fmt.Errorf("%s: billing_term must be monthly or yearly", item.Source)
	}
	if item.HTTPChallengeUpstream != "" {
		if item.Product != "relay" {
			return fmt.Errorf("%s: http_challenge_upstream is only valid for relay", item.Source)
		}
		if err := validateHostPort(item.HTTPChallengeUpstream); err != nil {
			return fmt.Errorf("%s: invalid http_challenge_upstream: %w", item.Source, err)
		}
	}
	return nil
}

func sameOrderDeclaration(a, b mapping) bool {
	return a.AccountName == b.AccountName && a.OrderKey == b.OrderKey && a.Product == b.Product && a.Domain == b.Domain &&
		a.Transport == b.Transport && a.BillingTerm == b.BillingTerm && a.Upstream == b.Upstream &&
		a.HTTPChallengeUpstream == b.HTTPChallengeUpstream && a.TLSMode == b.TLSMode &&
		a.ACMETermsAccepted == b.ACMETermsAccepted
}

func dockerMappingsForAccount(mappings []mapping, accountName string) []mapping {
	selected := make([]mapping, 0, len(mappings))
	for _, item := range mappings {
		if item.AccountName == accountName {
			selected = append(selected, item)
		}
	}
	return selected
}

func validateDockerSnapshot(static, docker []mapping) error {
	legacy := append([]mapping(nil), static...)
	for _, item := range docker {
		if item.Product == "" {
			legacy = append(legacy, item)
		}
	}
	if err := validateMappings(legacy); err != nil {
		return err
	}
	for _, item := range docker {
		if item.Product != "" {
			if err := validateOrderDeclaration(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateDockerPollInterval(interval time.Duration) error {
	if interval < time.Second || interval > 5*time.Minute {
		return errors.New("Docker poll interval must be between 1s and 5m")
	}
	return nil
}

func shortContainerID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	if id == "" {
		return "<unknown>"
	}
	return id
}
