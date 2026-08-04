package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/blindport/blindport/internal/protocol"
	"github.com/google/uuid"
)

const maxConfigSize = 1 << 20

type mapping struct {
	SubscriptionID        string `json:"subscription_id"`
	Upstream              string `json:"upstream"`
	HTTPChallengeUpstream string `json:"http_challenge_upstream,omitempty"`
	Source                string `json:"-"`
	OrderKey              string `json:"-"`
	Product               string `json:"-"`
	Domain                string `json:"-"`
	Transport             string `json:"-"`
	BillingTerm           string `json:"-"`
}

type staticConfig struct {
	Version  int       `json:"version"`
	Mappings []mapping `json:"mappings"`
}

type workerPlan struct {
	SubscriptionID        string
	RelayAddr             string
	Upstream              string
	HTTPChallengeUpstream string
	Claim                 *protocol.Claim
}

var upstreamHostnameLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func loadStaticConfig(path string) ([]mapping, error) {
	f, err := openStaticConfig(path)
	if err != nil {
		return nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened config %q: %w", path, err)
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("config %q must be a regular file", path)
	}
	if openedInfo.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("config %q must not be writable by group or others", path)
	}
	if err := validateStaticConfigOwner(openedInfo); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	if len(data) > maxConfigSize {
		return nil, fmt.Errorf("config %q exceeds %d bytes", path, maxConfigSize)
	}

	var cfg staticConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config %q: %w", path, err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return nil, fmt.Errorf("decode config %q: %w", path, err)
	}
	if cfg.Version != 1 {
		return nil, fmt.Errorf("config %q has unsupported version %d", path, cfg.Version)
	}
	if len(cfg.Mappings) == 0 {
		return nil, fmt.Errorf("config %q must contain at least one mapping", path)
	}
	for i := range cfg.Mappings {
		cfg.Mappings[i].Source = fmt.Sprintf("config %q mapping %d", path, i)
	}
	if err := validateMappings(cfg.Mappings); err != nil {
		return nil, err
	}
	return cfg.Mappings, nil
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values are not allowed")
	}
	return err
}

func validateMappings(mappings []mapping) error {
	seen := make(map[string]string, len(mappings))
	for i, item := range mappings {
		source := item.Source
		if source == "" {
			source = fmt.Sprintf("mapping %d", i)
		}
		if err := validateSubscriptionID(item.SubscriptionID); err != nil {
			return fmt.Errorf("%s: invalid subscription_id: %w", source, err)
		}
		if err := validateHostPort(item.Upstream); err != nil {
			return fmt.Errorf("%s: invalid upstream: %w", source, err)
		}
		if item.HTTPChallengeUpstream != "" {
			if err := validateHostPort(item.HTTPChallengeUpstream); err != nil {
				return fmt.Errorf("%s: invalid http_challenge_upstream: %w", source, err)
			}
		}
		if previous, ok := seen[item.SubscriptionID]; ok {
			return fmt.Errorf("duplicate subscription_id %s in %s and %s", item.SubscriptionID, previous, source)
		}
		seen[item.SubscriptionID] = source
	}
	return nil
}

func validateSubscriptionID(value string) error {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value {
		return errors.New("must be a canonical UUID")
	}
	if parsed.Version() != 4 {
		return errors.New("must be a UUIDv4")
	}
	if parsed.Variant() != uuid.RFC4122 {
		return errors.New("must use the RFC 4122 UUID variant")
	}
	return nil
}

func validateHostPort(value string) error {
	if value == "" || value != strings.TrimSpace(value) {
		return errors.New("must be a non-empty host:port without surrounding whitespace")
	}
	host, portRaw, err := net.SplitHostPort(value)
	if err != nil {
		return errors.New("must use host:port syntax (bracket IPv6 addresses)")
	}
	if host == "" {
		return errors.New("host is required")
	}
	if net.ParseIP(host) == nil {
		if len(host) > 253 {
			return errors.New("hostname is too long")
		}
		for _, label := range strings.Split(host, ".") {
			if !upstreamHostnameLabel.MatchString(label) {
				return errors.New("host must be an IP address or valid DNS hostname")
			}
		}
	}
	port, err := strconv.ParseUint(portRaw, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != portRaw {
		return errors.New("port must be a canonical integer in 1-65535")
	}
	return nil
}

func claimFromProvisioning(row provisioning) (*protocol.Claim, error) {
	claim := &protocol.Claim{Kind: protocol.ClaimKind(row.Product)}
	switch claim.Kind {
	case protocol.ClaimIP:
		claim.IP = row.AssignedIP
	case protocol.ClaimPort:
		claim.IP = row.AssignedIP
		claim.Port = row.AssignedPort
		claim.Transport = protocol.Transport(row.Transport)
	case protocol.ClaimRelay:
		claim.Domain = row.Domain
	}
	if err := protocol.ValidateClaim(claim); err != nil {
		return nil, fmt.Errorf("subscription %s has invalid provisioned claim: %w", row.SubscriptionID, err)
	}
	return claim, nil
}

func buildMappingPlans(mappings []mapping, cfg []provisioning, relayOverride string) ([]workerPlan, error) {
	return buildMappingPlansWithMissing(mappings, cfg, relayOverride, false)
}

func buildAvailableMappingPlans(mappings []mapping, cfg []provisioning, relayOverride string) ([]workerPlan, error) {
	return buildMappingPlansWithMissing(mappings, cfg, relayOverride, true)
}

func buildMappingPlansWithMissing(mappings []mapping, cfg []provisioning, relayOverride string, allowMissing bool) ([]workerPlan, error) {
	if err := validateMappings(mappings); err != nil {
		return nil, err
	}
	byID := make(map[string]provisioning, len(cfg))
	for _, row := range cfg {
		if err := validateSubscriptionID(row.SubscriptionID); err != nil {
			return nil, fmt.Errorf("provisioning has invalid subscription_id %q: %w", row.SubscriptionID, err)
		}
		if _, exists := byID[row.SubscriptionID]; exists {
			return nil, fmt.Errorf("provisioning has duplicate subscription_id %s", row.SubscriptionID)
		}
		byID[row.SubscriptionID] = row
	}
	plans := make([]workerPlan, 0, len(mappings))
	for _, item := range mappings {
		row, ok := byID[item.SubscriptionID]
		if !ok {
			if allowMissing {
				continue
			}
			return nil, fmt.Errorf("configured subscription %s does not exist or is not active", item.SubscriptionID)
		}
		claim, err := claimFromProvisioning(row)
		if err != nil {
			return nil, err
		}
		if item.HTTPChallengeUpstream != "" && claim.Kind != protocol.ClaimRelay {
			return nil, fmt.Errorf("subscription %s: http_challenge_upstream is only valid for Blindport Relay", item.SubscriptionID)
		}
		endpoints, err := provisioningEndpoints(row, relayOverride)
		if err != nil {
			return nil, fmt.Errorf("subscription %s: %w", item.SubscriptionID, err)
		}
		for _, endpoint := range endpoints {
			claimCopy := *claim
			plans = append(plans, workerPlan{
				SubscriptionID:        item.SubscriptionID,
				RelayAddr:             endpoint,
				Upstream:              item.Upstream,
				HTTPChallengeUpstream: item.HTTPChallengeUpstream,
				Claim:                 &claimCopy,
			})
		}
	}
	sort.SliceStable(plans, func(i, j int) bool {
		if plans[i].SubscriptionID != plans[j].SubscriptionID {
			return plans[i].SubscriptionID < plans[j].SubscriptionID
		}
		return plans[i].RelayAddr < plans[j].RelayAddr
	})
	return plans, nil
}

func provisioningEndpoints(row provisioning, relayOverride string) ([]string, error) {
	endpoints := row.RelayEndpoints
	if relayOverride != "" {
		endpoints = []string{relayOverride}
	} else if len(endpoints) == 0 && row.RelayEndpoint != "" {
		endpoints = []string{row.RelayEndpoint}
	}
	seen := make(map[string]struct{}, len(endpoints))
	result := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if err := validateHostPort(endpoint); err != nil {
			return nil, fmt.Errorf("invalid relay endpoint %q: %w", endpoint, err)
		}
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		result = append(result, endpoint)
	}
	if len(result) == 0 {
		return nil, errors.New("provisioning returned no relay endpoints")
	}
	return result, nil
}
