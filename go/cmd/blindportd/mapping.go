package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/blindport/blindport/internal/protocol"
	"github.com/google/uuid"
)

const (
	maxConfigSize     = 1 << 20
	maxStaticAccounts = 16
)

var errStaticConfigV3RequiresDocumentLoader = errors.New("config version 3 requires the multi-account config loader")

type mapping struct {
	AccountName           string `json:"-"`
	SubscriptionID        string `json:"subscription_id"`
	Upstream              string `json:"upstream"`
	HTTPChallengeUpstream string `json:"http_challenge_upstream,omitempty"`
	TLSMode               string `json:"tls_mode,omitempty"`
	ACMETermsAccepted     bool   `json:"acme_terms_accepted,omitempty"`
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

// staticConfigDocument retains account boundaries for multi-account runtimes.
type staticConfigDocument struct {
	Version  int             `json:"version"`
	Mappings []mapping       `json:"mappings,omitempty"`
	Accounts []staticAccount `json:"accounts,omitempty"`
}

type staticAccount struct {
	Name      string    `json:"name"`
	TokenFile string    `json:"token_file"`
	StateDir  string    `json:"state_dir"`
	Mappings  []mapping `json:"mappings"`
}

type staticConfigV3 struct {
	Version  int             `json:"version"`
	Accounts []staticAccount `json:"accounts"`
}

func (cfg staticConfigDocument) IsMultiAccount() bool {
	return cfg.Version == 3
}

func (cfg staticConfigDocument) Account(name string) (staticAccount, bool) {
	for _, account := range cfg.Accounts {
		if account.Name == name {
			return account, true
		}
	}
	return staticAccount{}, false
}

type workerPlan struct {
	AccountName           string
	SubscriptionID        string
	RelayAddr             string
	EdgeID                string
	Entitlement           string
	Upstream              string
	HTTPChallengeUpstream string
	TLSMode               string
	Claim                 *protocol.Claim
}

const (
	tlsModePassthrough = "passthrough"
	tlsModeAutomatic   = "automatic"
)

var upstreamHostnameLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func loadStaticConfig(path string) ([]mapping, error) {
	return loadStaticConfigWithPermissions(path, false)
}

func loadOwnerOnlyStaticConfig(path string) ([]mapping, error) {
	return loadStaticConfigWithPermissions(path, true)
}

func loadStaticConfigWithPermissions(path string, ownerOnly bool) ([]mapping, error) {
	cfg, err := loadStaticConfigDocumentWithPermissions(path, ownerOnly)
	if err != nil {
		return nil, err
	}
	if cfg.IsMultiAccount() {
		return nil, errStaticConfigV3RequiresDocumentLoader
	}
	return cfg.Mappings, nil
}

func loadStaticConfigDocument(path string) (staticConfigDocument, error) {
	return loadStaticConfigDocumentWithPermissions(path, false)
}

func loadStaticConfigDocumentWithPermissions(path string, ownerOnly bool) (staticConfigDocument, error) {
	f, err := openStaticConfig(path)
	if err != nil {
		return staticConfigDocument{}, fmt.Errorf("open config %q: %w", path, err)
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return staticConfigDocument{}, fmt.Errorf("inspect opened config %q: %w", path, err)
	}
	if !openedInfo.Mode().IsRegular() {
		return staticConfigDocument{}, fmt.Errorf("config %q must be a regular file", path)
	}
	if openedInfo.Mode().Perm()&0o022 != 0 {
		return staticConfigDocument{}, fmt.Errorf("config %q must not be writable by group or others", path)
	}
	if ownerOnly && openedInfo.Mode().Perm()&0o077 != 0 {
		return staticConfigDocument{}, fmt.Errorf("config %q must be owner-only (mode 0600 or stricter)", path)
	}
	if err := validateStaticConfigOwner(openedInfo); err != nil {
		return staticConfigDocument{}, fmt.Errorf("config %q: %w", path, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return staticConfigDocument{}, fmt.Errorf("read config %q: %w", path, err)
	}
	if len(data) > maxConfigSize {
		return staticConfigDocument{}, fmt.Errorf("config %q exceeds %d bytes", path, maxConfigSize)
	}
	return parseStaticConfigDocument(path, data)
}

func parseStaticConfigDocument(path string, data []byte) (staticConfigDocument, error) {
	var version struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &version); err == nil && version.Version == 3 {
		return parseStaticConfigV3(path, data)
	}

	var cfg staticConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return staticConfigDocument{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return staticConfigDocument{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	if cfg.Version != 1 && cfg.Version != 2 {
		return staticConfigDocument{}, fmt.Errorf("config %q has unsupported version %d", path, cfg.Version)
	}
	if len(cfg.Mappings) == 0 {
		return staticConfigDocument{}, fmt.Errorf("config %q must contain at least one mapping", path)
	}
	for i := range cfg.Mappings {
		cfg.Mappings[i].Source = fmt.Sprintf("config %q mapping %d", path, i)
		if cfg.Version == 1 {
			if cfg.Mappings[i].TLSMode != "" || cfg.Mappings[i].ACMETermsAccepted {
				return staticConfigDocument{}, fmt.Errorf("%s: TLS settings require config version 2", cfg.Mappings[i].Source)
			}
			cfg.Mappings[i].TLSMode = tlsModePassthrough
		} else if cfg.Mappings[i].TLSMode == "" {
			return staticConfigDocument{}, fmt.Errorf("%s: config version 2 requires an explicit tls_mode", cfg.Mappings[i].Source)
		}
	}
	if err := validateMappings(cfg.Mappings); err != nil {
		return staticConfigDocument{}, err
	}
	return staticConfigDocument{Version: cfg.Version, Mappings: cfg.Mappings}, nil
}

func parseStaticConfigV3(path string, data []byte) (staticConfigDocument, error) {
	var cfg staticConfigV3
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return staticConfigDocument{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return staticConfigDocument{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	if cfg.Version != 3 {
		return staticConfigDocument{}, fmt.Errorf("config %q has unsupported version %d", path, cfg.Version)
	}
	if err := validateStaticAccounts(cfg.Accounts, path); err != nil {
		return staticConfigDocument{}, err
	}
	return staticConfigDocument{Version: cfg.Version, Accounts: cfg.Accounts}, nil
}

var staticAccountName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

func validateStaticAccounts(accounts []staticAccount, path string) error {
	if len(accounts) == 0 || len(accounts) > maxStaticAccounts {
		return fmt.Errorf("config %q must contain between 1 and %d accounts", path, maxStaticAccounts)
	}
	seenNames := make(map[string]struct{}, len(accounts))
	seenTokenFiles := make(map[string]string, len(accounts))
	seenStateDirs := make(map[string]string, len(accounts))
	allMappings := make([]mapping, 0)
	for i := range accounts {
		account := &accounts[i]
		if !staticAccountName.MatchString(account.Name) {
			return fmt.Errorf("config %q account %d: name must be a lowercase stable ID", path, i)
		}
		if _, exists := seenNames[account.Name]; exists {
			return fmt.Errorf("config %q has duplicate account name %q", path, account.Name)
		}
		seenNames[account.Name] = struct{}{}
		if err := validateStaticConfigPath(account.TokenFile, "token_file"); err != nil {
			return fmt.Errorf("config %q account %q: %w", path, account.Name, err)
		}
		if previous, exists := seenTokenFiles[account.TokenFile]; exists {
			return fmt.Errorf("config %q accounts %q and %q share token_file %q", path, previous, account.Name, account.TokenFile)
		}
		seenTokenFiles[account.TokenFile] = account.Name
		if err := validateStaticConfigPath(account.StateDir, "state_dir"); err != nil {
			return fmt.Errorf("config %q account %q: %w", path, account.Name, err)
		}
		if previous, exists := seenStateDirs[account.StateDir]; exists {
			return fmt.Errorf("config %q accounts %q and %q share state_dir %q", path, previous, account.Name, account.StateDir)
		}
		for existingDir, existingName := range seenStateDirs {
			if pathsOverlap(account.StateDir, existingDir) {
				return fmt.Errorf("config %q accounts %q and %q have overlapping state_dir paths", path, existingName, account.Name)
			}
		}
		seenStateDirs[account.StateDir] = account.Name
		for mappingIndex := range account.Mappings {
			account.Mappings[mappingIndex].AccountName = account.Name
			account.Mappings[mappingIndex].Source = fmt.Sprintf("config %q account %q mapping %d", path, account.Name, mappingIndex)
		}
		allMappings = append(allMappings, account.Mappings...)
	}
	return validateMappings(allMappings)
}

func validateStaticAccountRuntimeMappings(accounts []staticAccount, dockerEnabled bool) error {
	if dockerEnabled {
		return nil
	}
	for _, account := range accounts {
		if len(account.Mappings) == 0 {
			return fmt.Errorf("account %q must contain at least one mapping when Docker discovery is disabled", account.Name)
		}
	}
	return nil
}

func validateStaticConfigPath(path, field string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return fmt.Errorf("%s must be an absolute, clean, non-root path", field)
	}
	return nil
}

func pathsOverlap(first, second string) bool {
	return first == second || strings.HasPrefix(first, second+string(filepath.Separator)) || strings.HasPrefix(second, first+string(filepath.Separator))
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
		if err := validateTLSMapping(item, source); err != nil {
			return err
		}
		if previous, ok := seen[item.SubscriptionID]; ok {
			return fmt.Errorf("duplicate subscription_id %s in %s and %s", item.SubscriptionID, previous, source)
		}
		seen[item.SubscriptionID] = source
	}
	return nil
}

func validateTLSMapping(item mapping, source string) error {
	switch item.TLSMode {
	case "", tlsModePassthrough:
		if item.ACMETermsAccepted {
			return fmt.Errorf("%s: acme_terms_accepted is only valid with automatic TLS", source)
		}
	case tlsModeAutomatic:
		if !item.ACMETermsAccepted {
			return fmt.Errorf("%s: automatic TLS requires acme_terms_accepted=true", source)
		}
		if item.HTTPChallengeUpstream != "" {
			return fmt.Errorf("%s: automatic TLS and http_challenge_upstream are mutually exclusive", source)
		}
	default:
		return fmt.Errorf("%s: tls_mode must be passthrough or automatic", source)
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
		if item.TLSMode == tlsModeAutomatic && claim.Kind != protocol.ClaimRelay {
			return nil, fmt.Errorf("subscription %s: automatic TLS is only valid for Blindport Relay", item.SubscriptionID)
		}
		assignments, err := provisioningAssignments(row, relayOverride)
		if err != nil {
			return nil, fmt.Errorf("subscription %s: %w", item.SubscriptionID, err)
		}
		for _, assignment := range assignments {
			claimCopy := *claim
			if assignment.AssignedIP != "" {
				claimCopy.IP = assignment.AssignedIP
			}
			if err := protocol.ValidateClaim(&claimCopy); err != nil {
				return nil, fmt.Errorf("subscription %s has invalid edge claim: %w", item.SubscriptionID, err)
			}
			plans = append(plans, workerPlan{
				AccountName:           item.AccountName,
				SubscriptionID:        item.SubscriptionID,
				RelayAddr:             assignment.RelayEndpoint,
				Upstream:              item.Upstream,
				HTTPChallengeUpstream: item.HTTPChallengeUpstream,
				TLSMode:               normalizedTLSMode(item.TLSMode),
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

func provisioningAssignments(row provisioning, relayOverride string) ([]relayAssignment, error) {
	if relayOverride != "" {
		for _, assignment := range row.RelayAssignments {
			if assignment.RelayEndpoint == relayOverride {
				return validateRelayAssignments([]relayAssignment{assignment})
			}
		}
		return validateRelayAssignments([]relayAssignment{{RelayEndpoint: relayOverride, AssignedIP: row.AssignedIP}})
	}
	if len(row.RelayAssignments) > 0 {
		return validateRelayAssignments(row.RelayAssignments)
	}
	endpoints, err := provisioningEndpoints(row, "")
	if err != nil {
		return nil, err
	}
	assignments := make([]relayAssignment, 0, len(endpoints))
	for _, endpoint := range endpoints {
		assignments = append(assignments, relayAssignment{RelayEndpoint: endpoint, AssignedIP: row.AssignedIP})
	}
	return assignments, nil
}

func validateRelayAssignments(assignments []relayAssignment) ([]relayAssignment, error) {
	seen := make(map[string]struct{}, len(assignments))
	result := make([]relayAssignment, 0, len(assignments))
	for _, assignment := range assignments {
		if err := validateHostPort(assignment.RelayEndpoint); err != nil {
			return nil, fmt.Errorf("invalid relay assignment endpoint %q: %w", assignment.RelayEndpoint, err)
		}
		if assignment.AssignedIP != "" && net.ParseIP(assignment.AssignedIP) == nil {
			return nil, fmt.Errorf("invalid relay assignment IP %q", assignment.AssignedIP)
		}
		key := assignment.RelayEndpoint + "\x00" + assignment.AssignedIP
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, assignment)
	}
	if len(result) == 0 {
		return nil, errors.New("provisioning returned no relay assignments")
	}
	return result, nil
}

func normalizedTLSMode(mode string) string {
	if mode == "" {
		return tlsModePassthrough
	}
	return mode
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
