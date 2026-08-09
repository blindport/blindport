package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blindport/blindport/internal/protocol"
)

const (
	authorizationStateName      = "authorization.json"
	authorizationCacheVersion   = 1
	authorizationV3StateName    = "authorization-v3.json"
	authorizationV3CacheVersion = 3
	maxAuthorizationCacheSize   = maxProvisioningJSON + 1024
	maxV2Subscriptions          = 1000
	maxV2Edges                  = 16
	maxEntitlementBytes         = 2048
	maxEntitlementPayload       = 1024
	entitlementSignature        = 64
	generationBits              = 31
	maxV2Unix                   = uint64((1<<63 - 1) >> generationBits)
)

var v2EdgeID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
var entitlementStableID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type provisioningSource string

const (
	provisioningOnlineV2 provisioningSource = "online_v2"
	provisioningCacheV2  provisioningSource = "cache_v2"
	provisioningOnlineV3 provisioningSource = "online_v3"
	provisioningCacheV3  provisioningSource = "cache_v3"
	provisioningOnlineV1 provisioningSource = "online_v1"
)

type provisioningResult struct {
	V1     []provisioning
	V2     *provisioningV2
	V3     *provisioningV3
	Source provisioningSource
}

// provisioningV2 is the complete /api/v2/client/config response.
type provisioningV2 struct {
	Version       int                        `json:"version"`
	Subscriptions []provisioningSubscription `json:"subscriptions"`
}

func (p *provisioningV2) UnmarshalJSON(raw []byte) error {
	if !hasExactJSONFields(raw, "version", "subscriptions") {
		return errors.New("invalid v2 provisioning")
	}
	type plain provisioningV2
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*p = provisioningV2(decoded)
	return nil
}

type provisioningSubscription struct {
	AssignedIP     *string              `json:"assigned_ip"`
	AssignedPort   *uint16              `json:"assigned_port"`
	Transport      string               `json:"transport"`
	Domain         *string              `json:"domain"`
	Product        string               `json:"product"`
	SubscriptionID string               `json:"subscription_id"`
	Edges          []provisioningV2Edge `json:"edges"`
}

func (p *provisioningSubscription) UnmarshalJSON(raw []byte) error {
	if !hasExactJSONFields(raw, "assigned_ip", "assigned_port", "transport", "domain", "product", "subscription_id", "edges") {
		return errors.New("invalid v2 subscription")
	}
	type plain provisioningSubscription
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*p = provisioningSubscription(decoded)
	return nil
}

type provisioningV2Edge struct {
	ID           string              `json:"id"`
	Endpoint     string              `json:"endpoint"`
	Claim        provisioningV2Claim `json:"claim"`
	Entitlement  string              `json:"entitlement"`
	PaidThrough  uint64              `json:"paid_through"`
	GraceThrough uint64              `json:"grace_through"`
	Generation   uint64              `json:"generation"`
}

func (p *provisioningV2Edge) UnmarshalJSON(raw []byte) error {
	if !hasExactJSONFields(raw, "id", "endpoint", "claim", "entitlement", "paid_through", "grace_through", "generation") {
		return errors.New("invalid v2 edge")
	}
	type plain provisioningV2Edge
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*p = provisioningV2Edge(decoded)
	return nil
}

// provisioningV2Claim deliberately has no omitempty fields. The control-plane
// response must carry the complete, edge-scoped claim shape.
type provisioningV2Claim struct {
	Kind      protocol.ClaimKind `json:"kind"`
	IP        string             `json:"ip"`
	Port      uint16             `json:"port"`
	Transport protocol.Transport `json:"transport"`
	Domain    string             `json:"domain"`
}

func (c *provisioningV2Claim) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != 5 {
		return errors.New("invalid v2 claim")
	}
	for _, name := range []string{"kind", "ip", "port", "transport", "domain"} {
		if _, ok := fields[name]; !ok {
			return errors.New("invalid v2 claim")
		}
	}
	type plain provisioningV2Claim
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*c = provisioningV2Claim(decoded)
	return nil
}

func (c provisioningV2Claim) protocolClaim() protocol.Claim {
	return protocol.Claim{Kind: c.Kind, IP: c.IP, Port: c.Port, Transport: c.Transport, Domain: c.Domain}
}

func hasExactJSONFields(raw []byte, names ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return false
		}
	}
	return true
}

type v2FetchKind uint8

const (
	v2FeatureUnavailable v2FetchKind = iota
	v2Terminal
	v2Infrastructure
)

type v2FetchError struct{ kind v2FetchKind }

func (e *v2FetchError) Error() string {
	switch e.kind {
	case v2FeatureUnavailable:
		return "v2 provisioning is unavailable"
	case v2Infrastructure:
		return "v2 provisioning infrastructure failure"
	default:
		return "v2 provisioning protocol failure"
	}
}

type provisioningFailureKind uint8

const (
	provisioningInfrastructure provisioningFailureKind = iota
	provisioningTerminal
)

// provisioningFetchError deliberately does not retain a transport error. The
// transport can include request URLs or response details that must not reach
// operator logs alongside a bearer-authenticated request.
type provisioningFetchError struct {
	kind   provisioningFailureKind
	status int
}

func (e *provisioningFetchError) Error() string {
	if e.kind == provisioningInfrastructure {
		return "provisioning infrastructure failure"
	}
	if e.status != 0 {
		return fmt.Sprintf("provisioning status %d", e.status)
	}
	return "provisioning authorization or protocol failure"
}

func provisioningFailure(err error) provisioningFailureKind {
	var typed *provisioningFetchError
	if errors.As(err, &typed) {
		return typed.kind
	}
	var v2 *v2FetchError
	if errors.As(err, &v2) && v2.kind == v2Infrastructure {
		return provisioningInfrastructure
	}
	return provisioningTerminal
}

func fetchProvisioning(ctx context.Context, client *http.Client, backend, token string, credentials *credentialManager, insecureSkipTLS bool) (provisioningResult, error) {
	var cache authorizationCacheStore
	if credentials != nil {
		cache = authorizationCache{stateDir: credentials.stateDir}
	}
	return fetchProvisioningWithCache(ctx, client, backend, token, credentials, insecureSkipTLS, cache)
}

// fetchProvisioningWithCache selects v3, then v2 when unavailable. It snapshots the
// identity around network and cache I/O, without holding the credential mutex.
func fetchProvisioningWithCache(ctx context.Context, client *http.Client, backend, token string, credentials *credentialManager, insecureSkipTLS bool, cache authorizationCacheStore) (provisioningResult, error) {
	if client == nil {
		return provisioningResult{}, errors.New("provisioning HTTP client is required")
	}
	if insecureSkipTLS {
		v1, err := fetchConfigWithClient(ctx, client, backend, token)
		if err != nil {
			return provisioningResult{}, err
		}
		return provisioningResult{V1: v1, Source: provisioningOnlineV1}, nil
	}
	if credentials == nil {
		return provisioningResult{}, errors.New("v2 provisioning requires a client identity")
	}
	if cache == nil {
		return provisioningResult{}, errors.New("v2 provisioning requires an authorization cache")
	}
	// Renewal intentionally does not hold the credential lock while network I/O
	// runs. Retry once if it installs a new generation in that interval.
	for attempt := 0; attempt < 2; attempt++ {
		identity := credentials.identity()
		v3Cache := authorizationCache{stateDir: credentials.stateDir}
		v3, rawV3, err := fetchProvisioningV3(ctx, client, backend, token, identity.instanceID)
		if err == nil {
			if validateV3Identity(v3, identity.instanceID, identity.generation) != nil || !credentials.hasIdentity(identity) {
				continue
			}
			if err := v3Cache.storeV3(identity, rawV3, v3); err != nil {
				return provisioningResult{}, errors.New("authorization cache update failure")
			}
			if !credentials.hasIdentity(identity) {
				continue
			}
			return provisioningResult{V3: v3, Source: provisioningOnlineV3}, nil
		}
		var v3Err *v3FetchError
		if !errors.As(err, &v3Err) {
			return provisioningResult{}, &provisioningFetchError{kind: provisioningTerminal}
		}
		if v3Err.kind == v2Infrastructure {
			if !credentials.hasIdentity(identity) {
				continue
			}
			cached, cacheErr := v3Cache.loadV3(identity.instanceID, identity.generation, time.Now())
			if !credentials.hasIdentity(identity) {
				continue
			}
			if cacheErr == nil {
				return provisioningResult{V3: cached, Source: provisioningCacheV3}, nil
			}
			return provisioningResult{}, &provisioningFetchError{kind: provisioningInfrastructure}
		}
		if v3Err.kind != v2FeatureUnavailable {
			return provisioningResult{}, &provisioningFetchError{kind: provisioningTerminal}
		}
		config, raw, err := fetchProvisioningV2(ctx, client, backend, token, identity.instanceID)
		if err == nil {
			if validateV2Identity(config, identity.instanceID, identity.generation) != nil || !credentials.hasIdentity(identity) {
				continue
			}
			if err := cache.store(identity, raw, config); err != nil {
				return provisioningResult{}, errors.New("authorization cache update failure")
			}
			if !credentials.hasIdentity(identity) {
				continue
			}
			return provisioningResult{V2: config, Source: provisioningOnlineV2}, nil
		}
		var fetchErr *v2FetchError
		if !errors.As(err, &fetchErr) {
			return provisioningResult{}, &provisioningFetchError{kind: provisioningTerminal}
		}
		if fetchErr.kind == v2FeatureUnavailable {
			v1, v1Err := fetchConfigWithClient(ctx, client, backend, token)
			if v1Err != nil {
				return provisioningResult{}, v1Err
			}
			return provisioningResult{V1: v1, Source: provisioningOnlineV1}, nil
		}
		if fetchErr.kind == v2Infrastructure {
			if !credentials.hasIdentity(identity) {
				continue
			}
			cached, cacheErr := cache.load(identity.instanceID, identity.generation, time.Now())
			if !credentials.hasIdentity(identity) {
				continue
			}
			if cacheErr == nil {
				return provisioningResult{V2: cached, Source: provisioningCacheV2}, nil
			}
			return provisioningResult{}, &provisioningFetchError{kind: provisioningInfrastructure}
		}
		return provisioningResult{}, &provisioningFetchError{kind: provisioningTerminal}
	}
	return provisioningResult{}, &provisioningFetchError{kind: provisioningInfrastructure}
}

func fetchProvisioningV2(ctx context.Context, client *http.Client, backend, token, instanceID string) (*provisioningV2, []byte, error) {
	if client == nil || !isCanonicalInstanceID(instanceID) {
		return nil, nil, &v2FetchError{kind: v2Terminal}
	}
	endpoint, err := url.Parse(strings.TrimRight(backend, "/") + "/api/v2/client/config")
	if err != nil {
		return nil, nil, &v2FetchError{kind: v2Terminal}
	}
	query := endpoint.Query()
	query.Set("instance_id", instanceID)
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, nil, &v2FetchError{kind: v2Terminal}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		return nil, nil, &v2FetchError{kind: v2Infrastructure}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, &v2FetchError{kind: v2FeatureUnavailable}
	}
	if resp.StatusCode >= 500 {
		return nil, nil, &v2FetchError{kind: v2Infrastructure}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, &v2FetchError{kind: v2Terminal}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxProvisioningJSON+1))
	if err != nil || len(raw) > maxProvisioningJSON {
		return nil, nil, &v2FetchError{kind: v2Terminal}
	}
	config, err := parseProvisioningV2(raw, time.Now())
	if err != nil || validateV2Identity(config, instanceID, -1) != nil {
		return nil, nil, &v2FetchError{kind: v2Terminal}
	}
	return config, raw, nil
}

func validateV2Identity(config *provisioningV2, instanceID string, generation int) error {
	for _, subscription := range config.Subscriptions {
		for _, edge := range subscription.Edges {
			boundInstance, err := entitlementInstance(edge.Entitlement)
			if err != nil || boundInstance != instanceID || (generation >= 0 && int(edge.Generation&((1<<generationBits)-1)) != generation) {
				return errors.New("invalid")
			}
		}
	}
	return nil
}

func parseProvisioningV2(raw []byte, now time.Time) (*provisioningV2, error) {
	if len(raw) == 0 || len(raw) > maxProvisioningJSON || rejectDuplicateJSONKeys(raw) != nil {
		return nil, errors.New("invalid v2 provisioning")
	}
	var config provisioningV2
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil || rejectTrailingJSON(decoder) != nil || validateProvisioningV2(&config, now) != nil {
		return nil, errors.New("invalid v2 provisioning")
	}
	return &config, nil
}

func validateProvisioningV2(config *provisioningV2, now time.Time) error {
	if config.Version != 2 || len(config.Subscriptions) > maxV2Subscriptions {
		return errors.New("invalid")
	}
	seenSubscriptions := make(map[string]struct{}, len(config.Subscriptions))
	for _, subscription := range config.Subscriptions {
		if validateSubscriptionID(subscription.SubscriptionID) != nil {
			return errors.New("invalid")
		}
		if _, exists := seenSubscriptions[subscription.SubscriptionID]; exists {
			return errors.New("invalid")
		}
		seenSubscriptions[subscription.SubscriptionID] = struct{}{}
		if validateV2Subscription(subscription) != nil || len(subscription.Edges) == 0 || len(subscription.Edges) > maxV2Edges {
			return errors.New("invalid")
		}
		seenIDs, seenEndpoints := make(map[string]struct{}, len(subscription.Edges)), make(map[string]struct{}, len(subscription.Edges))
		for _, edge := range subscription.Edges {
			if !v2EdgeID.MatchString(edge.ID) || validateCanonicalEndpoint(edge.Endpoint) != nil || validateCanonicalClaim(edge.Claim) != nil || validateV2EdgeBinding(subscription, edge) != nil || validateEntitlement(edge.Entitlement, subscription.SubscriptionID, edge, now) != nil || validateEntitlementTimes(edge, now) != nil {
				return errors.New("invalid")
			}
			if _, exists := seenIDs[edge.ID]; exists {
				return errors.New("invalid")
			}
			if _, exists := seenEndpoints[edge.Endpoint]; exists {
				return errors.New("invalid")
			}
			seenIDs[edge.ID], seenEndpoints[edge.Endpoint] = struct{}{}, struct{}{}
		}
	}
	return nil
}

func validateV2Subscription(subscription provisioningSubscription) error {
	switch protocol.ClaimKind(subscription.Product) {
	case protocol.ClaimIP:
		if subscription.AssignedIP == nil || subscription.AssignedPort != nil || subscription.Domain != nil || subscription.Transport != "tcp" || !canonicalIP(*subscription.AssignedIP) {
			return errors.New("invalid")
		}
	case protocol.ClaimPort:
		if subscription.AssignedIP == nil || subscription.AssignedPort == nil || subscription.Domain != nil || !canonicalIP(*subscription.AssignedIP) || *subscription.AssignedPort == 0 || (subscription.Transport != "tcp" && subscription.Transport != "udp") {
			return errors.New("invalid")
		}
	case protocol.ClaimRelay:
		if subscription.AssignedIP != nil || subscription.AssignedPort != nil || subscription.Domain == nil || subscription.Transport != "tcp" || !canonicalDomain(*subscription.Domain) {
			return errors.New("invalid")
		}
	default:
		return errors.New("invalid")
	}
	return nil
}

func validateV2EdgeBinding(subscription provisioningSubscription, edge provisioningV2Edge) error {
	if edge.Claim.Kind != protocol.ClaimKind(subscription.Product) {
		return errors.New("invalid")
	}
	switch edge.Claim.Kind {
	case protocol.ClaimIP:
		if edge.Claim.IP != *subscription.AssignedIP {
			return errors.New("invalid")
		}
	case protocol.ClaimPort:
		// Provider Port edges are assigned distinct local IPs, but retain the
		// subscription's signed port and transport exactly.
		if edge.Claim.Port != *subscription.AssignedPort || string(edge.Claim.Transport) != subscription.Transport {
			return errors.New("invalid")
		}
	case protocol.ClaimRelay:
		if edge.Claim.Domain != *subscription.Domain {
			return errors.New("invalid")
		}
	}
	return nil
}

func validateCanonicalEndpoint(value string) error {
	if validateHostPort(value) != nil {
		return errors.New("invalid")
	}
	host, _, _ := netSplitHostPort(value)
	if address, err := netip.ParseAddr(host); err == nil {
		if address.String() != host {
			return errors.New("invalid")
		}
	} else if strings.ToLower(host) != host {
		return errors.New("invalid")
	}
	return nil
}

func netSplitHostPort(value string) (string, string, error) { return net.SplitHostPort(value) }

func canonicalIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.String() == value
}

func canonicalDomain(value string) bool {
	claim := protocol.Claim{Kind: protocol.ClaimRelay, Domain: value}
	return protocol.ValidateClaim(&claim) == nil
}

func validateCanonicalClaim(claim provisioningV2Claim) error {
	converted := claim.protocolClaim()
	if protocol.ValidateClaim(&converted) != nil {
		return errors.New("invalid")
	}
	if claim.IP != "" && !canonicalIP(claim.IP) {
		return errors.New("invalid")
	}
	if claim.Kind == protocol.ClaimIP || claim.Kind == protocol.ClaimRelay {
		if claim.Transport != "" {
			return errors.New("invalid")
		}
	}
	return nil
}

// validateEntitlement validates artifact metadata only. blindportd does not
// verify entitlement signatures or keyrings: metadata is cache selection only,
// and the Relay remains authoritative for entitlement verification.
func validateEntitlement(value, subscriptionID string, edge provisioningV2Edge, now time.Time) error {
	payload, err := parseEntitlementMetadata(value)
	if err != nil || validateEntitlementMetadata(payload, now) != nil || payload.Subscription != subscriptionID || payload.Edge != edge.ID || payload.Kind != string(edge.Claim.Kind) || payload.IP != edge.Claim.IP || payload.Port != edge.Claim.Port || payload.Transport != string(edge.Claim.Transport) || payload.Domain != edge.Claim.Domain || payload.PaidThrough != edge.PaidThrough || payload.GraceThrough != edge.GraceThrough || payload.Generation != edge.Generation {
		return errors.New("invalid")
	}
	return nil
}

type entitlementMetadata struct {
	Type         string `json:"typ"`
	Version      uint64 `json:"v"`
	KeyID        string `json:"kid"`
	Account      string `json:"account"`
	Subscription string `json:"subscription"`
	Instance     string `json:"instance"`
	ClientKey    string `json:"client_pk"`
	Edge         string `json:"edge"`
	Kind         string `json:"kind"`
	IP           string `json:"ip"`
	Port         uint16 `json:"port"`
	Transport    string `json:"transport"`
	Domain       string `json:"domain"`
	Scope        string `json:"scope,omitempty"`
	IssuedAt     uint64 `json:"iat"`
	NotBefore    uint64 `json:"nbf"`
	PaidThrough  uint64 `json:"paid_through"`
	GraceThrough uint64 `json:"grace_through"`
	Generation   uint64 `json:"generation"`
	TokenID      string `json:"jti"`
}

func (p *entitlementMetadata) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return errors.New("invalid entitlement metadata")
	}
	versionRaw, ok := fields["v"]
	if !ok {
		return errors.New("invalid entitlement metadata")
	}
	var version uint64
	if json.Unmarshal(versionRaw, &version) != nil {
		return errors.New("invalid entitlement metadata")
	}
	names := []string{"typ", "v", "kid", "account", "subscription", "instance", "client_pk", "edge", "kind", "ip", "port", "transport", "domain", "iat", "nbf", "paid_through", "grace_through", "generation", "jti"}
	if version == 2 {
		names = append(names, "scope")
	}
	if !hasExactJSONFields(raw, names...) {
		return errors.New("invalid entitlement metadata")
	}
	type plain entitlementMetadata
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*p = entitlementMetadata(decoded)
	return nil
}

func parseEntitlementMetadata(value string) (entitlementMetadata, error) {
	if len(value) == 0 || len(value) > maxEntitlementBytes || !ascii(value) {
		return entitlementMetadata{}, errors.New("invalid")
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return entitlementMetadata{}, errors.New("invalid")
	}
	payloadBytes, err := decodeCanonicalRawBase64(parts[1], -1)
	if err != nil || len(payloadBytes) == 0 || len(payloadBytes) > maxEntitlementPayload || rejectDuplicateJSONKeys(payloadBytes) != nil || !ascii(string(payloadBytes)) {
		return entitlementMetadata{}, errors.New("invalid")
	}
	if _, err := decodeCanonicalRawBase64(parts[2], entitlementSignature); err != nil {
		return entitlementMetadata{}, errors.New("invalid")
	}
	var payload entitlementMetadata
	decoder := json.NewDecoder(bytes.NewReader(payloadBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || rejectTrailingJSON(decoder) != nil {
		return entitlementMetadata{}, errors.New("invalid")
	}
	canonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonical, payloadBytes) {
		return entitlementMetadata{}, errors.New("invalid")
	}
	return payload, nil
}

func validateEntitlementMetadata(payload entitlementMetadata, now time.Time) error {
	if payload.Type != "blindport-offline-entitlement" || (payload.Version != 1 && payload.Version != 2) || !entitlementStableID.MatchString(payload.KeyID) || !isCanonicalInstanceID(payload.Account) || !isCanonicalInstanceID(payload.Subscription) || !isCanonicalInstanceID(payload.Instance) || !entitlementStableID.MatchString(payload.Edge) || len(payload.IP) > 45 || len(payload.Domain) > 253 || payload.IssuedAt > maxV2Unix || payload.NotBefore > maxV2Unix || payload.PaidThrough > maxV2Unix || payload.GraceThrough > maxV2Unix || payload.IssuedAt != payload.NotBefore || payload.IssuedAt > payload.PaidThrough || payload.PaidThrough > payload.GraceThrough || payload.GraceThrough-payload.PaidThrough > uint64((7*24*time.Hour)/time.Second) || payload.Generation > uint64(1<<63-1) || payload.Generation&((1<<generationBits)-1) == 0 || payload.Generation != payload.PaidThrough<<generationBits|(payload.Generation&((1<<generationBits)-1)) || time.Unix(int64(payload.IssuedAt), 0).UTC().After(now.UTC().Add(60*time.Second)) || now.UTC().After(time.Unix(int64(payload.GraceThrough), 0).UTC()) {
		return errors.New("invalid")
	}
	if (payload.Version == 1 && payload.Scope != "") || (payload.Version == 2 && (payload.Scope != "wildcard" || payload.Kind != string(protocol.ClaimRelay))) {
		return errors.New("invalid")
	}
	if _, err := decodeCanonicalRawBase64(payload.ClientKey, 32); err != nil {
		return errors.New("invalid")
	}
	if _, err := decodeCanonicalRawBase64(payload.TokenID, 16); err != nil {
		return errors.New("invalid")
	}
	claim := protocol.Claim{Kind: protocol.ClaimKind(payload.Kind), IP: payload.IP, Port: payload.Port, Transport: protocol.Transport(payload.Transport), Domain: payload.Domain}
	if payload.Version == 2 {
		claim.Scope = protocol.RelayHostnameScopeWildcard
	}
	if protocol.ValidateClaim(&claim) != nil || (claim.IP != "" && !canonicalIP(claim.IP)) {
		return errors.New("invalid")
	}
	return nil
}

func validateEntitlementTimes(edge provisioningV2Edge, now time.Time) error {
	if edge.PaidThrough > edge.GraceThrough || edge.GraceThrough > maxV2Unix || edge.GraceThrough-edge.PaidThrough > uint64((7*24*time.Hour)/time.Second) || edge.Generation > uint64(1<<63-1) || edge.Generation&((1<<generationBits)-1) == 0 || edge.Generation != edge.PaidThrough<<generationBits|(edge.Generation&((1<<generationBits)-1)) || now.UTC().After(time.Unix(int64(edge.GraceThrough), 0).UTC()) {
		return errors.New("invalid")
	}
	return nil
}

func ascii(value string) bool {
	for i := range value {
		if value[i] > 0x7f {
			return false
		}
	}
	return true
}
func base64URL(value string) bool {
	for _, character := range value {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_') {
			return false
		}
	}
	return value != ""
}

type authorizationCacheStore interface {
	store(credentialIdentity, []byte, *provisioningV2) error
	load(instanceID string, generation int, now time.Time) (*provisioningV2, error)
}

// authorizationCacheEnvelope binds a cached response to one canonical client
// identity and credential generation, including authoritative empty responses.
type authorizationCacheEnvelope struct {
	Version    int             `json:"version"`
	InstanceID string          `json:"instance_id"`
	Generation int             `json:"generation"`
	Response   json.RawMessage `json:"response"`
}

func (e *authorizationCacheEnvelope) UnmarshalJSON(raw []byte) error {
	if !hasExactJSONFields(raw, "version", "instance_id", "generation", "response") {
		return errors.New("invalid authorization cache")
	}
	type plain authorizationCacheEnvelope
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*e = authorizationCacheEnvelope(decoded)
	return nil
}

type authorizationCache struct{ stateDir string }

func (c authorizationCache) path() string { return filepath.Join(c.stateDir, authorizationStateName) }

func (c authorizationCache) store(identity credentialIdentity, raw []byte, config *provisioningV2) error {
	if !isCanonicalInstanceID(identity.instanceID) || identity.generation < 1 || identity.generation > maxCredentialGeneration || config == nil || validateProvisioningV2(config, time.Now()) != nil || len(raw) == 0 || len(raw) > maxProvisioningJSON {
		return errors.New("invalid v2 authorization cache")
	}
	decoded, err := parseProvisioningV2(raw, time.Now())
	if err != nil || !reflect.DeepEqual(decoded, config) || validateV2Identity(config, identity.instanceID, identity.generation) != nil {
		return errors.New("invalid v2 authorization cache")
	}
	stored, err := json.Marshal(authorizationCacheEnvelope{Version: authorizationCacheVersion, InstanceID: identity.instanceID, Generation: identity.generation, Response: json.RawMessage(raw)})
	if err != nil || len(stored) > maxAuthorizationCacheSize {
		return errors.New("invalid v2 authorization cache")
	}
	if existing, err := c.readRaw(); err == nil && bytes.Equal(existing, stored) {
		return nil
	}
	if err := prepareCredentialStateDir(c.stateDir); err != nil {
		return errors.New("authorization cache state is unsafe")
	}
	if info, err := os.Lstat(c.path()); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || validateStaticConfigOwner(info) != nil) {
		return errors.New("authorization cache file is unsafe")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("authorization cache file is unavailable")
	}
	temporary, err := os.CreateTemp(c.stateDir, ".authorization-*")
	if err != nil {
		return errors.New("write authorization cache")
	}
	temporaryPath := temporary.Name()
	cleanup := func() { _ = temporary.Close(); _ = os.Remove(temporaryPath) }
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return errors.New("write authorization cache")
	}
	if _, err := temporary.Write(stored); err != nil {
		cleanup()
		return errors.New("write authorization cache")
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return errors.New("write authorization cache")
	}
	if err := temporary.Close(); err != nil {
		cleanup()
		return errors.New("write authorization cache")
	}
	if err := os.Rename(temporaryPath, c.path()); err != nil {
		cleanup()
		return errors.New("write authorization cache")
	}
	directory, err := os.Open(c.stateDir)
	if err != nil {
		return errors.New("write authorization cache")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("write authorization cache")
	}
	return nil
}

func (c authorizationCache) load(instanceID string, generation int, now time.Time) (*provisioningV2, error) {
	raw, err := c.readRaw()
	if err != nil {
		return nil, errors.New("authorization cache is unavailable")
	}
	config, err := parseAuthorizationCache(raw, instanceID, generation, now)
	if err != nil {
		return nil, errors.New("authorization cache is invalid")
	}
	return config, nil
}

func parseAuthorizationCache(raw []byte, instanceID string, generation int, now time.Time) (*provisioningV2, error) {
	if len(raw) == 0 || len(raw) > maxAuthorizationCacheSize || rejectDuplicateJSONKeys(raw) != nil || !isCanonicalInstanceID(instanceID) || generation < 1 || generation > maxCredentialGeneration {
		return nil, errors.New("invalid authorization cache")
	}
	var envelope authorizationCacheEnvelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || rejectTrailingJSON(decoder) != nil || envelope.Version != authorizationCacheVersion || envelope.InstanceID != instanceID || envelope.Generation != generation || !isCanonicalInstanceID(envelope.InstanceID) || envelope.Generation < 1 || envelope.Generation > maxCredentialGeneration {
		return nil, errors.New("invalid authorization cache")
	}
	config, err := parseProvisioningV2(envelope.Response, now)
	if err != nil || validateV2Identity(config, envelope.InstanceID, envelope.Generation) != nil {
		return nil, errors.New("invalid authorization cache")
	}
	return config, nil
}

func (c authorizationCache) readRaw() ([]byte, error) {
	return readAuthorizationCache(c.path())
}

func readAuthorizationCache(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || validateStaticConfigOwner(info) != nil {
		return nil, errors.New("unsafe cache")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return nil, errors.New("unsafe cache")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxAuthorizationCacheSize+1))
	if err != nil || len(raw) > maxAuthorizationCacheSize {
		return nil, errors.New("unsafe cache")
	}
	return raw, nil
}

func (c authorizationCache) v3Path() string {
	return filepath.Join(c.stateDir, authorizationV3StateName)
}

func (c authorizationCache) storeV3(identity credentialIdentity, raw []byte, config *provisioningV3) error {
	if !isCanonicalInstanceID(identity.instanceID) || identity.generation < 1 || identity.generation > maxCredentialGeneration || config == nil || validateProvisioningV3(config, time.Now()) != nil || len(raw) == 0 || len(raw) > maxProvisioningJSON {
		return errors.New("invalid v3 authorization cache")
	}
	decoded, err := parseProvisioningV3(raw, time.Now())
	if err != nil || !reflect.DeepEqual(decoded, config) || validateV3Identity(config, identity.instanceID, identity.generation) != nil {
		return errors.New("invalid v3 authorization cache")
	}
	stored, err := json.Marshal(authorizationCacheEnvelope{Version: authorizationV3CacheVersion, InstanceID: identity.instanceID, Generation: identity.generation, Response: json.RawMessage(raw)})
	if err != nil || len(stored) > maxAuthorizationCacheSize {
		return errors.New("invalid v3 authorization cache")
	}
	return writeAuthorizationCache(c.stateDir, c.v3Path(), stored)
}

func (c authorizationCache) loadV3(instanceID string, generation int, now time.Time) (*provisioningV3, error) {
	raw, err := readAuthorizationCache(c.v3Path())
	if err != nil {
		return nil, errors.New("v3 authorization cache is unavailable")
	}
	if len(raw) == 0 || len(raw) > maxAuthorizationCacheSize || rejectDuplicateJSONKeys(raw) != nil || !isCanonicalInstanceID(instanceID) || generation < 1 || generation > maxCredentialGeneration {
		return nil, errors.New("invalid v3 authorization cache")
	}
	var envelope authorizationCacheEnvelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || rejectTrailingJSON(decoder) != nil || envelope.Version != authorizationV3CacheVersion || envelope.InstanceID != instanceID || envelope.Generation != generation {
		return nil, errors.New("invalid v3 authorization cache")
	}
	config, err := parseProvisioningV3(envelope.Response, now)
	if err != nil || validateV3Identity(config, envelope.InstanceID, envelope.Generation) != nil {
		return nil, errors.New("invalid v3 authorization cache")
	}
	return config, nil
}

func writeAuthorizationCache(stateDir, path string, stored []byte) error {
	if err := prepareCredentialStateDir(stateDir); err != nil {
		return errors.New("authorization cache state is unsafe")
	}
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || validateStaticConfigOwner(info) != nil) {
		return errors.New("authorization cache file is unsafe")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("authorization cache file is unavailable")
	}
	temporary, err := os.CreateTemp(stateDir, ".authorization-*")
	if err != nil {
		return errors.New("write authorization cache")
	}
	temporaryPath := temporary.Name()
	cleanup := func() { _ = temporary.Close(); _ = os.Remove(temporaryPath) }
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return errors.New("write authorization cache")
	}
	if _, err := temporary.Write(stored); err != nil {
		cleanup()
		return errors.New("write authorization cache")
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return errors.New("write authorization cache")
	}
	if err := temporary.Close(); err != nil {
		cleanup()
		return errors.New("write authorization cache")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		cleanup()
		return errors.New("write authorization cache")
	}
	directory, err := os.Open(stateDir)
	if err != nil {
		return errors.New("write authorization cache")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("write authorization cache")
	}
	return nil
}

func entitlementInstance(value string) (string, error) {
	payload, err := parseEntitlementMetadata(value)
	if err != nil || validateEntitlementMetadata(payload, time.Now()) != nil {
		return "", errors.New("invalid")
	}
	return payload.Instance, nil
}

type entitlementStore struct {
	mu     sync.RWMutex
	values map[workerKey]string
}

func newEntitlementStore() *entitlementStore {
	return &entitlementStore{values: make(map[workerKey]string)}
}
func (s *entitlementStore) Set(key workerKey, value string) {
	s.mu.Lock()
	s.values[key] = value
	s.mu.Unlock()
}
func (s *entitlementStore) Replace(values map[workerKey]string) {
	replacement := make(map[workerKey]string, len(values))
	for key, value := range values {
		replacement[key] = value
	}
	s.mu.Lock()
	s.values = replacement
	s.mu.Unlock()
}
func (s *entitlementStore) Get(key workerKey) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.values[key]
	return value, ok
}

func buildV2MappingPlans(mappings []mapping, config *provisioningV2, relayOverride string) ([]workerPlan, error) {
	return buildV2MappingPlansWithMissing(mappings, config, relayOverride, false)
}

func buildAvailableV2MappingPlans(mappings []mapping, config *provisioningV2, relayOverride string) ([]workerPlan, error) {
	return buildV2MappingPlansWithMissing(mappings, config, relayOverride, true)
}

func buildV2MappingPlansWithMissing(mappings []mapping, config *provisioningV2, relayOverride string, allowMissing bool) ([]workerPlan, error) {
	if config == nil || validateProvisioningV2(config, time.Now()) != nil || validateMappings(mappings) != nil {
		return nil, errors.New("invalid v2 provisioning plans")
	}
	byID := make(map[string]provisioningSubscription, len(config.Subscriptions))
	for _, subscription := range config.Subscriptions {
		byID[subscription.SubscriptionID] = subscription
	}
	var plans []workerPlan
	for _, item := range mappings {
		subscription, exists := byID[item.SubscriptionID]
		if !exists {
			if allowMissing {
				continue
			}
			return nil, fmt.Errorf("configured subscription %s does not exist or is not active", item.SubscriptionID)
		}
		matched := 0
		for _, edge := range subscription.Edges {
			if relayOverride != "" && edge.Endpoint != relayOverride {
				continue
			}
			matched++
			claim := edge.Claim.protocolClaim()
			if item.HTTPChallengeUpstream != "" && claim.Kind != protocol.ClaimRelay {
				return nil, fmt.Errorf("subscription %s: http_challenge_upstream is only valid for Blindport Relay", item.SubscriptionID)
			}
			if item.TLSMode == tlsModeAutomatic && claim.Kind != protocol.ClaimRelay {
				return nil, fmt.Errorf("subscription %s: automatic TLS is only valid for Blindport Relay", item.SubscriptionID)
			}
			plans = append(plans, workerPlan{SubscriptionID: item.SubscriptionID, RelayAddr: edge.Endpoint, EdgeID: edge.ID, Entitlement: edge.Entitlement, Upstream: item.Upstream, HTTPChallengeUpstream: item.HTTPChallengeUpstream, TLSMode: normalizedTLSMode(item.TLSMode), Claim: &claim})
		}
		if relayOverride != "" && matched == 0 {
			return nil, fmt.Errorf("subscription %s: relay override does not match a signed v2 edge", item.SubscriptionID)
		}
	}
	sort.SliceStable(plans, func(i, j int) bool {
		if plans[i].SubscriptionID != plans[j].SubscriptionID {
			return plans[i].SubscriptionID < plans[j].SubscriptionID
		}
		return plans[i].RelayAddr < plans[j].RelayAddr
	})
	seenWorkers := make(map[workerKey]struct{}, len(plans))
	for _, plan := range plans {
		key := workerKey{subscriptionID: plan.SubscriptionID, relayAddr: plan.RelayAddr}
		if _, exists := seenWorkers[key]; exists {
			return nil, fmt.Errorf("duplicate worker plan for subscription %s relay %s", plan.SubscriptionID, plan.RelayAddr)
		}
		seenWorkers[key] = struct{}{}
	}
	return plans, nil
}

func decodeCanonicalRawBase64(value string, length int) ([]byte, error) {
	if !base64URL(value) {
		return nil, errors.New("invalid")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value || (length >= 0 && len(decoded) != length) {
		return nil, errors.New("invalid")
	}
	return decoded, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := consumeJSONValue(decoder); err != nil || rejectTrailingJSON(decoder) != nil {
		return errors.New("invalid")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid")
			}
			if _, exists := seen[name]; exists {
				return errors.New("duplicate")
			}
			seen[name] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("invalid")
	}
}
