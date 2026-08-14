package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/blindport/blindport/internal/protocol"
)

type provisioningV3 struct {
	Version       int                          `json:"version"`
	Subscriptions []provisioningV3Subscription `json:"subscriptions"`
}

func (p *provisioningV3) UnmarshalJSON(raw []byte) error {
	if !hasExactJSONFields(raw, "version", "subscriptions") {
		return errors.New("invalid v3 provisioning")
	}
	type plain provisioningV3
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*p = provisioningV3(decoded)
	return nil
}

type provisioningV3Subscription struct {
	AssignedIP         *string              `json:"assigned_ip"`
	AssignedPort       *uint16              `json:"assigned_port"`
	Transport          string               `json:"transport"`
	Domain             *string              `json:"domain"`
	Product            string               `json:"product"`
	RelayHostnameScope string               `json:"relay_hostname_scope"`
	SubscriptionID     string               `json:"subscription_id"`
	Edges              []provisioningV3Edge `json:"edges"`
}

func (p *provisioningV3Subscription) UnmarshalJSON(raw []byte) error {
	if !hasExactJSONFields(raw, "assigned_ip", "assigned_port", "transport", "domain", "product", "relay_hostname_scope", "subscription_id", "edges") {
		return errors.New("invalid v3 subscription")
	}
	type plain provisioningV3Subscription
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*p = provisioningV3Subscription(decoded)
	return nil
}

type provisioningV3Edge struct {
	ID           string              `json:"id"`
	Endpoint     string              `json:"endpoint"`
	Claim        provisioningV3Claim `json:"claim"`
	Entitlement  string              `json:"entitlement"`
	PaidThrough  uint64              `json:"paid_through"`
	GraceThrough uint64              `json:"grace_through"`
	Generation   uint64              `json:"generation"`
}

func (p *provisioningV3Edge) UnmarshalJSON(raw []byte) error {
	if !hasExactJSONFields(raw, "id", "endpoint", "claim", "entitlement", "paid_through", "grace_through", "generation") {
		return errors.New("invalid v3 edge")
	}
	type plain provisioningV3Edge
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*p = provisioningV3Edge(decoded)
	return nil
}

type provisioningV3Claim struct {
	Kind      protocol.ClaimKind `json:"kind"`
	IP        string             `json:"ip"`
	Port      uint16             `json:"port"`
	Transport protocol.Transport `json:"transport"`
	Domain    string             `json:"domain"`
	Scope     string             `json:"scope"`
}

func (c *provisioningV3Claim) UnmarshalJSON(raw []byte) error {
	if !hasExactJSONFields(raw, "kind", "ip", "port", "transport", "domain", "scope") {
		return errors.New("invalid v3 claim")
	}
	type plain provisioningV3Claim
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*c = provisioningV3Claim(decoded)
	return nil
}

func (c provisioningV3Claim) protocolClaim() (protocol.Claim, error) {
	scope, err := provisioningScope(c.Scope)
	if err != nil {
		return protocol.Claim{}, err
	}
	return protocol.Claim{Kind: c.Kind, IP: c.IP, Port: c.Port, Transport: c.Transport, Domain: c.Domain, Scope: scope}, nil
}

func provisioningScope(value string) (protocol.RelayHostnameScope, error) {
	switch value {
	case "exact":
		return protocol.RelayHostnameScopeExact, nil
	case "wildcard":
		return protocol.RelayHostnameScopeWildcard, nil
	default:
		return "", errors.New("invalid relay hostname scope")
	}
}

func parseProvisioningV3(raw []byte, now time.Time) (*provisioningV3, error) {
	if len(raw) == 0 || len(raw) > maxProvisioningJSON || rejectDuplicateJSONKeys(raw) != nil {
		return nil, errors.New("invalid v3 provisioning")
	}
	var config provisioningV3
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil || rejectTrailingJSON(decoder) != nil || validateProvisioningV3(&config, now) != nil {
		return nil, errors.New("invalid v3 provisioning")
	}
	return &config, nil
}

func validateProvisioningV3(config *provisioningV3, now time.Time) error {
	if config.Version != 3 || len(config.Subscriptions) > maxV2Subscriptions {
		return errors.New("invalid")
	}
	seenSubscriptions := make(map[string]struct{}, len(config.Subscriptions))
	for _, subscription := range config.Subscriptions {
		if !hasV3SubscriptionFields(subscription) || validateSubscriptionID(subscription.SubscriptionID) != nil {
			return errors.New("invalid")
		}
		if _, exists := seenSubscriptions[subscription.SubscriptionID]; exists {
			return errors.New("invalid")
		}
		seenSubscriptions[subscription.SubscriptionID] = struct{}{}
		scope, err := provisioningScope(subscription.RelayHostnameScope)
		if err != nil || validateV3Subscription(subscription, scope) != nil || len(subscription.Edges) == 0 || len(subscription.Edges) > maxV2Edges {
			return errors.New("invalid")
		}
		seenIDs, seenEndpoints := map[string]struct{}{}, map[string]struct{}{}
		for _, edge := range subscription.Edges {
			if !v2EdgeID.MatchString(edge.ID) || validateCanonicalEndpoint(edge.Endpoint) != nil || !hasV3EdgeFields(edge) || validateV3EdgeBinding(subscription, scope, edge) != nil || validateV3Entitlement(edge.Entitlement, subscription.SubscriptionID, edge, now) != nil || validateEntitlementTimesV3(edge, now) != nil {
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

func hasV3SubscriptionFields(subscription provisioningV3Subscription) bool {
	return subscription.RelayHostnameScope != "" && (subscription.Product == string(protocol.ClaimIP) || subscription.Product == string(protocol.ClaimPort) || subscription.Product == string(protocol.ClaimRelay))
}

func validateV3Subscription(subscription provisioningV3Subscription, scope protocol.RelayHostnameScope) error {
	if protocol.ClaimKind(subscription.Product) != protocol.ClaimRelay && scope != protocol.RelayHostnameScopeExact {
		return errors.New("invalid")
	}
	base := provisioningSubscription{AssignedIP: subscription.AssignedIP, AssignedPort: subscription.AssignedPort, Transport: subscription.Transport, Domain: subscription.Domain, Product: subscription.Product, SubscriptionID: subscription.SubscriptionID}
	return validateV2Subscription(base)
}

func hasV3EdgeFields(edge provisioningV3Edge) bool {
	return edge.Claim.Scope != ""
}

func validateV3EdgeBinding(subscription provisioningV3Subscription, scope protocol.RelayHostnameScope, edge provisioningV3Edge) error {
	claim, err := edge.Claim.protocolClaim()
	if err != nil || protocol.ValidateClaim(&claim) != nil || claim.Scope != scope || claim.Kind != protocol.ClaimKind(subscription.Product) || (claim.IP != "" && !canonicalIP(claim.IP)) {
		return errors.New("invalid")
	}
	if claim.Kind == protocol.ClaimIP || claim.Kind == protocol.ClaimRelay {
		if claim.Transport != "" {
			return errors.New("invalid")
		}
	}
	switch claim.Kind {
	case protocol.ClaimIP:
		if claim.IP != *subscription.AssignedIP {
			return errors.New("invalid")
		}
	case protocol.ClaimPort:
		if claim.Port != *subscription.AssignedPort || string(claim.Transport) != subscription.Transport {
			return errors.New("invalid")
		}
	case protocol.ClaimRelay:
		if claim.Domain != *subscription.Domain {
			return errors.New("invalid")
		}
	}
	return nil
}

func validateV3Entitlement(value, subscriptionID string, edge provisioningV3Edge, now time.Time) error {
	payload, err := parseEntitlementMetadata(value)
	claim, claimErr := edge.Claim.protocolClaim()
	if err != nil || claimErr != nil || validateEntitlementMetadata(payload, now) != nil || payload.Subscription != subscriptionID || payload.Edge != edge.ID || payload.Kind != string(claim.Kind) || payload.IP != claim.IP || payload.Port != claim.Port || payload.Transport != string(claim.Transport) || payload.Domain != claim.Domain || payload.PaidThrough != edge.PaidThrough || payload.GraceThrough != edge.GraceThrough || payload.Generation != edge.Generation {
		return errors.New("invalid")
	}
	if (claim.Scope == protocol.RelayHostnameScopeWildcard && (payload.Version != 2 || payload.Scope != "wildcard")) || (claim.Scope == protocol.RelayHostnameScopeExact && (payload.Version != 1 || payload.Scope != "")) {
		return errors.New("invalid")
	}
	return nil
}

func validateEntitlementTimesV3(edge provisioningV3Edge, now time.Time) error {
	return validateEntitlementTimes(provisioningV2Edge{PaidThrough: edge.PaidThrough, GraceThrough: edge.GraceThrough, Generation: edge.Generation}, now)
}

type v3FetchError struct{ kind v2FetchKind }

func (e *v3FetchError) Error() string { return "v3 provisioning failure" }

func fetchProvisioningV3(ctx context.Context, client *http.Client, backend, token, instanceID string) (*provisioningV3, []byte, error) {
	if client == nil || !isCanonicalInstanceID(instanceID) {
		return nil, nil, &v3FetchError{kind: v2Terminal}
	}
	endpoint, err := url.Parse(strings.TrimRight(backend, "/") + "/api/v3/client/config")
	if err != nil {
		return nil, nil, &v3FetchError{kind: v2Terminal}
	}
	query := endpoint.Query()
	query.Set("instance_id", instanceID)
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, nil, &v3FetchError{kind: v2Terminal}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		return nil, nil, &v3FetchError{kind: v2Infrastructure}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, &v3FetchError{kind: v2FeatureUnavailable}
	}
	if resp.StatusCode >= 500 {
		return nil, nil, &v3FetchError{kind: v2Infrastructure}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, &v3FetchError{kind: v2Terminal}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxProvisioningJSON+1))
	if err != nil || len(raw) > maxProvisioningJSON {
		return nil, nil, &v3FetchError{kind: v2Terminal}
	}
	config, err := parseProvisioningV3(raw, time.Now())
	if err != nil || validateV3Identity(config, instanceID, -1) != nil {
		return nil, nil, &v3FetchError{kind: v2Terminal}
	}
	return config, raw, nil
}

func validateV3Identity(config *provisioningV3, instanceID string, generation int) error {
	for _, subscription := range config.Subscriptions {
		for _, edge := range subscription.Edges {
			bound, err := entitlementInstance(edge.Entitlement)
			if err != nil || bound != instanceID || (generation >= 0 && int(edge.Generation&((1<<generationBits)-1)) != generation) {
				return errors.New("invalid")
			}
		}
	}
	return nil
}

func buildV3MappingPlans(mappings []mapping, config *provisioningV3, relayOverride string) ([]workerPlan, error) {
	return buildV3MappingPlansWithMissing(mappings, config, relayOverride, false)
}

func buildAvailableV3MappingPlans(mappings []mapping, config *provisioningV3, relayOverride string) ([]workerPlan, error) {
	return buildV3MappingPlansWithMissing(mappings, config, relayOverride, true)
}

func buildV3MappingPlansWithMissing(mappings []mapping, config *provisioningV3, relayOverride string, allowMissing bool) ([]workerPlan, error) {
	if config == nil || validateProvisioningV3(config, time.Now()) != nil || validateMappings(mappings) != nil {
		return nil, errors.New("invalid v3 provisioning plans")
	}
	byID := make(map[string]provisioningV3Subscription, len(config.Subscriptions))
	for _, subscription := range config.Subscriptions {
		byID[subscription.SubscriptionID] = subscription
	}
	var plans []workerPlan
	for _, item := range mappings {
		subscription, ok := byID[item.SubscriptionID]
		if !ok {
			if allowMissing {
				continue
			}
			return nil, errors.New("configured subscription does not exist or is not active")
		}
		matched := 0
		for _, edge := range subscription.Edges {
			if relayOverride != "" && edge.Endpoint != relayOverride {
				continue
			}
			matched++
			claim, err := edge.Claim.protocolClaim()
			if err != nil {
				return nil, errors.New("invalid v3 claim")
			}
			if claim.Scope == protocol.RelayHostnameScopeWildcard && normalizedTLSMode(item.TLSMode) != tlsModePassthrough {
				return nil, errors.New("wildcard Relay claims require passthrough TLS")
			}
			if item.HTTPChallengeUpstream != "" && claim.Kind != protocol.ClaimRelay {
				return nil, errors.New("http challenge upstream is only valid for Relay")
			}
			if item.ProxyProtocol != "" && claim.Transport == protocol.TransportUDP {
				return nil, errors.New("proxy_protocol is not valid for UDP")
			}
			plans = append(plans, workerPlan{AccountName: item.AccountName, SubscriptionID: item.SubscriptionID, RelayAddr: edge.Endpoint, EdgeID: edge.ID, Entitlement: edge.Entitlement, Upstream: item.Upstream, HTTPChallengeUpstream: item.HTTPChallengeUpstream, TLSMode: normalizedTLSMode(item.TLSMode), ProxyProtocol: item.ProxyProtocol, Claim: &claim})
		}
		if relayOverride != "" && matched == 0 {
			return nil, errors.New("relay override does not match a signed v3 edge")
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
		key := workerKey{accountName: plan.AccountName, subscriptionID: plan.SubscriptionID, relayAddr: plan.RelayAddr}
		if _, exists := seenWorkers[key]; exists {
			return nil, errors.New("duplicate v3 worker plan")
		}
		seenWorkers[key] = struct{}{}
	}
	return plans, nil
}
