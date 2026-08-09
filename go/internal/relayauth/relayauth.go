// Package relayauth contacts the Blindport backend's internal control-plane
// endpoints.
package relayauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/blindport/blindport/internal/protocol"
)

const maxResponseBody = 64 << 10

// ErrorKind classifies backend outcomes for authorization and readiness.
type ErrorKind string

const (
	ErrorDenied         ErrorKind = "denied"
	ErrorSecret         ErrorKind = "secret"
	ErrorInfrastructure ErrorKind = "infrastructure"
	ErrorProtocol       ErrorKind = "protocol"
)

// Error is a typed backend failure.
type Error struct {
	Kind   ErrorKind
	Status int
	Err    error
}

func (e *Error) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("relay auth %s (status %d): %v", e.Kind, e.Status, e.Err)
	}
	return fmt.Sprintf("relay auth %s: %v", e.Kind, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// IsKind reports whether err is a backend error of kind.
func IsKind(err error, kind ErrorKind) bool {
	var typed *Error
	return errors.As(err, &typed) && typed.Kind == kind
}

// Resolver calls backend internal control-plane endpoints.
type Resolver struct {
	backendURL string
	secret     string
	http       *http.Client
}

// New validates backendURL and creates a Resolver with a bounded HTTP client.
func New(backendURL, secret string) (*Resolver, error) {
	parsed, err := url.Parse(backendURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("backend URL must be an absolute http(s) URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("backend URL must not contain credentials, query, or fragment")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return &Resolver{
		backendURL: strings.TrimRight(parsed.String(), "/"),
		secret:     secret,
		http: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Resolution is the resolver's reply.
type Resolution struct {
	AccountID      string                 `json:"account_id"`
	SubscriptionID string                 `json:"subscription_id"`
	UserID         int64                  `json:"user_id"`
	IPs            []string               `json:"ip_ips"`
	RelayDomains   []string               `json:"relay_domains"`
	RelayClaims    []AuthorizedRelayClaim `json:"relay_claims"`
	PortLeases     []PortLease            `json:"port_leases"`
}

// AuthorizedRelayClaim is one scope-aware Relay hostname authorization.
// RelayDomains remains for legacy exact hostname responses. Backend "exact"
// scope values are normalized to the protocol's zero-value exact scope.
type AuthorizedRelayClaim struct {
	Domain string                      `json:"domain"`
	Scope  protocol.RelayHostnameScope `json:"scope,omitempty"`
}

// UnmarshalJSON accepts the backend's explicit scope vocabulary while keeping
// the protocol Claim zero value canonical for exact scopes.
func (c *AuthorizedRelayClaim) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Domain string  `json:"domain"`
		Scope  *string `json:"scope"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	if wire.Scope == nil {
		return errors.New("relay claim scope is required")
	}
	var scope protocol.RelayHostnameScope
	switch *wire.Scope {
	case "exact":
		scope = protocol.RelayHostnameScopeExact
	case string(protocol.RelayHostnameScopeWildcard):
		scope = protocol.RelayHostnameScopeWildcard
	default:
		return errors.New("invalid relay claim scope")
	}
	claim := protocol.Claim{Kind: protocol.ClaimRelay, Domain: wire.Domain, Scope: scope}
	if err := protocol.ValidateClaim(&claim); err != nil {
		return errors.New("invalid relay claim")
	}
	*c = AuthorizedRelayClaim{Domain: wire.Domain, Scope: scope}
	return nil
}

// PortLease is one authorized shared TCP or UDP socket.
type PortLease struct {
	AssignedIP   string `json:"assigned_ip"`
	AssignedPort uint16 `json:"assigned_port"`
	Transport    string `json:"transport"`
}

// Resolve looks up a bearer token's resource bindings. V3 receives the claim
// binding; rollout-era endpoints retain their token-only request shape.
func (r *Resolver) Resolve(ctx context.Context, token string, claim *protocol.Claim) (*Resolution, error) {
	v3Body, err := json.Marshal(struct {
		Token string          `json:"token"`
		Claim *protocol.Claim `json:"claim,omitempty"`
	}{Token: token, Claim: claim})
	if err != nil {
		return nil, infrastructure("encode resolve request", err)
	}
	legacyBody, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		return nil, infrastructure("encode resolve request", err)
	}
	var out Resolution
	err = r.postJSON(ctx, "/internal/v3/resolve", v3Body, &out, true)
	if err == nil {
		return &out, nil
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.Status != http.StatusNotFound {
		return nil, err
	}
	if claim != nil && claim.Scope == protocol.RelayHostnameScopeWildcard {
		return nil, &Error{Kind: ErrorDenied, Status: http.StatusNotFound, Err: errors.New("wildcard claims require v3 resolution")}
	}
	out = Resolution{}
	err = r.postJSON(ctx, "/internal/v2/resolve", legacyBody, &out, true)
	if err == nil {
		return &out, nil
	}
	if !errors.As(err, &typed) || typed.Status != http.StatusNotFound {
		return nil, err
	}
	out = Resolution{}
	if err = r.postJSON(ctx, "/internal/v1/resolve", legacyBody, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

// WireGuardPeer is one authorized routed peer in a desired-state snapshot.
type WireGuardPeer struct {
	PublicKey       string   `json:"public_key"`
	AllowedPrefixes []string `json:"allowed_prefixes"`
}

// PrefixBinding attributes one active routed /32 to a subscription. It is
// deliberately kept separate from normal peer authorization state.
type PrefixBinding struct {
	Prefix         string `json:"prefix"`
	SubscriptionID string `json:"subscription_id"`
}

// WireGuardDesiredState is the complete routed-plane snapshot for one relay.
type WireGuardDesiredState struct {
	Revision            string          `json:"revision"`
	GeneratedAt         string          `json:"generated_at"`
	ManagedPrefixes     []string        `json:"managed_prefixes"`
	Peers               []WireGuardPeer `json:"peers"`
	SMTPAllowedPrefixes []string        `json:"smtp_allowed_prefixes"`
	PrefixBindings      []PrefixBinding `json:"prefix_bindings"`
}

// These response types deliberately model each deployed endpoint separately.
// Keeping the wire contracts distinct makes newer fields protocol errors when
// returned by an older endpoint.
type wireGuardPeersV3Wire struct {
	Revision            string          `json:"revision"`
	GeneratedAt         string          `json:"generated_at"`
	ManagedPrefixes     []string        `json:"managed_prefixes"`
	Peers               []WireGuardPeer `json:"peers"`
	SMTPAllowedPrefixes []string        `json:"smtp_allowed_prefixes"`
	PrefixBindings      []PrefixBinding `json:"prefix_bindings"`
}

type wireGuardPeersV2Wire struct {
	Revision            string          `json:"revision"`
	GeneratedAt         string          `json:"generated_at"`
	ManagedPrefixes     []string        `json:"managed_prefixes"`
	Peers               []WireGuardPeer `json:"peers"`
	SMTPAllowedPrefixes []string        `json:"smtp_allowed_prefixes"`
}

type wireGuardPeersV1Wire struct {
	Revision        string          `json:"revision"`
	GeneratedAt     string          `json:"generated_at"`
	ManagedPrefixes []string        `json:"managed_prefixes"`
	Peers           []WireGuardPeer `json:"peers"`
}

// WireGuardPeers fetches the complete desired routed-plane state.
func (r *Resolver) WireGuardPeers(ctx context.Context) (*WireGuardDesiredState, error) {
	var v3 wireGuardPeersV3Wire
	err := r.getJSON(ctx, "/internal/v3/wireguard/peers", &v3)
	if err == nil {
		return &WireGuardDesiredState{Revision: v3.Revision, GeneratedAt: v3.GeneratedAt, ManagedPrefixes: v3.ManagedPrefixes, Peers: v3.Peers, SMTPAllowedPrefixes: v3.SMTPAllowedPrefixes, PrefixBindings: v3.PrefixBindings}, nil
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.Status != http.StatusNotFound {
		return nil, err
	}
	var v2 wireGuardPeersV2Wire
	err = r.getJSON(ctx, "/internal/v2/wireguard/peers", &v2)
	if err == nil {
		return &WireGuardDesiredState{Revision: v2.Revision, GeneratedAt: v2.GeneratedAt, ManagedPrefixes: v2.ManagedPrefixes, Peers: v2.Peers, SMTPAllowedPrefixes: v2.SMTPAllowedPrefixes}, nil
	}
	if !errors.As(err, &typed) || typed.Status != http.StatusNotFound {
		return nil, err
	}
	var legacy wireGuardPeersV1Wire
	if err = r.getJSON(ctx, "/internal/v1/wireguard/peers", &legacy); err != nil {
		return nil, err
	}
	return &WireGuardDesiredState{
		Revision:        legacy.Revision,
		GeneratedAt:     legacy.GeneratedAt,
		ManagedPrefixes: legacy.ManagedPrefixes,
		Peers:           legacy.Peers,
	}, nil
}

// DailyBandwidthReport is one subscriber-relative UTC-day total.
type DailyBandwidthReport struct {
	SubscriptionID string `json:"subscription_id"`
	Day            string `json:"day"`
	IngressBytes   int64  `json:"ingress_bytes"`
	EgressBytes    int64  `json:"egress_bytes"`
}

// DailyBandwidthBatch is an idempotent relay report. No resource or traffic
// metadata is included in this contract.
type DailyBandwidthBatch struct {
	EdgeID   string                 `json:"edge_id"`
	BootID   string                 `json:"boot_id"`
	Sequence int64                  `json:"sequence"`
	Reports  []DailyBandwidthReport `json:"reports"`
}

// ReportDailyBandwidth posts one bounded idempotent daily report batch.
func (r *Resolver) ReportDailyBandwidth(ctx context.Context, token string, batch DailyBandwidthBatch) error {
	if !isLowerHexToken(token) {
		return protocolFailure("validate bandwidth token", errors.New("heartbeat token must be exactly 64 lowercase hexadecimal characters"))
	}
	if batch.EdgeID == "" || len(batch.EdgeID) > 32 || batch.Sequence < 0 || len(batch.Reports) == 0 || len(batch.Reports) > 1000 {
		return protocolFailure("validate bandwidth request", errors.New("invalid bandwidth report batch"))
	}
	if !canonicalUUID(batch.BootID) {
		return protocolFailure("validate bandwidth request", errors.New("invalid boot ID"))
	}
	for _, report := range batch.Reports {
		if !canonicalUUID(report.SubscriptionID) || !canonicalDay(report.Day) || report.IngressBytes < 0 || report.EgressBytes < 0 {
			return protocolFailure("validate bandwidth request", errors.New("invalid bandwidth report"))
		}
	}
	body, err := json.Marshal(batch)
	if err != nil {
		return infrastructure("encode bandwidth request", err)
	}
	var acknowledgment struct {
		Status string `json:"status"`
	}
	if err := r.postJSONWithHeader(ctx, "/internal/v1/relay/bandwidth/daily", body, &acknowledgment, false, "X-Relay-Heartbeat-Token", token); err != nil {
		return err
	}
	if acknowledgment.Status != "accepted" {
		return protocolFailure("validate bandwidth response", errors.New("unexpected bandwidth status"))
	}
	return nil
}

func canonicalUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for i := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		c := value[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func canonicalDay(value string) bool {
	if len(value) != len("2006-01-02") {
		return false
	}
	parsed, err := time.Parse("2006-01-02", value)
	return err == nil && parsed.Format("2006-01-02") == value
}

// RelayCert is the materials issued by POST /internal/v1/relay/cert.
type RelayCert struct {
	CACertPEM     string `json:"ca_cert_pem"`
	ServerCertPEM string `json:"server_cert_pem"`
	ServerKeyPEM  string `json:"server_key_pem"`
	NotAfter      string `json:"not_after"`
}

// HealthComponents reports the relay's fixed health component states.
type HealthComponents struct {
	Authorization string `json:"authorization"`
	Certificate   string `json:"certificate"`
	Lifecycle     string `json:"lifecycle"`
	Listeners     string `json:"listeners"`
	WireGuard     string `json:"wireguard"`
}

// Heartbeat is a fixed-cardinality relay health and traffic snapshot.
type Heartbeat struct {
	EdgeID                   string           `json:"edge_id"`
	Ready                    bool             `json:"ready"`
	Components               HealthComponents `json:"components"`
	ActiveTunnels            int64            `json:"active_tunnels"`
	ActiveStreams            int64            `json:"active_streams"`
	AcceptedConnectionsTotal int64            `json:"accepted_connections_total"`
	ForwardedBytesTotal      int64            `json:"forwarded_bytes_total"`
}

// FetchRelayCert asks the backend to issue a server cert for the given SANs.
func (r *Resolver) FetchRelayCert(ctx context.Context, hostnames, ips []string) (*RelayCert, error) {
	if hostnames == nil {
		hostnames = []string{}
	}
	if ips == nil {
		ips = []string{}
	}
	body, err := json.Marshal(map[string]any{"hostnames": hostnames, "ips": ips})
	if err != nil {
		return nil, infrastructure("encode certificate request", err)
	}
	var out RelayCert
	if err := r.postJSON(ctx, "/internal/v1/relay/cert", body, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

// ReportHeartbeat sends a relay health and traffic snapshot to the backend.
func (r *Resolver) ReportHeartbeat(ctx context.Context, token string, heartbeat Heartbeat) error {
	if !isLowerHexToken(token) {
		return protocolFailure("validate heartbeat token", errors.New("heartbeat token must be exactly 64 lowercase hexadecimal characters"))
	}
	if heartbeat.ActiveTunnels < 0 || heartbeat.ActiveStreams < 0 || heartbeat.AcceptedConnectionsTotal < 0 || heartbeat.ForwardedBytesTotal < 0 {
		return protocolFailure("validate heartbeat request", errors.New("heartbeat values must be nonnegative"))
	}
	body, err := json.Marshal(heartbeat)
	if err != nil {
		return infrastructure("encode heartbeat request", err)
	}
	var acknowledgment struct {
		Status string `json:"status"`
	}
	if err := r.postJSONWithHeader(ctx, "/internal/v1/relay/heartbeat", body, &acknowledgment, false, "X-Relay-Heartbeat-Token", token); err != nil {
		return err
	}
	if acknowledgment.Status != "accepted" {
		return protocolFailure("validate heartbeat response", errors.New("unexpected heartbeat status"))
	}
	return nil
}

func (r *Resolver) postJSON(ctx context.Context, path string, body []byte, out any, resolve bool) error {
	return r.postJSONWithHeader(ctx, path, body, out, resolve, "", "")
}

func (r *Resolver) postJSONWithHeader(ctx context.Context, path string, body []byte, out any, resolve bool, header, value string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.backendURL+path, bytes.NewReader(body))
	if err != nil {
		return infrastructure("create request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if header != "" {
		req.Header.Set(header, value)
	}
	return r.doJSON(req, out, resolve)
}

func isLowerHexToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	for index := range token {
		character := token[index]
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func (r *Resolver) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.backendURL+path, nil)
	if err != nil {
		return infrastructure("create request", err)
	}
	return r.doJSON(req, out, false)
}

func (r *Resolver) doJSON(req *http.Request, out any, resolve bool) error {
	req.Header.Set("X-Relay-Secret", r.secret)
	resp, err := r.http.Do(req)
	if err != nil {
		return infrastructure("request backend", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody+1))
		kind := classifyStatus(resp.StatusCode, resolve)
		return &Error{Kind: kind, Status: resp.StatusCode, Err: errors.New(http.StatusText(resp.StatusCode))}
	}

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		return infrastructure("read backend response", err)
	}
	if len(responseBody) > maxResponseBody {
		return protocolFailure("read backend response", errors.New("response body exceeds limit"))
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return protocolFailure("decode backend response", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return protocolFailure("decode backend response", err)
	}
	return nil
}

func infrastructure(operation string, err error) error {
	return &Error{Kind: ErrorInfrastructure, Err: fmt.Errorf("%s: %w", operation, err)}
}

func protocolFailure(operation string, err error) error {
	return &Error{Kind: ErrorProtocol, Err: fmt.Errorf("%s: %w", operation, err)}
}

func classifyStatus(status int, resolve bool) ErrorKind {
	switch {
	case status == http.StatusUnauthorized:
		return ErrorSecret
	case resolve && (status == http.StatusForbidden || status == http.StatusNotFound):
		return ErrorDenied
	case status >= http.StatusInternalServerError:
		return ErrorInfrastructure
	default:
		return ErrorProtocol
	}
}
