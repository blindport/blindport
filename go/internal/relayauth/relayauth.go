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
)

const maxResponseBody = 64 << 10

// ErrorKind classifies backend outcomes for authorization and readiness.
type ErrorKind string

const (
	ErrorDenied         ErrorKind = "denied"
	ErrorSecret         ErrorKind = "secret"
	ErrorInfrastructure ErrorKind = "infrastructure"
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
	AccountID    string      `json:"account_id"`
	UserID       int64       `json:"user_id"`
	IPs          []string    `json:"ip_ips"`
	RelayDomains []string    `json:"relay_domains"`
	PortLeases   []PortLease `json:"port_leases"`
}

// PortLease is one authorized shared TCP or UDP socket.
type PortLease struct {
	AssignedIP   string `json:"assigned_ip"`
	AssignedPort uint16 `json:"assigned_port"`
	Transport    string `json:"transport"`
}

// Resolve looks up a bearer token's resource bindings.
func (r *Resolver) Resolve(ctx context.Context, token string) (*Resolution, error) {
	body, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		return nil, infrastructure("encode resolve request", err)
	}
	var out Resolution
	err = r.postJSON(ctx, "/internal/v2/resolve", body, &out, true)
	if err == nil {
		return &out, nil
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.Status != http.StatusNotFound {
		return nil, err
	}
	out = Resolution{}
	if err = r.postJSON(ctx, "/internal/v1/resolve", body, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

// WireGuardPeer is one authorized routed peer in a desired-state snapshot.
type WireGuardPeer struct {
	PublicKey       string   `json:"public_key"`
	AllowedPrefixes []string `json:"allowed_prefixes"`
}

// WireGuardDesiredState is the complete routed-plane snapshot for one relay.
type WireGuardDesiredState struct {
	Revision            string          `json:"revision"`
	GeneratedAt         string          `json:"generated_at"`
	ManagedPrefixes     []string        `json:"managed_prefixes"`
	Peers               []WireGuardPeer `json:"peers"`
	SMTPAllowedPrefixes []string        `json:"smtp_allowed_prefixes"`
}

// WireGuardPeers fetches the complete desired routed-plane state.
func (r *Resolver) WireGuardPeers(ctx context.Context) (*WireGuardDesiredState, error) {
	var out WireGuardDesiredState
	err := r.getJSON(ctx, "/internal/v2/wireguard/peers", &out)
	if err == nil {
		return &out, nil
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.Status != http.StatusNotFound {
		return nil, err
	}
	var legacy struct {
		Revision        string          `json:"revision"`
		GeneratedAt     string          `json:"generated_at"`
		ManagedPrefixes []string        `json:"managed_prefixes"`
		Peers           []WireGuardPeer `json:"peers"`
	}
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

// RelayCert is the materials issued by POST /internal/v1/relay/cert.
type RelayCert struct {
	CACertPEM     string `json:"ca_cert_pem"`
	ServerCertPEM string `json:"server_cert_pem"`
	ServerKeyPEM  string `json:"server_key_pem"`
	NotAfter      string `json:"not_after"`
}

// FetchRelayCert asks the backend to issue a server cert for the given SANs.
func (r *Resolver) FetchRelayCert(ctx context.Context, hostnames, ips []string) (*RelayCert, error) {
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

func (r *Resolver) postJSON(ctx context.Context, path string, body []byte, out any, resolve bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.backendURL+path, bytes.NewReader(body))
	if err != nil {
		return infrastructure("create request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return r.doJSON(req, out, resolve)
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
		kind := ErrorInfrastructure
		if resp.StatusCode == http.StatusUnauthorized {
			kind = ErrorSecret
		} else if resolve && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden) {
			kind = ErrorDenied
		}
		return &Error{Kind: kind, Status: resp.StatusCode, Err: errors.New(http.StatusText(resp.StatusCode))}
	}

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		return infrastructure("read backend response", err)
	}
	if len(responseBody) > maxResponseBody {
		return infrastructure("read backend response", errors.New("response body exceeds limit"))
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return infrastructure("decode backend response", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return infrastructure("decode backend response", err)
	}
	return nil
}

func infrastructure(operation string, err error) error {
	return &Error{Kind: ErrorInfrastructure, Err: fmt.Errorf("%s: %w", operation, err)}
}
