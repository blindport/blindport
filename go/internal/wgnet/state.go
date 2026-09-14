// Package wgnet validates and reconciles routed WireGuard Blindport IP state.
//
// The backend is authoritative for which peer owns which provider-routed /32.
// This package validates one complete desired snapshot and applies it to a
// Dataplane in a revocation-safe order: prefixes that lost their peer are
// blackholed before the peer set is replaced, and prefixes are activated only
// after their peer is configured.
package wgnet

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

// Peer is one authorized WireGuard peer and the routed prefixes it owns.
type Peer struct {
	PublicKey       string
	AllowedPrefixes []string
}

// DesiredState is one complete backend snapshot of the routed plane.
type DesiredState struct {
	Revision            string
	ManagedPrefixes     []string
	Peers               []Peer
	SMTPAllowedPrefixes []string
}

// ValidateKey rejects values that are not canonical base64 32-byte keys.
func ValidateKey(value string) error {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != value {
		return fmt.Errorf("WireGuard key %q must be canonical base64 for 32 bytes", value)
	}
	for _, b := range raw {
		if b != 0 {
			return nil
		}
	}
	return errors.New("WireGuard key must not be all zero")
}

// ValidatePrefix requires one canonical routed IPv4 /32 prefix.
func ValidatePrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid prefix %q", value)
	}
	if !prefix.Addr().Is4() || prefix.Bits() != 32 || prefix.String() != value {
		return netip.Prefix{}, fmt.Errorf("prefix %q must be one canonical IPv4 /32", value)
	}
	return prefix, nil
}

// Validate rejects malformed keys, unmanaged prefixes, and ownership overlap.
func (s *DesiredState) Validate() error {
	if s == nil {
		return errors.New("desired state is required")
	}
	managed := make(map[string]struct{}, len(s.ManagedPrefixes))
	for _, prefix := range s.ManagedPrefixes {
		if _, err := ValidatePrefix(prefix); err != nil {
			return err
		}
		if _, exists := managed[prefix]; exists {
			return fmt.Errorf("duplicate managed prefix %s", prefix)
		}
		managed[prefix] = struct{}{}
	}
	keys := make(map[string]struct{}, len(s.Peers))
	owners := make(map[string]struct{}, len(s.ManagedPrefixes))
	for _, peer := range s.Peers {
		if err := ValidateKey(peer.PublicKey); err != nil {
			return err
		}
		if _, exists := keys[peer.PublicKey]; exists {
			return errors.New("duplicate WireGuard peer public key")
		}
		keys[peer.PublicKey] = struct{}{}
		if len(peer.AllowedPrefixes) == 0 {
			return errors.New("peer must own at least one prefix")
		}
		for _, prefix := range peer.AllowedPrefixes {
			if _, exists := managed[prefix]; !exists {
				return fmt.Errorf("peer prefix %s is not managed inventory", prefix)
			}
			if _, exists := owners[prefix]; exists {
				return fmt.Errorf("prefix %s is owned by multiple peers", prefix)
			}
			owners[prefix] = struct{}{}
		}
	}
	smtpAllowed := make(map[string]struct{}, len(s.SMTPAllowedPrefixes))
	for _, prefix := range s.SMTPAllowedPrefixes {
		if _, err := ValidatePrefix(prefix); err != nil {
			return fmt.Errorf("SMTP allowed prefix: %w", err)
		}
		if _, exists := smtpAllowed[prefix]; exists {
			return fmt.Errorf("duplicate SMTP allowed prefix %s", prefix)
		}
		smtpAllowed[prefix] = struct{}{}
		if _, exists := managed[prefix]; !exists {
			return fmt.Errorf("SMTP allowed prefix %s is not managed inventory", prefix)
		}
		if _, active := owners[prefix]; !active {
			return fmt.Errorf("SMTP allowed prefix %s is not active", prefix)
		}
	}
	return nil
}

// ActivePrefixes returns the sorted prefixes currently owned by any peer.
func (s *DesiredState) ActivePrefixes() []string {
	active := make([]string, 0)
	for _, peer := range s.Peers {
		active = append(active, peer.AllowedPrefixes...)
	}
	sort.Strings(active)
	return active
}

// Dataplane applies WireGuard peer state and per-prefix routing decisions.
type Dataplane interface {
	// ApplyRoutedPolicy atomically replaces the managed forwarding policy.
	ApplyRoutedPolicy(activePrefixes, smtpAllowedPrefixes []string) error
	// ReplacePeers reconciles exactly this peer set on the device.
	ReplacePeers(peers []Peer) error
	// ActivateRoute routes one managed prefix into the WireGuard device.
	ActivateRoute(prefix string) error
	// BlackholeRoute drops one managed prefix at the relay.
	BlackholeRoute(prefix string) error
}

// Reconciler applies validated snapshots in a revocation-safe order.
type Reconciler struct {
	dataplane       Dataplane
	managedPrefixes []string
}

// NewReconciler wraps one dataplane.
func NewReconciler(dataplane Dataplane) *Reconciler {
	return &Reconciler{dataplane: dataplane}
}

// Apply validates and idempotently installs one complete snapshot.
func (r *Reconciler) Apply(state *DesiredState) error {
	if err := state.Validate(); err != nil {
		return fmt.Errorf("invalid desired state: %w", err)
	}
	owned := make(map[string]struct{})
	for _, prefix := range state.ActivePrefixes() {
		owned[prefix] = struct{}{}
	}
	managed := append([]string(nil), state.ManagedPrefixes...)
	sort.Strings(managed)
	allManaged := make(map[string]struct{}, len(managed)+len(r.managedPrefixes))
	for _, prefix := range managed {
		allManaged[prefix] = struct{}{}
	}
	for _, prefix := range r.managedPrefixes {
		allManaged[prefix] = struct{}{}
	}
	possiblyRevoked := make([]string, 0, len(allManaged))
	for prefix := range allManaged {
		possiblyRevoked = append(possiblyRevoked, prefix)
	}
	sort.Strings(possiblyRevoked)
	// Retain the union until every layer is reconciled so a later stale-state
	// fail-close also covers inventory introduced by a partially applied snapshot.
	r.managedPrefixes = possiblyRevoked

	// Revoked or unenrolled prefixes stop forwarding before peer replacement so
	// no packet can reach a peer that is about to lose authorization.
	for _, prefix := range possiblyRevoked {
		if _, active := owned[prefix]; active {
			continue
		}
		if err := r.dataplane.BlackholeRoute(prefix); err != nil {
			return fmt.Errorf("blackhole %s: %w", prefix, err)
		}
	}
	active := state.ActivePrefixes()
	smtpAllowed := append([]string(nil), state.SMTPAllowedPrefixes...)
	sort.Strings(smtpAllowed)
	if err := r.dataplane.ApplyRoutedPolicy(active, smtpAllowed); err != nil {
		return fmt.Errorf("apply routed firewall policy: %w", err)
	}
	peers := append([]Peer(nil), state.Peers...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].PublicKey < peers[j].PublicKey })
	if err := r.dataplane.ReplacePeers(peers); err != nil {
		applyErr := fmt.Errorf("replace WireGuard peers: %w", err)
		if failErr := r.failClosed(possiblyRevoked); failErr != nil {
			return errors.Join(applyErr, fmt.Errorf("fail closed after peer replacement failure: %w", failErr))
		}
		return applyErr
	}
	for _, prefix := range managed {
		if _, active := owned[prefix]; !active {
			continue
		}
		if err := r.dataplane.ActivateRoute(prefix); err != nil {
			return fmt.Errorf("activate %s: %w", prefix, err)
		}
	}
	r.managedPrefixes = managed
	return nil
}

// FailClosed removes every peer and blackholes all previously managed
// inventory after backend state has become too stale to trust.
func (r *Reconciler) FailClosed() error {
	return r.failClosed(r.managedPrefixes)
}

func (r *Reconciler) failClosed(prefixes []string) error {
	var failures []error
	// Peer removal is the fastest single operation that blocks both ingress and
	// egress. The independent policy and route layers are still attempted if it fails.
	if err := r.dataplane.ReplacePeers(nil); err != nil {
		failures = append(failures, fmt.Errorf("remove WireGuard peers: %w", err))
	}
	if err := r.dataplane.ApplyRoutedPolicy(nil, nil); err != nil {
		failures = append(failures, fmt.Errorf("apply empty routed firewall policy: %w", err))
	}
	for _, prefix := range prefixes {
		if err := r.dataplane.BlackholeRoute(prefix); err != nil {
			failures = append(failures, fmt.Errorf("blackhole %s: %w", prefix, err))
		}
	}
	return errors.Join(failures...)
}
