package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/protocol"
	"github.com/blindport/blindport/internal/relayauth"
	"github.com/blindport/blindport/internal/tunnel"
)

func TestCertificateIdentity(t *testing.T) {
	accountID, err := parseCanonicalUUID("018f47b8-2c36-7d4e-9a51-123456789abc")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		state   tls.ConnectionState
		want    clientIdentity
		wantErr bool
	}{
		{name: "account", state: verifiedStateWithCN("account:018f47b8-2c36-7d4e-9a51-123456789abc"), want: clientIdentity{kind: clientIdentityAccount, accountID: accountID}},
		{name: "legacy user", state: verifiedStateWithCN("user:42"), want: clientIdentity{kind: clientIdentityUser, userID: 42}},
		{name: "missing verified chain", state: tls.ConnectionState{}, wantErr: true},
		{name: "empty verified chain", state: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}, wantErr: true},
		{name: "missing common name", state: verifiedStateWithCN(""), wantErr: true},
		{name: "wrong identity kind", state: verifiedStateWithCN("relay:42"), wantErr: true},
		{name: "missing account UUID", state: verifiedStateWithCN("account:"), wantErr: true},
		{name: "account UUID without hyphens", state: verifiedStateWithCN("account:018f47b82c367d4e9a51123456789abc"), wantErr: true},
		{name: "uppercase account UUID", state: verifiedStateWithCN("account:018F47B8-2C36-7D4E-9A51-123456789ABC"), wantErr: true},
		{name: "non-hex account UUID", state: verifiedStateWithCN("account:018f47b8-2c36-7d4e-9a51-123456789abz"), wantErr: true},
		{name: "missing user id", state: verifiedStateWithCN("user:"), wantErr: true},
		{name: "non-numeric user id", state: verifiedStateWithCN("user:alice"), wantErr: true},
		{name: "zero user id", state: verifiedStateWithCN("user:0"), wantErr: true},
		{name: "negative user id", state: verifiedStateWithCN("user:-1"), wantErr: true},
		{name: "non-canonical user id", state: verifiedStateWithCN("user:042"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := certificateIdentity(tt.state)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("certificateIdentity() = %+v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("certificateIdentity() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("certificateIdentity() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestMalformedControlLogOmitsPeerAddresses(t *testing.T) {
	var output bytes.Buffer
	r := &relay{
		log:     slog.New(slog.NewJSONHandler(&output, nil)),
		metrics: &relayMetrics{health: newRelayHealth(false, time.Minute, time.Minute)},
	}
	r.handleControlConn(context.Background(), addressErrorConn{})

	logged := output.String()
	if !strings.Contains(logged, "invalid control hello") {
		t.Fatalf("missing bounded failure event: %s", logged)
	}
	for _, address := range []string{"198.51.100.20", "203.0.113.40"} {
		if strings.Contains(logged, address) {
			t.Fatalf("control log exposed peer address %q: %s", address, logged)
		}
	}
}

func TestListenerFailureLogOmitsAddresses(t *testing.T) {
	var output bytes.Buffer
	health := newRelayHealth(false, time.Minute, time.Minute)
	r := &relay{
		log:     slog.New(slog.NewJSONHandler(&output, nil)),
		metrics: &relayMetrics{health: health},
	}
	r.listenerFailed("sni", &net.OpError{
		Op:     "accept",
		Net:    "tcp",
		Source: &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 443},
		Addr:   &net.TCPAddr{IP: net.ParseIP("203.0.113.40"), Port: 49152},
		Err:    errors.New("synthetic listener failure"),
	})

	logged := output.String()
	if !strings.Contains(logged, "relay listener failed") {
		t.Fatalf("missing bounded listener event: %s", logged)
	}
	for _, address := range []string{"198.51.100.20", "203.0.113.40"} {
		if strings.Contains(logged, address) {
			t.Fatalf("listener log exposed address %q: %s", address, logged)
		}
	}
}

type addressErrorConn struct{}

func (addressErrorConn) Read([]byte) (int, error) {
	return 0, &net.OpError{
		Op:     "read",
		Net:    "tcp",
		Source: &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 5443},
		Addr:   &net.TCPAddr{IP: net.ParseIP("203.0.113.40"), Port: 49152},
		Err:    errors.New("synthetic read failure"),
	}
}

func (addressErrorConn) Write(payload []byte) (int, error) { return len(payload), nil }
func (addressErrorConn) Close() error                      { return nil }
func (addressErrorConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 5443}
}
func (addressErrorConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("203.0.113.40"), Port: 49152}
}
func (addressErrorConn) SetDeadline(time.Time) error      { return nil }
func (addressErrorConn) SetReadDeadline(time.Time) error  { return nil }
func (addressErrorConn) SetWriteDeadline(time.Time) error { return nil }

func TestRequireCertificateIdentity(t *testing.T) {
	const account = "018f47b8-2c36-7d4e-9a51-123456789abc"
	tests := []struct {
		name       string
		commonName string
		resolution *relayauth.Resolution
		wantErr    bool
	}{
		{name: "account matches account field", commonName: "account:" + account, resolution: &relayauth.Resolution{AccountID: account, UserID: 99}},
		{name: "account ignores legacy user mismatch", commonName: "account:" + account, resolution: &relayauth.Resolution{AccountID: account, UserID: 43}},
		{name: "account mismatch", commonName: "account:" + account, resolution: &relayauth.Resolution{AccountID: "118f47b8-2c36-7d4e-9a51-123456789abc", UserID: 42}, wantErr: true},
		{name: "account missing", commonName: "account:" + account, resolution: &relayauth.Resolution{UserID: 42}, wantErr: true},
		{name: "account malformed in resolution", commonName: "account:" + account, resolution: &relayauth.Resolution{AccountID: "not-a-uuid", UserID: 42}, wantErr: true},
		{name: "legacy user matches user field", commonName: "user:42", resolution: &relayauth.Resolution{AccountID: account, UserID: 42}},
		{name: "legacy user ignores account mismatch", commonName: "user:42", resolution: &relayauth.Resolution{AccountID: "118f47b8-2c36-7d4e-9a51-123456789abc", UserID: 42}},
		{name: "legacy user mismatch", commonName: "user:42", resolution: &relayauth.Resolution{AccountID: account, UserID: 43}, wantErr: true},
		{name: "legacy user missing", commonName: "user:42", resolution: &relayauth.Resolution{AccountID: account}, wantErr: true},
		{name: "missing resolution", commonName: "user:42", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := requireCertificateIdentity(verifiedStateWithCN(tt.commonName), tt.resolution)
			if (err != nil) != tt.wantErr {
				t.Fatalf("requireCertificateIdentity() = (%+v, %v), wantErr %t", identity, err, tt.wantErr)
			}
		})
	}
}

func TestReauthorizationRequiresClose(t *testing.T) {
	now := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
	maxStaleness := 90 * time.Second
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "alice.example.com"}
	matching := &relayauth.Resolution{
		AccountID:    "018f47b8-2c36-7d4e-9a51-123456789abc",
		UserID:       42,
		RelayDomains: []string{"ALICE.EXAMPLE.COM"},
	}
	changedIdentities := &relayauth.Resolution{
		AccountID:    "118f47b8-2c36-7d4e-9a51-123456789abc",
		UserID:       43,
		RelayDomains: []string{"alice.example.com"},
	}
	changedUserOnly := &relayauth.Resolution{
		AccountID:    matching.AccountID,
		UserID:       43,
		RelayDomains: []string{"alice.example.com"},
	}
	changedAccountOnly := &relayauth.Resolution{
		AccountID:    changedIdentities.AccountID,
		UserID:       42,
		RelayDomains: []string{"alice.example.com"},
	}
	missingAccount := &relayauth.Resolution{UserID: 42, RelayDomains: []string{"alice.example.com"}}
	malformedAccount := &relayauth.Resolution{AccountID: "not-a-uuid", UserID: 42, RelayDomains: []string{"alice.example.com"}}
	missingUser := &relayauth.Resolution{AccountID: matching.AccountID, RelayDomains: []string{"alice.example.com"}}
	revokedClaim := &relayauth.Resolution{AccountID: matching.AccountID, UserID: 42}
	accountID, err := parseCanonicalUUID(matching.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	peerAccount := clientIdentity{kind: clientIdentityAccount, accountID: accountID}
	peerUser := clientIdentity{kind: clientIdentityUser, userID: 42}

	tests := []struct {
		name       string
		resolution *relayauth.Resolution
		err        error
		identity   *clientIdentity
		lastAuth   time.Time
		wantClose  bool
	}{
		{name: "authorized without mtls", resolution: matching, lastAuth: now.Add(-time.Hour)},
		{name: "account certificate matches", resolution: matching, identity: &peerAccount, lastAuth: now.Add(-time.Hour)},
		{name: "account certificate ignores changed user", resolution: changedUserOnly, identity: &peerAccount, lastAuth: now},
		{name: "account certificate rejects changed account", resolution: changedAccountOnly, identity: &peerAccount, lastAuth: now, wantClose: true},
		{name: "account certificate rejects missing account", resolution: missingAccount, identity: &peerAccount, lastAuth: now, wantClose: true},
		{name: "account certificate rejects malformed account", resolution: malformedAccount, identity: &peerAccount, lastAuth: now, wantClose: true},
		{name: "legacy certificate matches", resolution: matching, identity: &peerUser, lastAuth: now.Add(-time.Hour)},
		{name: "legacy certificate ignores changed account", resolution: changedAccountOnly, identity: &peerUser, lastAuth: now},
		{name: "legacy certificate rejects changed user", resolution: changedUserOnly, identity: &peerUser, lastAuth: now, wantClose: true},
		{name: "legacy certificate rejects missing user", resolution: missingUser, identity: &peerUser, lastAuth: now, wantClose: true},
		{name: "claim revoked", resolution: revokedClaim, identity: &peerAccount, lastAuth: now, wantClose: true},
		{name: "transient resolver error within limit", err: errors.New("backend unavailable"), identity: &peerAccount, lastAuth: now.Add(-maxStaleness + time.Nanosecond)},
		{name: "resolver error at limit", err: errors.New("backend unavailable"), identity: &peerAccount, lastAuth: now.Add(-maxStaleness), wantClose: true},
		{name: "resolver error beyond limit", err: errors.New("backend unavailable"), identity: &peerAccount, lastAuth: now.Add(-maxStaleness - time.Second), wantClose: true},
		{name: "empty successful resolution", identity: &peerAccount, lastAuth: now, wantClose: true},
		{name: "token denial closes immediately", err: &relayauth.Error{Kind: relayauth.ErrorDenied, Err: errors.New("missing")}, identity: &peerAccount, lastAuth: now, wantClose: true},
		{name: "secret rejection closes immediately", err: &relayauth.Error{Kind: relayauth.ErrorSecret, Err: errors.New("secret")}, identity: &peerAccount, lastAuth: now, wantClose: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reauthorizationRequiresClose(tt.resolution, tt.err, claim, tt.identity, tt.lastAuth, now, maxStaleness, false, false); got != tt.wantClose {
				t.Fatalf("reauthorizationRequiresClose() = %t, want %t", got, tt.wantClose)
			}
		})
	}
}

func TestSubscriptionAttributionRequiresCloseOnlyForAuthoritativeResolution(t *testing.T) {
	for _, test := range []struct {
		name       string
		resolution *relayauth.Resolution
		wantClose  bool
	}{
		{name: "legacy fallback without attribution", resolution: &relayauth.Resolution{}},
		{name: "authoritative matching attribution", resolution: &relayauth.Resolution{SubscriptionAuthoritative: true, SubscriptionID: testSubscriptionOne}},
		{name: "authoritative missing attribution", resolution: &relayauth.Resolution{SubscriptionAuthoritative: true}, wantClose: true},
		{name: "authoritative changed attribution", resolution: &relayauth.Resolution{SubscriptionAuthoritative: true, SubscriptionID: testSubscriptionTwo}, wantClose: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := subscriptionAttributionRequiresClose(test.resolution, testSubscriptionOne); got != test.wantClose {
				t.Fatalf("subscriptionAttributionRequiresClose() = %t, want %t", got, test.wantClose)
			}
		})
	}
}

func TestRelayServesOnlyConfiguredInventory(t *testing.T) {
	r := &relay{
		listenIPs: []string{"203.0.113.10"}, sharedIPs: []string{"203.0.113.20"},
		sharedTCPPorts: []uint16{10000, 10001}, sharedUDPPorts: []uint16{11000}, sniEnabled: true,
	}
	tests := []struct {
		claim *protocol.Claim
		want  bool
	}{
		{claim: &protocol.Claim{Kind: protocol.ClaimIP, IP: "203.0.113.10"}, want: true},
		{claim: &protocol.Claim{Kind: protocol.ClaimIP, IP: "203.0.113.11"}},
		{claim: &protocol.Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP}, want: true},
		{claim: &protocol.Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10002, Transport: protocol.TransportTCP}},
		{claim: &protocol.Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 11000, Transport: protocol.TransportUDP}, want: true},
		{claim: &protocol.Claim{Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportUDP}},
		{claim: &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "example.test"}, want: true},
	}
	for _, test := range tests {
		if got := r.servesClaim(test.claim); got != test.want {
			t.Fatalf("servesClaim(%+v) = %t, want %t", test.claim, got, test.want)
		}
	}
	r.sniEnabled = false
	if r.servesClaim(&protocol.Claim{Kind: protocol.ClaimRelay, Domain: "example.test"}) {
		t.Fatal("relay without SNI listener accepted Blindport Relay claim")
	}
	r.challengeEnabled = true
	if !r.servesClaim(&protocol.Claim{Kind: protocol.ClaimRelay, Domain: "example.test"}) {
		t.Fatal("relay with challenge ingress rejected Blindport Relay claim")
	}
}

type countingResolver struct {
	calls int
}

func (r *countingResolver) Resolve(context.Context, string, *protocol.Claim) (*relayauth.Resolution, error) {
	r.calls++
	return nil, errors.New("unexpected resolver call")
}

type allowedResolver struct{}

func (*allowedResolver) Resolve(context.Context, string, *protocol.Claim) (*relayauth.Resolution, error) {
	return &relayauth.Resolution{UserID: 42, IPs: []string{"203.0.113.10"}}, nil
}

type subscriptionChangingResolver struct{}

func (*subscriptionChangingResolver) Resolve(context.Context, string, *protocol.Claim) (*relayauth.Resolution, error) {
	return &relayauth.Resolution{
		UserID:                    42,
		IPs:                       []string{"203.0.113.10"},
		SubscriptionID:            testSubscriptionTwo,
		SubscriptionAuthoritative: true,
	}, nil
}

func TestReauthorizationClosesChangedSubscriptionAttribution(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	tunnelConn := tunnel.New(raw, nil)
	r := &relay{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), resolver: &subscriptionChangingResolver{},
		metrics:        &relayMetrics{health: newRelayHealth(false, time.Minute, time.Minute)},
		reauthInterval: 5 * time.Millisecond, reauthMaxStale: time.Second,
		bandwidth: testBandwidthReporter(),
	}
	done := make(chan struct{})
	go r.watchAuthorization(
		context.Background(), "token", &protocol.Claim{Kind: protocol.ClaimIP, IP: "203.0.113.10"},
		nil, nil, testSubscriptionOne, tunnelConn, done,
	)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("tunnel remained open after subscription attribution changed")
	}
}

func TestControlAdmissionIsReleasedAfterHello(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	health := newRelayHealth(false, time.Minute, time.Minute)
	r := &relay{
		log: slog.Default(), resolver: &allowedResolver{}, listenIPs: []string{"203.0.113.10"},
		metrics: &relayMetrics{health: health}, tunnels: map[string]*tunnel.Conn{},
		allTunnels: map[*tunnel.Conn]struct{}{}, reauthInterval: time.Hour,
		reauthMaxStale: time.Hour, maxStreamsPerTunnel: 1,
	}
	released := make(chan struct{})
	done := make(chan struct{})
	go func() {
		r.handleControlConnWithAdmission(ctx, server, func() { close(released) })
		close(done)
	}()
	claim := &protocol.Claim{Kind: protocol.ClaimIP, IP: "203.0.113.10"}
	if err := protocol.WriteFrame(client, &protocol.Frame{
		Type: protocol.TypeHello, Token: "token", Claim: claim,
		Capabilities: []protocol.Capability{protocol.CapabilityTCPHalfClose, protocol.CapabilityStreamFlowControl},
	}); err != nil {
		t.Fatal(err)
	}
	reply, err := protocol.ReadFrame(client)
	if err != nil || reply.Type != protocol.TypeHelloOK {
		t.Fatalf("HELLO reply = %+v, %v", reply, err)
	}
	if !reply.HasCapability(protocol.CapabilityTCPHalfClose) {
		t.Fatal("relay did not select offered TCP half-close capability")
	}
	if !reply.HasCapability(protocol.CapabilityStreamFlowControl) {
		t.Fatal("relay did not select offered stream flow-control capability")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("handshake admission was not released after HELLO")
	}
	cancel()
	<-done
}

func TestTunnelRegistryReplacementAndShutdown(t *testing.T) {
	health := newRelayHealth(false, time.Minute, time.Minute)
	r := &relay{
		metrics:             &relayMetrics{health: health},
		tunnels:             map[string]*tunnel.Conn{},
		tunnelSubscriptions: map[*tunnel.Conn]string{},
		allTunnels:          map[*tunnel.Conn]struct{}{},
	}
	firstRaw, firstPeer := net.Pipe()
	secondRaw, secondPeer := net.Pipe()
	thirdRaw, thirdPeer := net.Pipe()
	defer firstPeer.Close()
	defer secondPeer.Close()
	defer thirdPeer.Close()
	first := tunnel.New(firstRaw, nil)
	second := tunnel.New(secondRaw, nil)
	third := tunnel.New(thirdRaw, nil)

	r.registerTunnel("ip:203.0.113.10", protocol.ClaimIP, first, bandwidthTestUUID(1))
	r.registerTunnel("ip:203.0.113.10", protocol.ClaimIP, second, bandwidthTestUUID(2))
	assertPeerClosed(t, firstPeer)
	r.unregisterTunnel("ip:203.0.113.10", protocol.ClaimIP, first)
	if got := r.getTunnel("ip:203.0.113.10"); got != second {
		t.Fatalf("replacement tunnel = %p, want %p", got, second)
	}
	if got, subscriptionID := r.getTunnelSubscription("ip:203.0.113.10"); got != second || subscriptionID != bandwidthTestUUID(2) {
		t.Fatalf("replacement binding = %p/%q", got, subscriptionID)
	}

	r.registerTunnel("domain:alice.example", protocol.ClaimRelay, third)
	r.closeAllTunnels()
	assertPeerClosed(t, secondPeer)
	assertPeerClosed(t, thirdPeer)
	r.unregisterTunnel("ip:203.0.113.10", protocol.ClaimIP, second)
	r.unregisterTunnel("domain:alice.example", protocol.ClaimRelay, third)
	if got := r.metrics.tunnels[claimKindIndex(protocol.ClaimIP)].active.Load(); got != 0 {
		t.Fatalf("active Blindport IP tunnels = %d, want 0", got)
	}
	if got := r.metrics.tunnels[claimKindIndex(protocol.ClaimRelay)].active.Load(); got != 0 {
		t.Fatalf("active Blindport Relay tunnels = %d, want 0", got)
	}
}

func assertPeerClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return
	}
	var buffer [1]byte
	if _, err := conn.Read(buffer[:]); err == nil {
		t.Fatal("peer remained open")
	}
}

func TestUnservedClaimIsRejectedBeforeBackendResolution(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	resolver := &countingResolver{}
	health := newRelayHealth(false, time.Minute, time.Minute)
	r := &relay{
		log: slog.Default(), resolver: resolver, listenIPs: []string{"203.0.113.10"},
		metrics: &relayMetrics{health: health}, tunnels: map[string]*tunnel.Conn{},
		allTunnels: map[*tunnel.Conn]struct{}{},
	}
	done := make(chan struct{})
	go func() {
		r.handleControlConn(context.Background(), server)
		close(done)
	}()
	claim := &protocol.Claim{Kind: protocol.ClaimIP, IP: "203.0.113.11"}
	if err := protocol.WriteFrame(client, &protocol.Frame{Type: protocol.TypeHello, Token: "token", Claim: claim}); err != nil {
		t.Fatal(err)
	}
	reply, err := protocol.ReadFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != protocol.TypeHelloErr || resolver.calls != 0 {
		t.Fatalf("reply/calls = %+v/%d", reply, resolver.calls)
	}
	<-done
}

func TestValidateReauthorizationConfig(t *testing.T) {
	tests := []struct {
		name         string
		interval     time.Duration
		maxStaleness time.Duration
		wantErr      bool
	}{
		{name: "valid", interval: 45 * time.Second, maxStaleness: 90 * time.Second},
		{name: "equal is valid", interval: 45 * time.Second, maxStaleness: 45 * time.Second},
		{name: "nonpositive interval", maxStaleness: time.Minute, wantErr: true},
		{name: "staleness below interval", interval: time.Minute, maxStaleness: 59 * time.Second, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReauthorizationConfig(tt.interval, tt.maxStaleness)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateReauthorizationConfig() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestPortClaimKeyAndAuthorization(t *testing.T) {
	claim := &protocol.Claim{
		Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000, Transport: protocol.TransportTCP,
	}
	resolution := &relayauth.Resolution{
		PortLeases: []relayauth.PortLease{
			{AssignedIP: "203.0.113.20", AssignedPort: 10000, Transport: "tcp"},
		},
	}
	if got, want := claimKey(claim), "port:tcp:203.0.113.20:10000"; got != want {
		t.Fatalf("claimKey() = %q, want %q", got, want)
	}
	if !claimAllowed(resolution, claim) {
		t.Fatal("claimAllowed() rejected exact authorized socket")
	}
	claim.Port = 10001
	if claimAllowed(resolution, claim) {
		t.Fatal("claimAllowed() accepted a different port")
	}
	claim.Port = 10000
	claim.Transport = protocol.TransportUDP
	if claimAllowed(resolution, claim) {
		t.Fatal("claimAllowed() accepted a different transport")
	}
}

func TestRelayClaimScopeKeysAuthorizationAndSNILookup(t *testing.T) {
	health := newRelayHealth(false, time.Minute, time.Minute)
	r := &relay{
		metrics:    &relayMetrics{health: health},
		tunnels:    map[string]*tunnel.Conn{},
		allTunnels: map[*tunnel.Conn]struct{}{},
		sniEnabled: true,
	}
	exactRaw, exactPeer := net.Pipe()
	wildcardRaw, wildcardPeer := net.Pipe()
	longerRaw, longerPeer := net.Pipe()
	baseRaw, basePeer := net.Pipe()
	defer exactPeer.Close()
	defer wildcardPeer.Close()
	defer longerPeer.Close()
	defer basePeer.Close()
	exact := tunnel.New(exactRaw, nil)
	wildcard := tunnel.New(wildcardRaw, nil)
	longer := tunnel.New(longerRaw, nil)
	base := tunnel.New(baseRaw, nil)
	exactClaim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "api.public.example"}
	wildcardClaim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "public.example", Scope: protocol.RelayHostnameScopeWildcard}
	longerClaim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "api.public.example", Scope: protocol.RelayHostnameScopeWildcard}
	baseClaim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "nested.public.example", Scope: protocol.RelayHostnameScopeWildcard}
	r.registerTunnel(claimKey(exactClaim), exactClaim.Kind, exact)
	r.registerTunnel(claimKey(wildcardClaim), wildcardClaim.Kind, wildcard)
	r.registerTunnel(claimKey(longerClaim), longerClaim.Kind, longer)
	r.registerTunnel(claimKey(baseClaim), baseClaim.Kind, base)
	defer r.unregisterTunnel(claimKey(exactClaim), exactClaim.Kind, exact)
	defer r.unregisterTunnel(claimKey(wildcardClaim), wildcardClaim.Kind, wildcard)
	defer r.unregisterTunnel(claimKey(longerClaim), longerClaim.Kind, longer)
	defer r.unregisterTunnel(claimKey(baseClaim), baseClaim.Kind, base)

	if got, want := claimKey(exactClaim), "domain:api.public.example"; got != want {
		t.Fatalf("exact claim key = %q, want %q", got, want)
	}
	if got, want := claimKey(wildcardClaim), "domain:wildcard:public.example"; got != want {
		t.Fatalf("wildcard claim key = %q, want %q", got, want)
	}
	for _, test := range []struct {
		name     string
		hostname string
		wantKey  string
		wantOK   bool
	}{
		{name: "exact claim takes precedence over wildcard at same base", hostname: "api.public.example", wantKey: claimKey(exactClaim), wantOK: true},
		{name: "wildcard matches its base hostname", hostname: "public.example", wantKey: claimKey(wildcardClaim), wantOK: true},
		{name: "wildcard base takes precedence over parent suffix", hostname: "nested.public.example", wantKey: claimKey(baseClaim), wantOK: true},
		{name: "longest wildcard suffix matches descendant", hostname: "v1.api.public.example", wantKey: claimKey(longerClaim), wantOK: true},
		{name: "hostname without label boundary is rejected", hostname: "badpublic.example"},
		{name: "unrelated hostname is rejected", hostname: "unrelated.example"},
	} {
		t.Run(test.name, func(t *testing.T) {
			key, ok := r.relayTunnelKey(test.hostname)
			if key != test.wantKey || ok != test.wantOK {
				t.Fatalf("relayTunnelKey(%q) = %q, %t; want %q, %t", test.hostname, key, ok, test.wantKey, test.wantOK)
			}
		})
	}

	resolution := &relayauth.Resolution{
		RelayDomains: []string{"legacy.example"},
		RelayClaims: []relayauth.AuthorizedRelayClaim{
			{Domain: "public.example", Scope: protocol.RelayHostnameScopeWildcard},
		},
	}
	if !claimAllowed(resolution, &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "legacy.example"}) {
		t.Fatal("legacy exact authorization was rejected")
	}
	if claimAllowed(resolution, &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "legacy.example", Scope: protocol.RelayHostnameScopeWildcard}) {
		t.Fatal("legacy exact authorization authorized a wildcard claim")
	}
	if !claimAllowed(resolution, wildcardClaim) {
		t.Fatal("scope-aware wildcard authorization was rejected")
	}
	if claimAllowed(resolution, &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "public.example"}) {
		t.Fatal("wildcard authorization authorized an exact claim")
	}
	if r.servesClaim(wildcardClaim) != true {
		t.Fatal("SNI-enabled relay rejected wildcard claim")
	}
	r.sniEnabled = false
	r.challengeEnabled = true
	if r.servesClaim(wildcardClaim) {
		t.Fatal("HTTP-only relay accepted wildcard claim")
	}
}

func TestForwardToRelayUsesLogicalWildcardDestination(t *testing.T) {
	health := newRelayHealth(false, time.Minute, time.Minute)
	r := &relay{
		metrics:             &relayMetrics{health: health},
		tunnels:             make(map[string]*tunnel.Conn),
		tunnelSubscriptions: make(map[*tunnel.Conn]string),
		allTunnels:          make(map[*tunnel.Conn]struct{}),
	}
	wildcardRaw, agentRaw := net.Pipe()
	opened := make(chan *tunnel.Stream, 1)
	wildcard := tunnel.New(wildcardRaw, nil)
	agent := tunnel.New(agentRaw, func(stream *tunnel.Stream) {
		opened <- stream
		_ = stream.Close()
	})
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "public.example", Scope: protocol.RelayHostnameScopeWildcard}
	r.registerTunnel(claimKey(claim), claim.Kind, wildcard, testSubscriptionOne)
	go func() { _ = wildcard.Run() }()
	go func() { _ = agent.Run() }()
	defer r.unregisterTunnel(claimKey(claim), claim.Kind, wildcard)
	defer wildcard.Close()
	defer agent.Close()

	client, ingress := net.Pipe()
	done := make(chan bool, 1)
	go func() { done <- r.forwardToRelay(ingress, "a.public.example", "443") }()
	_ = client.Close()
	stream := <-opened
	if stream.Destination != "domain:a.public.example:443" || stream.DestinationAddress == "" {
		t.Fatalf("stream metadata = %+v", stream)
	}
	if !<-done {
		t.Fatal("forwardToRelay returned false")
	}
}

func TestParseRelayConfig(t *testing.T) {
	cfg, err := parseRelayConfig("203.0.113.10,203.0.113.11", "80,443", "203.0.113.20", "10000-10007", "11000-11007")
	if err != nil {
		t.Fatalf("parseRelayConfig() error = %v", err)
	}
	if len(cfg.sharedTCPPorts) != 8 || cfg.sharedTCPPorts[0] != 10000 || cfg.sharedTCPPorts[7] != 10007 {
		t.Fatalf("shared TCP ports = %v", cfg.sharedTCPPorts)
	}
	if len(cfg.sharedUDPPorts) != 8 || cfg.sharedUDPPorts[0] != 11000 || cfg.sharedUDPPorts[7] != 11007 {
		t.Fatalf("shared UDP ports = %v", cfg.sharedUDPPorts)
	}
	fullRange, err := parseRelayConfig("", "", "203.0.113.20", "10000-65535", "")
	if err != nil {
		t.Fatalf("parseRelayConfig() full shared range error = %v", err)
	}
	if len(fullRange.sharedTCPPorts) != 55536 || fullRange.sharedTCPPorts[0] != 10000 || fullRange.sharedTCPPorts[len(fullRange.sharedTCPPorts)-1] != 65535 {
		t.Fatalf("full shared TCP range = %d ports from %d to %d", len(fullRange.sharedTCPPorts), fullRange.sharedTCPPorts[0], fullRange.sharedTCPPorts[len(fullRange.sharedTCPPorts)-1])
	}

	invalid := []struct {
		name           string
		dedicatedIPs   string
		dedicatedPorts string
		sharedIPs      string
		sharedTCPPorts string
		sharedUDPPorts string
	}{
		{name: "overlap", dedicatedIPs: "203.0.113.20", dedicatedPorts: "80", sharedIPs: "203.0.113.20", sharedTCPPorts: "10000-10007"},
		{name: "missing shared range", dedicatedPorts: "80", sharedIPs: "203.0.113.20"},
		{name: "missing shared IP", dedicatedPorts: "80", sharedTCPPorts: "10000-10007"},
		{name: "bad TCP range", dedicatedPorts: "80", sharedIPs: "203.0.113.20", sharedTCPPorts: "10007-10000"},
		{name: "bad UDP range", dedicatedPorts: "80", sharedIPs: "203.0.113.20", sharedUDPPorts: "10007-10000"},
		{name: "duplicate IP", dedicatedIPs: "203.0.113.10,203.0.113.10", dedicatedPorts: "80"},
		{name: "bad port", dedicatedIPs: "203.0.113.10", dedicatedPorts: "0"},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseRelayConfig(tt.dedicatedIPs, tt.dedicatedPorts, tt.sharedIPs, tt.sharedTCPPorts, tt.sharedUDPPorts); err == nil {
				t.Fatal("parseRelayConfig() returned nil error")
			}
		})
	}
}

func TestParseControlListeners(t *testing.T) {
	tests := []struct {
		name    string
		primary string
		extras  string
		want    []string
		wantErr bool
	}{
		{name: "primary only", primary: ":5443", want: []string{":5443"}},
		{name: "additional listeners", primary: "0.0.0.0:5443", extras: "127.0.0.1:5444, [::1]:5445", want: []string{"0.0.0.0:5443", "127.0.0.1:5444", "[::1]:5445"}},
		{name: "empty primary", wantErr: true},
		{name: "empty first extra", primary: ":5443", extras: ",127.0.0.1:5444", wantErr: true},
		{name: "empty middle extra", primary: ":5443", extras: "127.0.0.1:5444,,127.0.0.1:5445", wantErr: true},
		{name: "empty last extra", primary: ":5443", extras: "127.0.0.1:5444,", wantErr: true},
		{name: "duplicate primary", primary: ":5443", extras: ":5443", wantErr: true},
		{name: "duplicate extra", primary: ":5443", extras: "127.0.0.1:5444,127.0.0.1:5444", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseControlListeners(tt.primary, tt.extras)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseControlListeners() error = %v, wantErr %t", err, tt.wantErr)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseControlListeners() = %v, want %v", got, tt.want)
			}
			for index := range got {
				if got[index] != tt.want[index] {
					t.Fatalf("parseControlListeners() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestValidateSNIProxyProtocol(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		listen  string
		enabled bool
		wantErr bool
	}{
		{name: "disabled", listen: ":4443"},
		{name: "IPv4 loopback", value: "v2", listen: "127.0.0.1:4443", enabled: true},
		{name: "IPv6 loopback", value: "v2", listen: "[::1]:4443", enabled: true},
		{name: "unsupported version", value: "v1", listen: "127.0.0.1:4443", wantErr: true},
		{name: "wildcard IPv4", value: "v2", listen: ":4443", wantErr: true},
		{name: "public IPv4", value: "v2", listen: "192.0.2.10:4443", wantErr: true},
		{name: "hostname", value: "v2", listen: "localhost:4443", wantErr: true},
		{name: "disabled listener", value: "v2", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enabled, err := validateSNIProxyProtocol(tt.value, tt.listen)
			if (err != nil) != tt.wantErr || enabled != tt.enabled {
				t.Fatalf("validateSNIProxyProtocol() = (%t, %v), want (%t, error=%t)", enabled, err, tt.enabled, tt.wantErr)
			}
		})
	}
}

func TestBindRelayListenersDoesNotBindSharedPortInventory(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(probe.Addr().(*net.TCPAddr).Port)
	_ = probe.Close()
	cfg := relayListenerConfig{
		sharedIPs: []string{"127.0.0.1"}, sharedTCPPorts: []uint16{port},
		sharedUDPPorts: []uint16{port},
	}
	listeners, err := bindRelayListeners([]string{"127.0.0.1:0"}, "", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBoundListeners(listeners)
	if len(listeners) != 2 {
		t.Fatalf("bound listener count = %d, want control and challenge", len(listeners))
	}
	var challengeFound bool
	for _, listener := range listeners {
		challengeFound = challengeFound || listener.kind == listenerChallenge && listener.listener != nil
	}
	if !challengeFound {
		t.Fatal("challenge listener was not bound")
	}
	tcp, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatalf("shared TCP inventory port was bound at startup: %v", err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatalf("shared UDP inventory port was bound at startup: %v", err)
	}
	defer udp.Close()
}

func TestBindRelayListenersBindsEveryControlAddress(t *testing.T) {
	listeners, err := bindRelayListeners([]string{"127.0.0.1:0", "127.0.0.1:0"}, "", "", relayListenerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeBoundListeners(listeners)
	if len(listeners) != 2 {
		t.Fatalf("bound listener count = %d, want 2", len(listeners))
	}
	for _, listener := range listeners {
		if listener.kind != listenerControl || listener.listener == nil {
			t.Fatalf("bound listener = %+v, want TCP control listener", listener)
		}
	}
}

func TestBindRelayListenersCleansUpAfterFailure(t *testing.T) {
	firstProbe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	firstAddr := firstProbe.Addr().String()
	_ = firstProbe.Close()

	blocked, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	if _, err := bindRelayListeners([]string{firstAddr, blocked.Addr().String()}, "", "", relayListenerConfig{}); err == nil {
		t.Fatal("bindRelayListeners() returned nil error for occupied additional control listener")
	}
	rebound, err := net.Listen("tcp", firstAddr)
	if err != nil {
		t.Fatalf("first listener remained bound after startup failure: %v", err)
	}
	_ = rebound.Close()
}

func TestMultipleControlListenersServeControlProtocol(t *testing.T) {
	listeners, err := bindRelayListeners([]string{"127.0.0.1:0", "127.0.0.1:0"}, "", "", relayListenerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	limits, err := newAdmissionLimits(limitConfig{
		controlHandshakes: 4, totalIngress: 4, sniPeeks: 1, challenges: 1,
		controlPerSource: 4, ingressPerSource: 4, challengeRate: 60, challengeBurst: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	health := newRelayHealth(false, time.Minute, time.Minute)
	r := &relay{
		log: slog.Default(), resolver: &allowedResolver{}, listenIPs: []string{"203.0.113.10"},
		limits: limits, metrics: &relayMetrics{health: health}, tunnels: map[string]*tunnel.Conn{},
		allTunnels: map[*tunnel.Conn]struct{}{}, reauthInterval: time.Hour,
		reauthMaxStale: time.Hour, maxStreamsPerTunnel: 1,
	}
	for _, bound := range listeners {
		go r.serveControl(ctx, bound.listener)
	}
	for _, bound := range listeners {
		conn, err := net.DialTimeout("tcp", bound.listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		claim := &protocol.Claim{Kind: protocol.ClaimIP, IP: "203.0.113.10"}
		if err := protocol.WriteFrame(conn, &protocol.Frame{Type: protocol.TypeHello, Token: "token", Claim: claim}); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		reply, err := protocol.ReadFrame(conn)
		_ = conn.Close()
		if err != nil || reply.Type != protocol.TypeHelloOK {
			t.Fatalf("control listener %s HELLO reply = %+v, %v", bound.listener.Addr(), reply, err)
		}
		if len(reply.Capabilities) != 0 {
			t.Fatalf("legacy HELLO selected capabilities %v", reply.Capabilities)
		}
	}
	cancel()
	closeBoundListeners(listeners)
	if !r.handlers.stopAndWait(time.Second) {
		t.Fatal("control handlers did not stop")
	}
}

func verifiedStateWithCN(commonName string) tls.ConnectionState {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: commonName}}
	return tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
}
