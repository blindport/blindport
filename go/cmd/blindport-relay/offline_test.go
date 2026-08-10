package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/protocol"
	"github.com/blindport/blindport/internal/relayauth"
	"github.com/blindport/blindport/internal/tunnel"
)

const (
	offlineTestAccount  = "12345678-1234-4234-8234-123456789abc"
	offlineTestInstance = "11111111-2222-4333-8444-555555555555"
)

type offlineTestFixture struct {
	artifact     string
	claim        *protocol.Claim
	client       tls.Certificate
	server       tls.Certificate
	clientRoots  *x509.CertPool
	identity     clientIdentity
	keyringJSON  string
	graceThrough time.Time
}

type staticResolver struct {
	resolution *relayauth.Resolution
	err        error
}

func (r staticResolver) Resolve(context.Context, string, *protocol.Claim) (*relayauth.Resolution, error) {
	return r.resolution, r.err
}

func TestOfflineCertificateIdentityRequiresExactV2Certificate(t *testing.T) {
	fixture := newOfflineTestFixture(t, time.Now().UTC().Truncate(time.Second))
	certificate, err := x509.ParseCertificate(fixture.client.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	validState := tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certificate}}}

	identity, err := offlineCertificateIdentity(validState)
	if err != nil {
		t.Fatalf("offlineCertificateIdentity() error = %v", err)
	}
	if identity.kind != clientIdentityAccount || identity.accountID != fixture.identity.accountID || identity.instanceID != fixture.identity.instanceID || !identity.offlineV2 || !reflect.DeepEqual(identity.clientPublicKey, fixture.identity.clientPublicKey) {
		t.Fatalf("offline identity = %+v", identity)
	}

	makeState := func(commonName, rawURI string, uriCount int, publicKey any) tls.ConnectionState {
		cert := &x509.Certificate{Subject: pkix.Name{CommonName: commonName}, PublicKey: publicKey}
		if uriCount > 0 {
			uri, parseErr := url.Parse(rawURI)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			cert.URIs = []*url.URL{uri}
		}
		if uriCount > 1 {
			cert.URIs = append(cert.URIs, cert.URIs[0])
		}
		return tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
	}
	for _, test := range []struct {
		name       string
		commonName string
		uri        string
		uriCount   int
		publicKey  any
	}{
		{name: "legacy user", commonName: "user:42", uri: "urn:blindport:client:" + offlineTestInstance, uriCount: 1, publicKey: certificate.PublicKey},
		{name: "missing URI", commonName: "account:" + offlineTestAccount, publicKey: certificate.PublicKey},
		{name: "multiple URIs", commonName: "account:" + offlineTestAccount, uri: "urn:blindport:client:" + offlineTestInstance, uriCount: 2, publicKey: certificate.PublicKey},
		{name: "URL scheme", commonName: "account:" + offlineTestAccount, uri: "https://blindport/client/" + offlineTestInstance, uriCount: 1, publicKey: certificate.PublicKey},
		{name: "encoded UUID", commonName: "account:" + offlineTestAccount, uri: "urn:blindport:client:%31" + offlineTestInstance[1:], uriCount: 1, publicKey: certificate.PublicKey},
		{name: "URI query", commonName: "account:" + offlineTestAccount, uri: "urn:blindport:client:" + offlineTestInstance + "?edge=a", uriCount: 1, publicKey: certificate.PublicKey},
		{name: "uppercase UUID", commonName: "account:" + offlineTestAccount, uri: "urn:blindport:client:11111111-2222-4333-8444-55555555555A", uriCount: 1, publicKey: certificate.PublicKey},
		{name: "non Ed25519 key", commonName: "account:" + offlineTestAccount, uri: "urn:blindport:client:" + offlineTestInstance, uriCount: 1, publicKey: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := offlineCertificateIdentity(makeState(test.commonName, test.uri, test.uriCount, test.publicKey)); err == nil {
				t.Fatal("offlineCertificateIdentity() accepted an invalid certificate")
			}
		})
	}
}

func TestOfflineControlAdmissionSurvivesResolverOutageAfterRestart(t *testing.T) {
	fixture := newOfflineTestFixture(t, time.Now().UTC().Truncate(time.Second))
	for restart := range 2 {
		t.Run("fresh relay", func(t *testing.T) {
			r := newOfflineTestRelay(t, fixture, staticResolver{err: &relayauth.Error{Kind: relayauth.ErrorInfrastructure, Err: errors.New("backend unavailable")}})
			released := make(chan struct{})
			client, done := startOfflineControl(t, r, fixture, func() { close(released) })
			defer client.Close()
			_ = restart

			// A new relay has no prior authorization state, so this models a restart during an outage.
			if err := writeOfflineHello(client, fixture, fixture.artifact); err != nil {
				t.Fatal(err)
			}
			reply, err := protocol.ReadFrame(client)
			if err != nil || reply.Type != protocol.TypeHelloOK {
				t.Fatalf("HELLO reply = %+v, %v", reply, err)
			}
			select {
			case <-released:
			case <-time.After(time.Second):
				t.Fatal("handshake admission was not released")
			}
			if !waitForOfflineTest(time.Second, func() bool {
				return r.metrics.entitlement[entitlementOffline].Load() == 1 && r.metrics.control[controlAccepted].Load() == 1
			}) {
				t.Fatal("offline authorization was not recorded")
			}
			client.Close()
			<-done
		})
	}
}

func TestOfflineControlFallbackAndFeatureGate(t *testing.T) {
	fixture := newOfflineTestFixture(t, time.Now().UTC().Truncate(time.Second))
	for _, test := range []struct {
		name     string
		resolver staticResolver
		enabled  bool
		artifact string
		wantOK   bool
		wantCaps []protocol.Capability
	}{
		{
			name: "infrastructure fallback", resolver: staticResolver{err: &relayauth.Error{Kind: relayauth.ErrorInfrastructure, Err: errors.New("backend unavailable")}}, enabled: true,
			artifact: fixture.artifact, wantOK: true,
			wantCaps: []protocol.Capability{protocol.CapabilityTCPHalfClose, protocol.CapabilityStreamFlowControl, protocol.CapabilityOfflineEntitlementV1},
		},
		{name: "denial never falls back", resolver: staticResolver{err: &relayauth.Error{Kind: relayauth.ErrorDenied, Err: errors.New("denied")}}, enabled: true, artifact: fixture.artifact},
		{name: "secret never falls back", resolver: staticResolver{err: &relayauth.Error{Kind: relayauth.ErrorSecret, Err: errors.New("secret")}}, enabled: true, artifact: fixture.artifact},
		{name: "protocol never falls back", resolver: staticResolver{err: &relayauth.Error{Kind: relayauth.ErrorProtocol, Err: errors.New("protocol")}}, enabled: true, artifact: fixture.artifact},
		{name: "untyped failure never falls back", resolver: staticResolver{err: errors.New("unknown")}, enabled: true, artifact: fixture.artifact},
		{
			name: "disabled ignores artifact", resolver: staticResolver{resolution: matchingOfflineResolution()}, artifact: "invalid", wantOK: true,
			wantCaps: []protocol.Capability{protocol.CapabilityTCPHalfClose, protocol.CapabilityStreamFlowControl},
		},
		{name: "online acknowledged proof verifies", resolver: staticResolver{resolution: matchingOfflineResolution()}, enabled: true, artifact: "invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := newOfflineTestRelay(t, fixture, test.resolver)
			if !test.enabled {
				r.offlineEntitlements = nil
				r.tlsConfig = nil
			}
			client, done := startOfflineControl(t, r, fixture, func() {})
			defer client.Close()
			if err := writeOfflineHello(client, fixture, test.artifact); err != nil {
				t.Fatal(err)
			}
			reply, err := protocol.ReadFrame(client)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantOK {
				if reply.Type != protocol.TypeHelloOK || !reflect.DeepEqual(reply.Capabilities, test.wantCaps) {
					t.Fatalf("HELLO reply = %+v, want capabilities %v", reply, test.wantCaps)
				}
				if !waitForOfflineTest(time.Second, func() bool { return r.metrics.control[controlAccepted].Load() == 1 }) {
					t.Fatal("accepted control connection was not recorded")
				}
			} else if reply.Type != protocol.TypeHelloErr || r.metrics.control[controlAccepted].Load() != 0 || r.metrics.entitlement[entitlementOffline].Load() != 0 {
				t.Fatalf("HELLO reply/metrics = %+v/%d/%d", reply, r.metrics.control[controlAccepted].Load(), r.metrics.entitlement[entitlementOffline].Load())
			}
			_ = client.Close()
			<-done
		})
	}
}

func waitForOfflineTest(timeout time.Duration, condition func() bool) bool {
	deadline := time.Now().Add(timeout)
	for !condition() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	return condition()
}

func writeOfflineHello(client *tls.Conn, fixture offlineTestFixture, artifact string) error {
	return protocol.WriteFrame(client, &protocol.Frame{
		Type: protocol.TypeHello, Token: "test-token", Claim: fixture.claim, Entitlement: artifact,
		Capabilities: []protocol.Capability{protocol.CapabilityTCPHalfClose, protocol.CapabilityStreamFlowControl, protocol.CapabilityOfflineEntitlementV1},
	})
}

func TestOfflineReauthorizationBoundariesAndErrorKinds(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fixture := newOfflineTestFixture(t, now)
	r := newOfflineTestRelay(t, fixture, staticResolver{})
	if _, err := r.verifyOfflineEntitlement(fixture.artifact, fixture.claim, fixture.identity, fixture.graceThrough); err != nil {
		t.Fatalf("entitlement at grace boundary rejected: %v", err)
	}
	if _, err := r.verifyOfflineEntitlement(fixture.artifact, fixture.claim, fixture.identity, fixture.graceThrough.Add(time.Second)); err == nil {
		t.Fatal("entitlement after grace boundary accepted")
	}

	lastAuthorized := now.Add(-90 * time.Second)
	if reauthorizationRequiresClose(nil, &relayauth.Error{Kind: relayauth.ErrorInfrastructure, Err: errors.New("outage")}, fixture.claim, &fixture.identity, lastAuthorized, now, 90*time.Second, true, true) {
		t.Fatal("valid infrastructure fallback closed at the legacy staleness boundary")
	}
	if !reauthorizationRequiresClose(nil, &relayauth.Error{Kind: relayauth.ErrorInfrastructure, Err: errors.New("outage")}, fixture.claim, &fixture.identity, lastAuthorized, now, 90*time.Second, false, true) {
		t.Fatal("invalid infrastructure fallback retained a tunnel")
	}
	if reauthorizationRequiresClose(matchingOfflineResolution(), nil, fixture.claim, &fixture.identity, lastAuthorized, fixture.graceThrough.Add(time.Second), 90*time.Second, false, true) {
		t.Fatal("online authorization was not authoritative after entitlement expiry")
	}
	if !reauthorizationRequiresClose(nil, &relayauth.Error{Kind: relayauth.ErrorProtocol, Err: errors.New("protocol")}, fixture.claim, &fixture.identity, now, now, 90*time.Second, true, true) {
		t.Fatal("protocol failure retained a tunnel")
	}
	if !reauthorizationRequiresClose(nil, errors.New("untyped"), fixture.claim, &fixture.identity, lastAuthorized, now, 90*time.Second, true, true) {
		t.Fatal("untyped failure used offline proof fallback")
	}
}

func newOfflineTestRelay(t *testing.T, fixture offlineTestFixture, resolver tokenResolver) *relay {
	t.Helper()
	config, err := parseOfflineEntitlementConfig(true, fixture.keyringJSON, "edge-a", int(maxOfflineEntitlementGrace/time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return &relay{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), resolver: resolver,
		sharedIPs: []string{fixture.claim.IP}, sharedTCPPorts: []uint16{fixture.claim.Port},
		tlsConfig: &tls.Config{}, offlineEntitlements: config, reauthInterval: time.Hour,
		reauthMaxStale: 90 * time.Second, maxStreamsPerTunnel: 1,
		metrics: &relayMetrics{health: newRelayHealth(true, time.Minute, 90*time.Second)},
		tunnels: map[string]*tunnel.Conn{}, allTunnels: map[*tunnel.Conn]struct{}{},
	}
}

func startOfflineControl(t *testing.T, r *relay, fixture offlineTestFixture, release func()) (*tls.Conn, <-chan struct{}) {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	server := tls.Server(serverRaw, &tls.Config{
		Certificates: []tls.Certificate{fixture.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: fixture.clientRoots,
	})
	client := tls.Client(clientRaw, &tls.Config{Certificates: []tls.Certificate{fixture.client}, InsecureSkipVerify: true}) // #nosec G402, local generated test certificate
	done := make(chan struct{})
	go func() {
		r.handleControlConnWithAdmission(context.Background(), server, release)
		close(done)
	}()
	return client, done
}

func matchingOfflineResolution() *relayauth.Resolution {
	return &relayauth.Resolution{
		AccountID:      offlineTestAccount,
		SubscriptionID: testSubscriptionOne,
		PortLeases:     []relayauth.PortLease{{AssignedIP: "198.51.100.30", AssignedPort: 10000, Transport: "tcp"}},
	}
}

func newOfflineTestFixture(t *testing.T, now time.Time) offlineTestFixture {
	t.Helper()
	caKey := mustEd25519Key(t)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Blindport test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER := createCertificate(t, caTemplate, caTemplate, caKey.Public(), caKey)
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	clientSeed := make([]byte, ed25519.SeedSize)
	for index := range clientSeed {
		clientSeed[index] = byte(index)
	}
	clientKey := ed25519.NewKeyFromSeed(clientSeed)
	instanceURI, err := url.Parse("urn:blindport:client:" + offlineTestInstance)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "account:" + offlineTestAccount}, URIs: []*url.URL{instanceURI},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER := createCertificate(t, clientTemplate, caCertificate, clientKey.Public(), caKey)
	serverKey := mustEd25519Key(t)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "relay.test"}, DNSNames: []string{"relay.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER := createCertificate(t, serverTemplate, caCertificate, serverKey.Public(), caKey)
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)

	accountID, err := parseCanonicalUUID(offlineTestAccount)
	if err != nil {
		t.Fatal(err)
	}
	instanceID, err := parseCanonicalUUID(offlineTestInstance)
	if err != nil {
		t.Fatal(err)
	}
	clientPublicKey := clientKey.Public().(ed25519.PublicKey)
	claim := &protocol.Claim{Kind: protocol.ClaimPort, IP: "198.51.100.30", Port: 10000, Transport: protocol.TransportTCP}
	graceThrough := now.Add(time.Hour)
	signingSeed := make([]byte, ed25519.SeedSize)
	for index := range signingSeed {
		signingSeed[index] = byte(index + 1)
	}
	signingKey := ed25519.NewKeyFromSeed(signingSeed)
	keyringJSON, err := json.Marshal(map[string]string{"offline-a": base64.RawURLEncoding.EncodeToString(signingKey.Public().(ed25519.PublicKey))})
	if err != nil {
		t.Fatal(err)
	}
	payload := struct {
		Type, KeyID, Account, Subscription, Instance, ClientKey, Edge, Kind, IP string
		Version                                                                 uint64 `json:"v"`
		Port                                                                    uint16 `json:"port"`
		Transport, Domain                                                       string
		IssuedAt, NotBefore, PaidThrough, GraceThrough, Generation              uint64
		TokenID                                                                 string
	}{
		Type: "blindport-offline-entitlement", Version: 1, KeyID: "offline-a", Account: offlineTestAccount,
		Subscription: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Instance: offlineTestInstance,
		ClientKey: base64.RawURLEncoding.EncodeToString(clientPublicKey), Edge: "edge-a", Kind: "port", IP: claim.IP,
		Port: claim.Port, Transport: "tcp", IssuedAt: uint64(now.Unix()), NotBefore: uint64(now.Unix()),
		PaidThrough: uint64(now.Unix()), GraceThrough: uint64(graceThrough.Unix()), Generation: uint64(now.Unix())<<31 | 7,
		TokenID: "EBESExQVFhcYGRobHB0eHw",
	}
	// Match the backend's canonical payload field names and ordering exactly.
	rawPayload, err := json.Marshal(struct {
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
		IssuedAt     uint64 `json:"iat"`
		NotBefore    uint64 `json:"nbf"`
		PaidThrough  uint64 `json:"paid_through"`
		GraceThrough uint64 `json:"grace_through"`
		Generation   uint64 `json:"generation"`
		TokenID      string `json:"jti"`
	}{
		Type: payload.Type, Version: payload.Version, KeyID: payload.KeyID, Account: payload.Account, Subscription: payload.Subscription,
		Instance: payload.Instance, ClientKey: payload.ClientKey, Edge: payload.Edge, Kind: payload.Kind, IP: payload.IP,
		Port: payload.Port, Transport: payload.Transport, Domain: payload.Domain, IssuedAt: payload.IssuedAt, NotBefore: payload.NotBefore,
		PaidThrough: payload.PaidThrough, GraceThrough: payload.GraceThrough, Generation: payload.Generation, TokenID: payload.TokenID,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := "v1." + base64.RawURLEncoding.EncodeToString(rawPayload) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(signingKey, rawPayload))
	return offlineTestFixture{
		artifact: artifact, claim: claim, client: tls.Certificate{Certificate: [][]byte{clientDER}, PrivateKey: clientKey},
		server: tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}, clientRoots: roots,
		identity:    clientIdentity{kind: clientIdentityAccount, accountID: accountID, instanceID: instanceID, clientPublicKey: append([]byte(nil), clientPublicKey...), offlineV2: true},
		keyringJSON: string(keyringJSON), graceThrough: graceThrough,
	}
}

func mustEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}

func createCertificate(t *testing.T, template, parent *x509.Certificate, publicKey any, parentKey ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
