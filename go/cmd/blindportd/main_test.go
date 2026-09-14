package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/protocol"
	"github.com/blindport/blindport/internal/tunnel"
)

func TestChooseProvisioningPort(t *testing.T) {
	cfg := []provisioning{
		{Product: "ip", AssignedIP: "203.0.113.10", Transport: "tcp"},
		{Product: "port", AssignedIP: "203.0.113.20", AssignedPort: 10000, Transport: "tcp"},
		{Product: "port", AssignedIP: "203.0.113.20", AssignedPort: 10001, Transport: "tcp"},
		{Product: "port", AssignedIP: "203.0.113.20", AssignedPort: 10001, Transport: "udp"},
	}

	chosen := chooseProvisioning(cfg, "port", "203.0.113.20", 10001, "tcp", "")
	if chosen == nil || chosen.AssignedPort != 10001 {
		t.Fatalf("chooseProvisioning() = %+v, want port 10001", chosen)
	}
	if got := chooseProvisioning(cfg, "port", "203.0.113.20", 10001, "udp", ""); got == nil || got.Transport != "udp" {
		t.Fatalf("chooseProvisioning() did not select UDP lease: %+v", got)
	}
}

func TestBuildLegacyPlansSelectsSoleActiveSubscription(t *testing.T) {
	cfg := []provisioning{{
		RelayEndpoint:  "relay.example:5443",
		Product:        "relay",
		Domain:         "hello.example.com",
		Transport:      "tcp",
		SubscriptionID: testSubscriptionID1,
	}}

	plans, err := buildLegacyPlans(cfg, legacySelection{}, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 || plans[0].SubscriptionID != testSubscriptionID1 {
		t.Fatalf("plans = %+v", plans)
	}
	if plans[0].Upstream != "127.0.0.1:443" || plans[0].Claim.Kind != protocol.ClaimRelay {
		t.Fatalf("sole Relay defaults = %+v", plans[0])
	}
}

func TestBuildLegacyPlansUsesNonRelayDefaultUpstream(t *testing.T) {
	for _, product := range []string{"ip", "port"} {
		t.Run(product, func(t *testing.T) {
			row := provisioning{
				RelayEndpoint:  "relay.example:5443",
				Product:        product,
				AssignedIP:     "203.0.113.10",
				Transport:      "tcp",
				SubscriptionID: testSubscriptionID1,
			}
			if product == "port" {
				row.AssignedPort = 10000
			}
			plans, err := buildLegacyPlans([]provisioning{row}, legacySelection{}, "", "", "")
			if err != nil {
				t.Fatal(err)
			}
			if len(plans) != 1 || plans[0].Upstream != "127.0.0.1:80" {
				t.Fatalf("sole %s defaults = %+v", product, plans)
			}
		})
	}
}

func TestBuildLegacyPlansInvalidKindDoesNotAutoSelect(t *testing.T) {
	cfg := []provisioning{{
		RelayEndpoint:  "relay.example:5443",
		Product:        "relay",
		Domain:         "hello.example.com",
		Transport:      "tcp",
		SubscriptionID: testSubscriptionID1,
	}}

	_, err := buildLegacyPlans(cfg, legacySelection{kind: "invalid"}, "", "", "")
	if err == nil || !strings.Contains(err.Error(), `claim kind "invalid"`) {
		t.Fatalf("invalid-kind error = %v", err)
	}
}

func TestBuildLegacyPlansRequiresSelectionForMultipleSubscriptions(t *testing.T) {
	cfg := []provisioning{
		{Product: "ip", AssignedIP: "203.0.113.10", Transport: "tcp", SubscriptionID: testSubscriptionID1},
		{Product: "relay", Domain: "hello.example.com", Transport: "tcp", SubscriptionID: testSubscriptionID2},
	}

	_, err := buildLegacyPlans(cfg, legacySelection{}, "", "", "")
	if err == nil || !strings.Contains(err.Error(), "multiple active framed subscriptions") || !strings.Contains(err.Error(), "-config") {
		t.Fatalf("multiple-subscription error = %v", err)
	}
}

func TestBuildLegacyPlansPreservesExplicitSelectionAndUpstream(t *testing.T) {
	cfg := []provisioning{
		{RelayEndpoint: "relay.example:5443", Product: "ip", AssignedIP: "203.0.113.10", Transport: "tcp", SubscriptionID: testSubscriptionID1},
		{RelayEndpoint: "relay.example:5443", Product: "relay", Domain: "hello.example.com", Transport: "tcp", SubscriptionID: testSubscriptionID2},
	}

	plans, err := buildLegacyPlans(cfg, legacySelection{kind: "relay"}, "127.0.0.1:8443", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 || plans[0].SubscriptionID != testSubscriptionID2 || plans[0].Upstream != "127.0.0.1:8443" {
		t.Fatalf("explicit selection plans = %+v", plans)
	}
}

func TestBootstrapHTTPClientIsDedicatedAndBounded(t *testing.T) {
	outbound, err := newOutboundTransport("")
	if err != nil {
		t.Fatal(err)
	}
	if outbound.httpClient == http.DefaultClient {
		t.Fatal("bootstrap client uses http.DefaultClient")
	}
	if outbound.httpClient.Timeout != 10*time.Second {
		t.Fatalf("bootstrap timeout = %s", outbound.httpClient.Timeout)
	}
}

func TestLoadTokenFileRequiresPrivateRegularFile(t *testing.T) {
	t.Setenv("BLINDPORT_TOKEN", "")
	directory := t.TempDir()
	secure := filepath.Join(directory, "token")
	if err := os.WriteFile(secure, []byte("PRIVATE-TOKEN\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := loadToken("", secure)
	if err != nil || token != "PRIVATE-TOKEN" {
		t.Fatalf("loadToken() = %q, %v", token, err)
	}
	if err := os.Chmod(secure, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadToken("", secure); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("exposed token error = %v", err)
	}
	link := filepath.Join(directory, "token-link")
	if err := os.Symlink(secure, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadToken("", link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink token error = %v", err)
	}
}

func TestLoadTokenUsesExplicitSourcesBeforeFile(t *testing.T) {
	t.Setenv("BLINDPORT_TOKEN", "ENV-TOKEN")
	if token, err := loadToken("FLAG-TOKEN", "/missing"); err != nil || token != "FLAG-TOKEN" {
		t.Fatalf("flag token = %q, %v", token, err)
	}
	if token, err := loadToken("", "/missing"); err != nil || token != "ENV-TOKEN" {
		t.Fatalf("environment token = %q, %v", token, err)
	}
	t.Setenv("BLINDPORT_TOKEN", "")
	if token, err := loadToken("", "/missing"); err != nil || token != "" {
		t.Fatalf("missing token = %q, %v", token, err)
	}
}

func TestFetchConfigRejectsOversizedMalformedAndTrailingResponses(t *testing.T) {
	tests := map[string]func(http.ResponseWriter){
		"oversized": func(w http.ResponseWriter) {
			_, _ = io.CopyN(w, strings.NewReader(strings.Repeat("x", maxProvisioningJSON+1)), maxProvisioningJSON+1)
		},
		"malformed": func(w http.ResponseWriter) { _, _ = io.WriteString(w, `[{`) },
		"trailing JSON": func(w http.ResponseWriter) {
			_, _ = io.WriteString(w, `[] {}`)
		},
	}
	for name, handler := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { handler(w) }))
			defer server.Close()
			if _, err := fetchConfigWithClient(context.Background(), server.Client(), server.URL, "token"); err == nil {
				t.Fatal("fetchConfigWithClient() succeeded")
			}
		})
	}
}

func TestFetchConfigAdvertisesRelayAssignmentsCapability(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Blindport-Agent-Capabilities"); got != relayAssignmentsCapability {
			t.Errorf("Blindport-Agent-Capabilities = %q", got)
		}
		_, _ = io.WriteString(w, `[{"relay_endpoint":"primary.example:5443","relay_endpoints":["primary.example:5443"],"relay_assignments":[{"relay_endpoint":"secondary.example:5443","assigned_ip":"203.0.113.21"}],"assigned_ip":"203.0.113.20","assigned_port":10000,"transport":"tcp","product":"port","subscription_id":"`+testSubscriptionID1+`"}]`)
	}))
	defer server.Close()

	cfg, err := fetchConfigWithClient(context.Background(), server.Client(), server.URL, "token")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg) != 1 || len(cfg[0].RelayAssignments) != 1 || cfg[0].RelayAssignments[0].AssignedIP != "203.0.113.21" {
		t.Fatalf("config = %+v", cfg)
	}
}

func TestFetchClientCertRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.CopyN(w, strings.NewReader(strings.Repeat("x", maxCertificateResponse+1)), maxCertificateResponse+1)
	}))
	defer server.Close()
	if _, err := fetchClientCertWithClient(context.Background(), server.Client(), server.URL, "token"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("fetchClientCertWithClient() error = %v", err)
	}
}

func TestFetchConfigTimesOutStalledResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 30 * time.Millisecond
	started := time.Now()
	_, err := fetchConfigWithClient(context.Background(), client, server.URL, "token")
	if err == nil {
		t.Fatal("fetchConfigWithClient() succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("stalled response took %s", elapsed)
	}
}

func TestExchangeHelloTimesOutWhenRelayDoesNotReply(t *testing.T) {
	listener := listenLocal(t)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = protocol.ReadFrame(conn)
		_, _ = io.Copy(io.Discard, conn)
	}()
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "hello.example"}
	started := time.Now()
	_, err := runOnceWithHelloTimeout(context.Background(), slog.Default(), listener.Addr().String(), "token", claim, "127.0.0.1:1", "", &net.Dialer{Timeout: time.Second}, nil, 30*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "read hello reply") {
		t.Fatalf("runOnceWithHelloTimeout() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("HELLO timeout took %s", elapsed)
	}
	<-serverDone
}

func TestExchangeHelloClearsDeadlineAfterHelloOK(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = protocol.ReadFrame(server)
		_ = protocol.WriteFrame(server, &protocol.Frame{Type: protocol.TypeHelloOK})
		time.Sleep(60 * time.Millisecond)
		_ = protocol.WriteFrame(server, &protocol.Frame{Type: protocol.TypePing})
	}()
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "hello.example"}
	capabilities, err := exchangeHello(client, "token", claim, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if capabilities.halfClose || capabilities.flowControl {
		t.Fatalf("legacy relay unexpectedly negotiated capabilities %+v", capabilities)
	}
	if _, err := protocol.ReadFrame(client); err != nil {
		t.Fatalf("post-HELLO read failed after deadline should be cleared: %v", err)
	}
}

func TestExchangeHelloRequiresVersionedRelayForUDP(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		hello, _ := protocol.ReadFrame(server)
		if hello.Version != protocol.CurrentVersion {
			t.Errorf("HELLO version = %d", hello.Version)
		}
		_ = protocol.WriteFrame(server, &protocol.Frame{Type: protocol.TypeHelloOK})
	}()
	claim := &protocol.Claim{
		Kind: protocol.ClaimPort, IP: "203.0.113.20", Port: 10000,
		Transport: protocol.TransportUDP,
	}
	if _, err := exchangeHello(client, "token", claim, time.Second); err == nil || !strings.Contains(err.Error(), "UDP requires") {
		t.Fatalf("exchangeHello() error = %v", err)
	}
}

func TestExchangeHelloNegotiatesTCPHalfClose(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		hello, _ := protocol.ReadFrame(server)
		if !hello.HasCapability(protocol.CapabilityTCPHalfClose) {
			t.Error("HELLO did not advertise TCP half-close")
		}
		if !hello.HasCapability(protocol.CapabilityStreamFlowControl) {
			t.Error("HELLO did not advertise stream flow control")
		}
		_ = protocol.WriteFrame(server, &protocol.Frame{
			Type: protocol.TypeHelloOK, Version: protocol.CurrentVersion,
			Capabilities: []protocol.Capability{protocol.CapabilityTCPHalfClose, protocol.CapabilityStreamFlowControl},
		})
	}()
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "hello.example"}
	capabilities, err := exchangeHello(client, "token", claim, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !capabilities.halfClose || !capabilities.flowControl {
		t.Fatalf("negotiated capabilities = %+v", capabilities)
	}
}

func TestExchangeHelloAddsOfflineEntitlementOnlyWhenProvided(t *testing.T) {
	for name, entitlement := range map[string]string{"v2": "v1.payload.signature", "v1": ""} {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go func() {
				hello, err := protocol.ReadFrame(server)
				if err != nil {
					t.Error(err)
					return
				}
				if hello.Entitlement != entitlement {
					t.Errorf("entitlement = %q", hello.Entitlement)
				}
				if got := hello.HasCapability(protocol.CapabilityOfflineEntitlementV1); got != (entitlement != "") {
					t.Errorf("offline capability = %t", got)
				}
				_ = protocol.WriteFrame(server, &protocol.Frame{Type: protocol.TypeHelloOK, Version: protocol.CurrentVersion})
			}()
			claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "hello.example"}
			if _, err := exchangeHelloWithEntitlement(client, "token", claim, time.Second, entitlement); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSecureFramedRuntimeEnrollsBeforeV2ProvisioningAndSendsProof(t *testing.T) {
	enrollment := newEnrollmentServer(t)
	relayListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relayListener.Close() })
	relayCertificate := issueTestRelayCertificate(t, enrollment, net.ParseIP("127.0.0.1"))
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(enrollment.caCert)
	tlsListener := tls.NewListener(relayListener, &tls.Config{
		Certificates: []tls.Certificate{relayCertificate}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: clientRoots, MinVersion: tls.VersionTLS12,
	})

	helloReceived := make(chan *protocol.Frame, 1)
	go func() {
		conn, acceptErr := tlsListener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		hello, readErr := protocol.ReadFrame(conn)
		if readErr != nil {
			return
		}
		helloReceived <- hello
		_ = protocol.WriteFrame(conn, &protocol.Frame{Type: protocol.TypeHelloOK, Version: protocol.CurrentVersion})
		_, _ = io.Copy(io.Discard, conn)
	}()

	var entitlement string
	configFetched := make(chan struct{}, 1)
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/client/certificate":
			enrollment.handle(w, r)
		case "/api/v2/client/config":
			if enrollment.callCount() != 1 {
				t.Errorf("provisioning ran before enrollment: calls = %d", enrollment.callCount())
				w.WriteHeader(http.StatusConflict)
				return
			}
			instance := r.URL.Query().Get("instance_id")
			now := time.Now().UTC().Truncate(time.Second)
			domain := "runtime.example"
			edge := testV2Edge(now, "edge-a", relayListener.Addr().String(), provisioningV2Claim{Kind: protocol.ClaimRelay, Domain: domain}, testSubscriptionID1, instance, 1)
			entitlement = edge.Entitlement
			config := provisioningV2{Version: 2, Subscriptions: []provisioningSubscription{{
				Domain: &domain, Transport: "tcp", Product: "relay", SubscriptionID: testSubscriptionID1,
				Edges: []provisioningV2Edge{edge},
			}}}
			configFetched <- struct{}{}
			_, _ = w.Write(testJSON(t, config))
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()

	ctx, cancel := context.WithCancel(context.Background())
	outbound := &outboundTransport{httpClient: control.Client(), relayDialer: &net.Dialer{Timeout: time.Second}}
	done := make(chan error, 1)
	go func() {
		done <- runFramedProvisioner(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), "test-token", outbound,
			newMappingProvisioningCoordinator([]mapping{{SubscriptionID: testSubscriptionID1, Upstream: "app:443"}}, "", false),
			framedRuntimeOptions{backend: control.URL, stateDir: privateStateDir(t), pollInterval: time.Hour},
		)
	}()
	select {
	case <-configFetched:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("v2 provisioning was not fetched")
	}
	select {
	case hello := <-helloReceived:
		if hello.Entitlement != entitlement || !hello.HasCapability(protocol.CapabilityOfflineEntitlementV1) {
			t.Fatalf("HELLO entitlement = %q, capabilities = %v", hello.Entitlement, hello.Capabilities)
		}
		if hello.Claim == nil || hello.Claim.Kind != protocol.ClaimRelay || hello.Claim.Domain != "runtime.example" {
			t.Fatalf("HELLO claim = %+v", hello.Claim)
		}
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("secure framed worker did not send HELLO")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func issueTestRelayCertificate(t *testing.T, enrollment *enrollmentServer, ip net.IP) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "test relay"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{ip},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, enrollment.caCert, publicKey, enrollment.caKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestExchangeHelloRejectsFlowControlWithoutHalfClose(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = protocol.ReadFrame(server)
		_ = protocol.WriteFrame(server, &protocol.Frame{
			Type: protocol.TypeHelloOK, Version: protocol.CurrentVersion,
			Capabilities: []protocol.Capability{protocol.CapabilityStreamFlowControl},
		})
	}()
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "hello.example"}
	capabilities, err := exchangeHello(client, "token", claim, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if capabilities.halfClose || capabilities.flowControl {
		t.Fatalf("invalid capability selection accepted: %+v", capabilities)
	}
}

func TestNotifyAgentUpdateLogsInstallerCommand(t *testing.T) {
	oldVersion := version
	version = "abc1234"
	t.Cleanup(func() { version = oldVersion })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/client/version" {
			t.Errorf("version path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		_, _ = io.WriteString(w, `{"version":"def5678"}`)
	}))
	defer server.Close()
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))

	notifyAgentUpdate(context.Background(), logger, server.Client(), server.URL, "secret")

	logged := output.String()
	for _, expected := range []string{
		"blindportd update available",
		"current_version=abc1234",
		"latest_version=def5678",
		"curl -fsSL " + server.URL + "/downloads/install.sh | sh",
	} {
		if !strings.Contains(logged, expected) {
			t.Errorf("update log missing %q: %s", expected, logged)
		}
	}
}

func TestNotifyAgentUpdateSkipsMainChannel(t *testing.T) {
	oldVersion := version
	version = "main-1234567890abcdef"
	t.Cleanup(func() { version = oldVersion })
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, `{"version":"v9.9.9"}`)
	}))
	defer server.Close()
	var output bytes.Buffer

	notifyAgentUpdate(context.Background(), slog.New(slog.NewTextHandler(&output, nil)), server.Client(), server.URL, "secret")

	if requests.Load() != 0 || output.Len() != 0 {
		t.Fatalf("main channel update check made %d requests and logged %q", requests.Load(), output.String())
	}
}

func TestFetchLatestAgentVersionAllowsOlderBackendWithoutEndpoint(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	latest, err := fetchLatestAgentVersion(context.Background(), server.Client(), server.URL, "secret")
	if err != nil || latest != "" {
		t.Fatalf("latest version = %q, %v", latest, err)
	}
}

func TestHandleTCPStreamPropagatesRequestFINAndLargeResponse(t *testing.T) {
	upstream := listenLocal(t)
	upstreamDone := make(chan error, 1)
	response := append(bytes.Repeat([]byte("x"), 40*protocol.MaxDataPayloadSize), []byte("final reverse response")...)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			upstreamDone <- err
			return
		}
		defer conn.Close()
		request, err := io.ReadAll(conn)
		if err != nil {
			upstreamDone <- err
			return
		}
		if string(request) != "request requiring FIN" {
			upstreamDone <- fmt.Errorf("upstream request = %q", request)
			return
		}
		_, err = conn.Write(response)
		upstreamDone <- err
	}()

	agentRaw, relayRaw := net.Pipe()
	handlerDone := make(chan struct{})
	agent := tunnel.New(agentRaw, func(stream *tunnel.Stream) {
		handleTCPStream(slog.Default(), stream, upstream.Addr().String())
		close(handlerDone)
	})
	relay := tunnel.New(relayRaw, nil)
	agent.EnableTCPHalfClose()
	relay.EnableTCPHalfClose()
	go func() { _ = agent.Run() }()
	go func() { _ = relay.Run() }()
	defer agent.Close()
	defer relay.Close()

	stream, err := relay.OpenStream("tcp", "src", "dst")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(stream, "request requiring FIN"); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("response length = %d, want %d", len(got), len(response))
	}
	if err := <-upstreamDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("TCP handler did not fully clean up")
	}
}

func TestHandleUDPAssociationForwardsWholeDatagrams(t *testing.T) {
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	originDone := make(chan struct{})
	go func() {
		defer close(originDone)
		buffer := make([]byte, protocol.MaxDatagramPayloadSize)
		for {
			n, source, err := origin.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if _, err := origin.WriteToUDP(buffer[:n], source); err != nil {
				return
			}
		}
	}()

	agentRaw, relayRaw := net.Pipe()
	handlerDone := make(chan struct{})
	agent := tunnel.New(agentRaw, func(stream *tunnel.Stream) {
		handleIncoming(slog.Default(), stream, nil, origin.LocalAddr().String(), "", protocol.TransportUDP)
		close(handlerDone)
	})
	relay := tunnel.New(relayRaw, nil)
	go func() { _ = agent.Run() }()
	go func() { _ = relay.Run() }()
	defer agent.Close()
	defer relay.Close()

	stream, err := relay.OpenStream("udp", "192.0.2.10:32100", "203.0.113.20:10000")
	if err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{
		{},
		[]byte("dns-sized"),
		bytes.Repeat([]byte("u"), protocol.MaxDatagramPayloadSize),
	}
	buffer := make([]byte, protocol.MaxDatagramPayloadSize)
	for _, payload := range payloads {
		if _, err := stream.WriteDatagram(payload); err != nil {
			t.Fatal(err)
		}
		n, err := stream.ReadDatagram(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buffer[:n], payload) {
			t.Fatalf("UDP response length = %d, want %d", n, len(payload))
		}
	}
	_ = stream.Close()
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("UDP association handler did not stop")
	}
	_ = origin.Close()
	<-originDone
}

func TestSelectTCPUpstreamValidatesRelayDestination(t *testing.T) {
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "service.example"}
	tests := []struct {
		destination string
		challenge   string
		want        string
		wantErr     bool
	}{
		{destination: "domain:service.example:443", challenge: "solver:80", want: "tls:443"},
		{destination: "domain:service.example:80", challenge: "solver:80", want: "solver:80"},
		{destination: "domain:service.example:80", wantErr: true},
		{destination: "domain:other.example:443", challenge: "solver:80", wantErr: true},
		{destination: "domain:service.example:8080", challenge: "solver:80", wantErr: true},
		{destination: "service.example:443", challenge: "solver:80", wantErr: true},
	}
	for _, test := range tests {
		got, err := selectTCPUpstream(test.destination, claim, "tls:443", test.challenge)
		if (err != nil) != test.wantErr || got != test.want {
			t.Errorf("selectTCPUpstream(%q) = %q, %v", test.destination, got, err)
		}
	}
}

func TestSelectTCPUpstreamValidatesWildcardRelayDestination(t *testing.T) {
	wildcard := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "public.example", Scope: protocol.RelayHostnameScopeWildcard}
	deeper := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "api.public.example", Scope: protocol.RelayHostnameScopeWildcard}
	for _, test := range []struct {
		name        string
		claim       *protocol.Claim
		destination string
		wantErr     bool
	}{
		{"wildcard base", wildcard, "domain:public.example:443", false},
		{"wildcard descendant", wildcard, "domain:a.public.example:443", false},
		{"deeper wildcard descendant", deeper, "domain:v1.api.public.example:80", false},
		{"boundary confusion", wildcard, "domain:badpublic.example:443", true},
		{"unrelated", wildcard, "domain:other.example:443", true},
		{"uppercase", wildcard, "domain:A.public.example:443", true},
		{"invalid port", wildcard, "domain:a.public.example:8443", true},
		{"internal wildcard key", wildcard, "domain:wildcard:public.example:443", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := selectTCPUpstream(test.destination, test.claim, "tls:443", "solver:80")
			if (err != nil) != test.wantErr {
				t.Fatalf("selectTCPUpstream(%q) error = %v", test.destination, err)
			}
		})
	}
}

func TestRelayDispatchesChallengeAndTLSStreamsToDistinctUpstreams(t *testing.T) {
	normal := listenLocal(t)
	challenge := listenLocal(t)
	serve := func(listener net.Listener, want, reply string) <-chan error {
		done := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			defer conn.Close()
			buffer := make([]byte, len(want))
			if _, err := io.ReadFull(conn, buffer); err != nil {
				done <- err
				return
			}
			if string(buffer) != want {
				done <- fmt.Errorf("upstream received %q, want %q", buffer, want)
				return
			}
			_, err = io.WriteString(conn, reply)
			done <- err
		}()
		return done
	}
	challengeDone := serve(challenge, "http-proof", "challenge-response")
	normalDone := serve(normal, "tls-clienthello", "tls-response")

	agentRaw, relayRaw := net.Pipe()
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "service.example"}
	agent := tunnel.New(agentRaw, func(stream *tunnel.Stream) {
		handleIncoming(slog.Default(), stream, claim, normal.Addr().String(), challenge.Addr().String(), protocol.TransportTCP)
	})
	relay := tunnel.New(relayRaw, nil)
	go func() { _ = agent.Run() }()
	go func() { _ = relay.Run() }()
	defer agent.Close()
	defer relay.Close()

	assertStream := func(destination, request, want string) {
		t.Helper()
		stream, err := relay.OpenStream("tcp", "192.0.2.1:1234", destination)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(stream, request); err != nil {
			t.Fatal(err)
		}
		response, err := io.ReadAll(stream)
		if err != nil {
			t.Fatal(err)
		}
		if string(response) != want {
			t.Fatalf("stream response = %q, want %q", response, want)
		}
	}
	assertStream("domain:service.example:80", "http-proof", "challenge-response")
	assertStream("domain:service.example:443", "tls-clienthello", "tls-response")
	if err := <-challengeDone; err != nil {
		t.Fatal(err)
	}
	if err := <-normalDone; err != nil {
		t.Fatal(err)
	}
}

func TestTCPStreamWritesProxyHeaderBeforePayload(t *testing.T) {
	upstream := listenLocal(t)
	received := make(chan []byte, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 28+len("payload"))
		if _, err := io.ReadFull(conn, buffer); err == nil {
			received <- buffer
		}
	}()

	agentRaw, relayRaw := net.Pipe()
	agent := tunnel.New(agentRaw, func(stream *tunnel.Stream) {
		handleIncomingManagedWithProxy(slog.Default(), stream, nil, upstream.Addr().String(), "", protocol.TransportTCP, nil, true)
	})
	relay := tunnel.New(relayRaw, nil)
	go func() { _ = agent.Run() }()
	go func() { _ = relay.Run() }()
	defer upstream.Close()
	defer agent.Close()
	defer relay.Close()

	stream, err := relay.OpenStreamWithDestinationAddress("tcp", "192.0.2.10:1234", "domain:service.example:443", "198.51.100.2:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(stream, "payload"); err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	got := <-received
	if got[12] != 0x21 || got[13] != 0x11 || !bytes.Equal(got[16:20], []byte{192, 0, 2, 10}) || !bytes.Equal(got[20:24], []byte{198, 51, 100, 2}) || string(got[28:]) != "payload" {
		t.Fatalf("upstream bytes = %x", got)
	}
}

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func serveHelloRelay(listener net.Listener, reply bool, hello chan<- struct{}) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err := protocol.ReadFrame(conn); err != nil {
		return
	}
	if reply {
		if err := protocol.WriteFrame(conn, &protocol.Frame{Type: protocol.TypeHelloOK}); err != nil {
			return
		}
		close(hello)
	}
	_, _ = io.Copy(io.Discard, conn)
}

func TestTwoRelayWorkersEstablishHealthyEdgeWhileOtherStalls(t *testing.T) {
	stalled := listenLocal(t)
	healthy := listenLocal(t)
	healthyHello := make(chan struct{})
	go serveHelloRelay(stalled, false, nil)
	go serveHelloRelay(healthy, true, healthyHello)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "multi.example"}
	plans := []workerPlan{
		{SubscriptionID: testSubscriptionID1, RelayAddr: stalled.Addr().String(), Upstream: "127.0.0.1:1", Claim: claim},
		{SubscriptionID: testSubscriptionID1, RelayAddr: healthy.Addr().String(), Upstream: "127.0.0.1:1", Claim: claim},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWorkerPlans(plans, func(plan workerPlan) {
			_, _ = runOnceWithHelloTimeout(ctx, slog.Default(), plan.RelayAddr, "token", plan.Claim, plan.Upstream, "", &net.Dialer{Timeout: time.Second}, nil, 2*time.Second)
		})
	}()
	select {
	case <-healthyHello:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("healthy relay did not complete HELLO while first relay was stalled")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("workers did not stop after cancellation")
	}
}

func TestDecodeBoundedJSONPropagatesReadError(t *testing.T) {
	errReader := errorReader{err: errors.New("read failed")}
	var destination any
	if err := decodeBoundedJSON(errReader, 10, &destination); err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatalf("decodeBoundedJSON() error = %v", err)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, fmt.Errorf("body: %w", r.err) }
