package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/protocol"
	"github.com/blindport/blindport/internal/relayauth"
	"github.com/blindport/blindport/internal/tunnel"
)

type portLeaseResolver struct {
	lease relayauth.PortLease
}

func (r portLeaseResolver) Resolve(context.Context, string, *protocol.Claim) (*relayauth.Resolution, error) {
	return &relayauth.Resolution{PortLeases: []relayauth.PortLease{r.lease}}, nil
}

func TestPortControlTunnelAcquiresExactListenerBeforeHelloOK(t *testing.T) {
	port := availableTCPPort(t)
	for _, transport := range []protocol.Transport{protocol.TransportTCP, protocol.TransportUDP} {
		t.Run(string(transport), func(t *testing.T) {
			r := newPortTestRelay(port, transport)
			binds := make(chan portBindCall, 1)
			if transport == protocol.TransportTCP {
				r.portListeners.listen = func(network, address string) (net.Listener, error) {
					binds <- portBindCall{network: network, address: address}
					return net.Listen(network, address)
				}
			} else {
				r.portListeners.listenPacket = func(network, address string) (net.PacketConn, error) {
					binds <- portBindCall{network: network, address: address}
					return net.ListenPacket(network, address)
				}
			}

			client, server := net.Pipe()
			done := make(chan struct{})
			go func() {
				r.handleControlConn(context.Background(), server)
				close(done)
			}()
			claim := &protocol.Claim{Kind: protocol.ClaimPort, IP: "127.0.0.1", Port: port, Transport: transport}
			if err := protocol.WriteFrame(client, &protocol.Frame{Type: protocol.TypeHello, Version: protocol.CurrentVersion, Token: "token", Claim: claim}); err != nil {
				t.Fatal(err)
			}
			reply, err := protocol.ReadFrame(client)
			if err != nil {
				t.Fatal(err)
			}
			if reply.Type != protocol.TypeHelloOK {
				t.Fatalf("HELLO reply = %+v, want HELLO_OK", reply)
			}
			select {
			case bind := <-binds:
				wantNetwork := string(transport)
				wantAddress := net.JoinHostPort(claim.IP, strconv.Itoa(int(claim.Port)))
				if bind.network != wantNetwork || bind.address != wantAddress {
					t.Fatalf("listener bind = %s %s, want %s %s", bind.network, bind.address, wantNetwork, wantAddress)
				}
			default:
				t.Fatal("HELLO_OK was sent before the shared port listener was acquired")
			}
			_ = client.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("control session did not exit")
			}
			assertPortAvailable(t, transport, claim.IP, claim.Port)
		})
	}
}

func TestPortListenerRegistryRefcountsTCPAndUDPSeparately(t *testing.T) {
	port := availableTCPPort(t)
	r := newPortTestRelay(port, protocol.TransportTCP)
	tcpClaim := &protocol.Claim{Kind: protocol.ClaimPort, IP: "127.0.0.1", Port: port, Transport: protocol.TransportTCP}
	udpClaim := &protocol.Claim{Kind: protocol.ClaimPort, IP: "127.0.0.1", Port: port, Transport: protocol.TransportUDP}

	firstTCPRelease, err := r.acquirePortListener(context.Background(), tcpClaim)
	if err != nil {
		t.Fatal(err)
	}
	secondTCPRelease, err := r.acquirePortListener(context.Background(), tcpClaim)
	if err != nil {
		t.Fatal(err)
	}
	udpRelease, err := r.acquirePortListener(context.Background(), udpClaim)
	if err != nil {
		t.Fatal(err)
	}
	if got := activePortListenerCount(r.portListeners); got != 2 {
		t.Fatalf("active shared listeners = %d, want separate TCP and UDP listeners", got)
	}

	firstTCPRelease()
	assertPortBound(t, protocol.TransportTCP, tcpClaim.IP, tcpClaim.Port)
	assertPortBound(t, protocol.TransportUDP, udpClaim.IP, udpClaim.Port)

	secondTCPRelease()
	assertPortAvailable(t, protocol.TransportTCP, tcpClaim.IP, tcpClaim.Port)
	assertPortBound(t, protocol.TransportUDP, udpClaim.IP, udpClaim.Port)

	udpRelease()
	assertPortAvailable(t, protocol.TransportUDP, udpClaim.IP, udpClaim.Port)
}

func TestPortListenerRegistryCapacityAllowsExistingClaims(t *testing.T) {
	port := availableTCPPort(t)
	r := newPortTestRelay(port, protocol.TransportTCP)
	r.portListeners = newPortListenerRegistry(r, 1)
	tcpClaim := &protocol.Claim{Kind: protocol.ClaimPort, IP: "127.0.0.1", Port: port, Transport: protocol.TransportTCP}
	udpClaim := &protocol.Claim{Kind: protocol.ClaimPort, IP: "127.0.0.1", Port: port, Transport: protocol.TransportUDP}

	firstTCPRelease, err := r.acquirePortListener(context.Background(), tcpClaim)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.acquirePortListener(context.Background(), udpClaim); err == nil {
		t.Fatal("new UDP claim was acquired after reaching shared listener capacity")
	}
	secondTCPRelease, err := r.acquirePortListener(context.Background(), tcpClaim)
	if err != nil {
		t.Fatalf("existing TCP claim was rejected at capacity: %v", err)
	}
	if got := activePortListenerCount(r.portListeners); got != 1 {
		t.Fatalf("active shared listeners = %d, want 1", got)
	}

	firstTCPRelease()
	assertPortBound(t, protocol.TransportTCP, tcpClaim.IP, tcpClaim.Port)
	secondTCPRelease()
	assertPortAvailable(t, protocol.TransportTCP, tcpClaim.IP, tcpClaim.Port)

	udpRelease, err := r.acquirePortListener(context.Background(), udpClaim)
	if err != nil {
		t.Fatalf("new UDP claim was rejected after capacity was released: %v", err)
	}
	udpRelease()
	assertPortAvailable(t, protocol.TransportUDP, udpClaim.IP, udpClaim.Port)
}

func TestValidateMaxPortListeners(t *testing.T) {
	for _, test := range []struct {
		name    string
		value   int
		wantErr bool
	}{
		{name: "minimum", value: 1},
		{name: "maximum", value: maxDynamicPortListeners},
		{name: "zero", value: 0, wantErr: true},
		{name: "negative", value: -1, wantErr: true},
		{name: "above maximum", value: maxDynamicPortListeners + 1, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateMaxPortListeners(test.value); (err != nil) != test.wantErr {
				t.Fatalf("validateMaxPortListeners(%d) error = %v, wantErr %t", test.value, err, test.wantErr)
			}
		})
	}
}

func TestPortControlTunnelRejectsListenerBindFailure(t *testing.T) {
	for _, transport := range []protocol.Transport{protocol.TransportTCP, protocol.TransportUDP} {
		t.Run(string(transport), func(t *testing.T) {
			r := newPortTestRelay(10000, transport)
			if transport == protocol.TransportTCP {
				r.portListeners.listen = func(string, string) (net.Listener, error) {
					return nil, errors.New("synthetic bind failure")
				}
			} else {
				r.portListeners.listenPacket = func(string, string) (net.PacketConn, error) {
					return nil, errors.New("synthetic bind failure")
				}
			}

			client, server := net.Pipe()
			done := make(chan struct{})
			go func() {
				r.handleControlConn(context.Background(), server)
				close(done)
			}()
			claim := &protocol.Claim{Kind: protocol.ClaimPort, IP: "127.0.0.1", Port: 10000, Transport: transport}
			if err := protocol.WriteFrame(client, &protocol.Frame{Type: protocol.TypeHello, Version: protocol.CurrentVersion, Token: "token", Claim: claim}); err != nil {
				t.Fatal(err)
			}
			reply, err := protocol.ReadFrame(client)
			if err != nil {
				t.Fatal(err)
			}
			if reply.Type != protocol.TypeHelloErr {
				t.Fatalf("HELLO reply = %+v, want HELLO_ERR", reply)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("rejected control session did not exit")
			}
			if got := activePortListenerCount(r.portListeners); got != 0 {
				t.Fatalf("active shared listeners after bind failure = %d", got)
			}
		})
	}
}

func TestPortListenerRegistryShutdownClosesWithoutListenerFailure(t *testing.T) {
	port := availableTCPPort(t)
	health := newRelayHealth(false, time.Minute, time.Minute)
	health.listenersUp.Store(true)
	var shutdownCalls atomic.Int32
	r := newPortTestRelay(port, protocol.TransportTCP)
	r.metrics = &relayMetrics{health: health}
	r.shutdown = func() { shutdownCalls.Add(1) }
	acceptExited := make(chan struct{}, 1)
	r.portListeners.listen = func(network, address string) (net.Listener, error) {
		listener, err := net.Listen(network, address)
		if err != nil {
			return nil, err
		}
		return notifyingListener{Listener: listener, acceptExited: acceptExited}, nil
	}
	claim := &protocol.Claim{Kind: protocol.ClaimPort, IP: "127.0.0.1", Port: port, Transport: protocol.TransportTCP}
	release, err := r.acquirePortListener(context.Background(), claim)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	r.closePortListeners()
	select {
	case <-acceptExited:
	case <-time.After(time.Second):
		t.Fatal("dynamic TCP listener did not stop during shutdown")
	}
	if !health.listenersUp.Load() || shutdownCalls.Load() != 0 {
		t.Fatalf("intentional listener close changed health/shutdown state = %t/%d", health.listenersUp.Load(), shutdownCalls.Load())
	}
	assertPortAvailable(t, protocol.TransportTCP, claim.IP, claim.Port)
}

type portBindCall struct {
	network string
	address string
}

type notifyingListener struct {
	net.Listener
	acceptExited chan<- struct{}
}

func (listener notifyingListener) Accept() (net.Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		select {
		case listener.acceptExited <- struct{}{}:
		default:
		}
	}
	return conn, err
}

func newPortTestRelay(port uint16, transport protocol.Transport) *relay {
	health := newRelayHealth(false, time.Minute, time.Minute)
	r := &relay{
		log:                 slog.New(slog.NewTextHandler(io.Discard, nil)),
		resolver:            portLeaseResolver{lease: relayauth.PortLease{AssignedIP: "127.0.0.1", AssignedPort: port, Transport: string(transport)}},
		sharedIPs:           []string{"127.0.0.1"},
		sharedTCPPorts:      []uint16{port},
		sharedUDPPorts:      []uint16{port},
		metrics:             &relayMetrics{health: health},
		tunnels:             make(map[string]*tunnel.Conn),
		tunnelSubscriptions: make(map[*tunnel.Conn]string),
		allTunnels:          make(map[*tunnel.Conn]struct{}),
		reauthInterval:      time.Hour,
		reauthMaxStale:      time.Hour,
		maxStreamsPerTunnel: 1,
	}
	r.portListeners = newPortListenerRegistry(r, maxDynamicPortListeners)
	return r
}

func availableTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	_ = listener.Close()
	return port
}

func assertPortBound(t *testing.T, transport protocol.Transport, ip string, port uint16) {
	t.Helper()
	address := net.JoinHostPort(ip, strconv.Itoa(int(port)))
	if transport == protocol.TransportTCP {
		listener, err := net.Listen("tcp", address)
		if err == nil {
			_ = listener.Close()
			t.Fatalf("%s listener %s was not bound", transport, address)
		}
		return
	}
	packetConn, err := net.ListenPacket("udp", address)
	if err == nil {
		_ = packetConn.Close()
		t.Fatalf("%s listener %s was not bound", transport, address)
	}
}

func assertPortAvailable(t *testing.T, transport protocol.Transport, ip string, port uint16) {
	t.Helper()
	address := net.JoinHostPort(ip, strconv.Itoa(int(port)))
	if transport == protocol.TransportTCP {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatalf("%s listener %s remained bound: %v", transport, address, err)
		}
		_ = listener.Close()
		return
	}
	packetConn, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatalf("%s listener %s remained bound: %v", transport, address, err)
	}
	_ = packetConn.Close()
}

func activePortListenerCount(registry *portListenerRegistry) int {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return len(registry.listeners)
}
