package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/protocol"
	"github.com/blindport/blindport/internal/tunnel"
)

func TestUDPPortAssociatesSourcesAndPreservesDatagrams(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpAddr := packetConn.LocalAddr().(*net.UDPAddr)
	limits, err := newAdmissionLimits(limitConfig{
		controlHandshakes: 4, totalIngress: 4, sniPeeks: 1, challenges: 1,
		controlPerSource: 2, ingressPerSource: 4, challengeRate: 60, challengeBurst: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	health := newRelayHealth(false, time.Minute, time.Minute)
	r := &relay{
		log: slog.Default(), limits: limits, metrics: &relayMetrics{health: health},
		udpAssociationIdle: 500 * time.Millisecond,
		tunnels:            make(map[string]*tunnel.Conn),
		allTunnels:         make(map[*tunnel.Conn]struct{}),
	}
	relayRaw, agentRaw := net.Pipe()
	relayTunnel := tunnel.New(relayRaw, nil)
	opened := make(chan *tunnel.Stream, 2)
	agentTunnel := tunnel.New(agentRaw, func(stream *tunnel.Stream) {
		opened <- stream
		go func() {
			buffer := make([]byte, protocol.MaxDatagramPayloadSize)
			for {
				n, err := stream.ReadDatagram(buffer)
				if err != nil {
					return
				}
				_, _ = stream.WriteDatagram(buffer[:n])
			}
		}()
	})
	go func() { _ = relayTunnel.Run() }()
	go func() { _ = agentTunnel.Run() }()
	key := "port:udp:" + net.JoinHostPort(udpAddr.IP.String(), strconv.Itoa(udpAddr.Port))
	r.registerTunnel(key, protocol.ClaimPort, relayTunnel)

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		r.serveUDPPort(ctx, packetConn, udpAddr.IP.String(), uint16(udpAddr.Port))
	}()
	clients := make([]*net.UDPConn, 2)
	for i := range clients {
		client, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			t.Fatal(err)
		}
		clients[i] = client
		defer client.Close()
		payload := []byte("source-" + strconv.Itoa(i))
		if i == 0 {
			payload = []byte{}
		} else {
			payload = bytes.Repeat([]byte("u"), protocol.MaxDatagramPayloadSize)
		}
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, protocol.MaxDatagramPayloadSize)
		if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, err := client.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buffer[:n], payload) {
			t.Fatalf("response %d length = %d, want %d", i, n, len(payload))
		}
	}
	for range clients {
		select {
		case stream := <-opened:
			if stream.Protocol != protocol.TransportUDP || stream.Destination != packetConn.LocalAddr().String() {
				t.Fatalf("UDP OPEN metadata = %+v", stream)
			}
		case <-time.After(time.Second):
			t.Fatal("agent did not receive UDP OPEN")
		}
	}
	if got := r.metrics.udp.associations.total.Load(); got != 2 {
		t.Fatalf("UDP association total = %d, want 2", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for r.metrics.udp.associations.active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := r.metrics.udp.associations.active.Load(); got != 0 {
		t.Fatalf("UDP associations remained active after idle timeout: %d", got)
	}

	cancel()
	_ = packetConn.Close()
	<-serveDone
	r.unregisterTunnel(key, protocol.ClaimPort, relayTunnel)
	_ = agentTunnel.Close()
}

func TestUDPAssociationQueueHasPayloadByteLimit(t *testing.T) {
	association := &udpAssociation{
		queue: make(chan []byte, udpAssociationQueueSize),
		done:  make(chan struct{}),
	}
	packet := bytes.Repeat([]byte("u"), protocol.MaxDatagramPayloadSize)
	queuedPackets := udpAssociationQueueByteSize / len(packet)
	for range queuedPackets {
		if !association.enqueue(packet) {
			t.Fatal("queue rejected datagram within payload byte limit")
		}
	}
	if association.enqueue(packet) {
		t.Fatal("queue accepted datagram beyond payload byte limit")
	}
	if got := association.queued.Load(); got > udpAssociationQueueByteSize {
		t.Fatalf("queued payload bytes = %d", got)
	}
}

func TestUDPAssociationStopsOnContextCancellation(t *testing.T) {
	limits, err := newAdmissionLimits(limitConfig{
		controlHandshakes: 2, totalIngress: 2, sniPeeks: 1, challenges: 1,
		controlPerSource: 1, ingressPerSource: 2, challengeRate: 60, challengeBurst: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &relay{
		log: slog.Default(), limits: limits,
		metrics:            &relayMetrics{health: newRelayHealth(false, time.Minute, time.Minute)},
		udpAssociationIdle: time.Hour,
		tunnels:            make(map[string]*tunnel.Conn),
		allTunnels:         make(map[*tunnel.Conn]struct{}),
	}
	relayRaw, agentRaw := net.Pipe()
	relayTunnel := tunnel.New(relayRaw, nil)
	opened := make(chan struct{})
	agentTunnel := tunnel.New(agentRaw, func(*tunnel.Stream) { close(opened) })
	go func() { _ = relayTunnel.Run() }()
	go func() { _ = agentTunnel.Run() }()
	defer agentTunnel.Close()

	key := "port:udp:127.0.0.1:10000"
	r.registerTunnel(key, protocol.ClaimPort, relayTunnel)
	defer r.unregisterTunnel(key, protocol.ClaimPort, relayTunnel)
	forwarder := &udpForwarder{
		relay: r, packetConn: &discardPacketConn{}, claimKey: key,
		destination: "127.0.0.1:10000", ctx: ctx,
		associations: make(map[string]*udpAssociation),
	}
	source := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 32100}
	if association := forwarder.createAssociation(source.String(), source); association == nil {
		t.Fatal("failed to create UDP association")
	}
	select {
	case <-opened:
	case <-time.After(time.Second):
		t.Fatal("agent did not receive UDP association OPEN")
	}

	cancel()
	if !r.handlers.stopAndWait(time.Second) {
		t.Fatal("UDP association did not stop after context cancellation")
	}
	if got := r.metrics.udp.associations.active.Load(); got != 0 {
		t.Fatalf("active UDP associations after cancellation = %d", got)
	}
	forwarder.mu.Lock()
	remaining := len(forwarder.associations)
	forwarder.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("UDP associations retained after cancellation = %d", remaining)
	}
}

func TestUDPPortAdmissionRejectsExcessSource(t *testing.T) {
	limits, err := newAdmissionLimits(limitConfig{
		controlHandshakes: 1, totalIngress: 1, sniPeeks: 1, challenges: 1,
		controlPerSource: 1, ingressPerSource: 1, challengeRate: 60, challengeBurst: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{
		log: slog.Default(), limits: limits,
		metrics: &relayMetrics{health: newRelayHealth(false, time.Minute, time.Minute)},
		tunnels: make(map[string]*tunnel.Conn), allTunnels: make(map[*tunnel.Conn]struct{}),
	}
	raw, peer := net.Pipe()
	defer peer.Close()
	tunnelConn := tunnel.New(raw, nil)
	r.tunnels["port:udp:127.0.0.1:10000"] = tunnelConn
	forwarder := &udpForwarder{
		relay: r, packetConn: &discardPacketConn{}, claimKey: "port:udp:127.0.0.1:10000",
		destination: "127.0.0.1:10000", ctx: context.Background(),
		associations: make(map[string]*udpAssociation),
	}
	firstRelease, ok := limits.ingressSources.acquire(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1})
	if !ok {
		t.Fatal("failed to fill admission slot")
	}
	defer firstRelease()
	forwarder.receive(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 2}, []byte("dropped"))
	if r.metrics.udp.rejected.Load() != 1 || r.metrics.udp.dropped.Load() != 1 {
		t.Fatalf("rejected/dropped = %d/%d", r.metrics.udp.rejected.Load(), r.metrics.udp.dropped.Load())
	}
}

type discardPacketConn struct{}

func (*discardPacketConn) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, net.ErrClosed }
func (*discardPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (*discardPacketConn) Close() error                              { return nil }
func (*discardPacketConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (*discardPacketConn) SetDeadline(time.Time) error               { return nil }
func (*discardPacketConn) SetReadDeadline(time.Time) error           { return nil }
func (*discardPacketConn) SetWriteDeadline(time.Time) error          { return nil }
