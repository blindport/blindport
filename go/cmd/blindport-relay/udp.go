package main

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blindport/blindport/internal/protocol"
	"github.com/blindport/blindport/internal/tunnel"
)

const udpAssociationQueueSize = 32

const udpAssociationQueueByteSize = udpAssociationQueueSize * protocol.MaxDataPayloadSize

type udpAssociation struct {
	forwarder *udpForwarder
	key       string
	source    net.Addr
	tunnel    *tunnel.Conn
	queue     chan []byte
	queued    atomic.Int64
	done      chan struct{}
	release   func()
	stream    *tunnel.Stream
	once      sync.Once
}

type udpForwarder struct {
	relay       *relay
	packetConn  net.PacketConn
	claimKey    string
	destination string
	ctx         context.Context

	mu           sync.Mutex
	associations map[string]*udpAssociation
}

func (r *relay) serveUDPPort(ctx context.Context, packetConn net.PacketConn, ip string, port uint16) {
	destination := net.JoinHostPort(ip, strconv.Itoa(int(port)))
	forwarder := &udpForwarder{
		relay: r, packetConn: packetConn,
		claimKey:    "port:" + string(protocol.TransportUDP) + ":" + destination,
		destination: destination, ctx: ctx,
		associations: make(map[string]*udpAssociation),
	}
	r.log.Info("port UDP listening", "addr", destination)
	buffer := make([]byte, protocol.MaxDatagramPayloadSize)
	for {
		n, source, err := packetConn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			r.listenerFailed("port_udp", err)
			return
		}
		forwarder.receive(source, buffer[:n])
	}
}

func (f *udpForwarder) receive(source net.Addr, payload []byte) {
	key := source.String()
	f.mu.Lock()
	association := f.associations[key]
	f.mu.Unlock()
	if association == nil {
		association = f.createAssociation(key, cloneUDPAddr(source))
		if association == nil {
			f.relay.metrics.udp.dropped.Add(1)
			return
		}
	}

	if !association.enqueue(payload) {
		f.relay.metrics.udp.dropped.Add(1)
	}
}

func (a *udpAssociation) enqueue(payload []byte) bool {
	size := int64(len(payload))
	for {
		queued := a.queued.Load()
		if size > int64(udpAssociationQueueByteSize)-queued {
			return false
		}
		if a.queued.CompareAndSwap(queued, queued+size) {
			break
		}
	}
	release := func() { a.queued.Add(-size) }
	select {
	case <-a.done:
		release()
		return false
	default:
	}
	packet := append([]byte(nil), payload...)
	select {
	case a.queue <- packet:
		return true
	case <-a.done:
		release()
		return false
	default:
		release()
		return false
	}
}

func (f *udpForwarder) createAssociation(key string, source net.Addr) *udpAssociation {
	t := f.relay.getTunnel(f.claimKey)
	if t == nil {
		return nil
	}
	release, ok := f.relay.limits.ingressSources.acquire(source)
	if !ok {
		f.relay.metrics.udp.rejected.Add(1)
		return nil
	}
	association := &udpAssociation{
		forwarder: f, key: key, source: source, tunnel: t,
		queue: make(chan []byte, udpAssociationQueueSize), done: make(chan struct{}), release: release,
	}
	f.mu.Lock()
	if existing := f.associations[key]; existing != nil {
		f.mu.Unlock()
		release()
		return existing
	}
	f.associations[key] = association
	f.mu.Unlock()
	f.relay.metrics.udp.associations.active.Add(1)
	f.relay.metrics.udp.associations.total.Add(1)
	if !f.relay.handlers.start(association.run) {
		f.relay.metrics.udp.rejected.Add(1)
		association.finish()
		return nil
	}
	return association
}

func (a *udpAssociation) run() {
	defer a.finish()
	stream, err := a.tunnel.OpenStream("udp", a.source.String(), a.forwarder.destination)
	if err != nil {
		a.forwarder.relay.log.Warn("open UDP association stream", "err", err)
		return
	}
	a.stream = stream
	index := claimKindIndex(protocol.ClaimPort)
	a.forwarder.relay.metrics.streams[index].active.Add(1)
	a.forwarder.relay.metrics.streams[index].total.Add(1)
	defer a.forwarder.relay.metrics.streams[index].active.Add(-1)

	responses := make(chan []byte)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buffer := make([]byte, protocol.MaxDatagramPayloadSize)
		for {
			n, err := stream.ReadDatagram(buffer)
			if err != nil {
				return
			}
			packet := append([]byte(nil), buffer[:n]...)
			select {
			case responses <- packet:
			case <-a.done:
				return
			case <-a.forwarder.ctx.Done():
				return
			}
		}
	}()

	idle := time.NewTimer(a.forwarder.relay.udpAssociationIdle)
	defer idle.Stop()
	resetIdle := func() {
		if !idle.Stop() {
			select {
			case <-idle.C:
			default:
			}
		}
		idle.Reset(a.forwarder.relay.udpAssociationIdle)
	}
	for {
		select {
		case packet := <-a.queue:
			a.queued.Add(-int64(len(packet)))
			if _, err := stream.WriteDatagram(packet); err != nil {
				return
			}
			a.forwarder.relay.metrics.udp.datagrams[0].Add(1)
			a.forwarder.relay.metrics.bytes[index][0].Add(uint64(len(packet)))
			resetIdle()
		case packet := <-responses:
			n, err := a.forwarder.packetConn.WriteTo(packet, a.source)
			if err != nil || n != len(packet) {
				return
			}
			a.forwarder.relay.metrics.udp.datagrams[1].Add(1)
			a.forwarder.relay.metrics.bytes[index][1].Add(uint64(n))
			resetIdle()
		case <-readDone:
			return
		case <-idle.C:
			return
		case <-a.forwarder.ctx.Done():
			return
		}
	}
}

func (a *udpAssociation) finish() {
	a.once.Do(func() {
		close(a.done)
		if a.stream != nil {
			_ = a.stream.Close()
		}
		a.forwarder.mu.Lock()
		if a.forwarder.associations[a.key] == a {
			delete(a.forwarder.associations, a.key)
		}
		a.forwarder.mu.Unlock()
		a.release()
		a.forwarder.relay.metrics.udp.associations.active.Add(-1)
	})
}

func cloneUDPAddr(addr net.Addr) net.Addr {
	if udp, ok := addr.(*net.UDPAddr); ok {
		copyAddr := *udp
		copyAddr.IP = append(net.IP(nil), udp.IP...)
		return &copyAddr
	}
	return addr
}
