package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/blindport/blindport/internal/protocol"
)

const maxDynamicPortListeners = 8192

type portListenerRegistry struct {
	relay *relay

	mu           sync.Mutex
	listeners    map[string]*portListener
	maxListeners int
	closed       bool

	listen       func(network, address string) (net.Listener, error)
	listenPacket func(network, address string) (net.PacketConn, error)
}

type portListener struct {
	references  int
	cancel      context.CancelFunc
	listeners   []net.Listener
	packetConns []net.PacketConn
}

func newPortListenerRegistry(relay *relay, maxListeners int) *portListenerRegistry {
	return &portListenerRegistry{
		relay:        relay,
		listeners:    make(map[string]*portListener),
		maxListeners: maxListeners,
		listen:       net.Listen,
		listenPacket: net.ListenPacket,
	}
}

func validateMaxPortListeners(value int) error {
	if value <= 0 || value > maxDynamicPortListeners {
		return fmt.Errorf("shared port listener limit must be between 1 and %d", maxDynamicPortListeners)
	}
	return nil
}

func (r *relay) acquirePortListener(ctx context.Context, claim *protocol.Claim) (func(), error) {
	if claim.Kind != protocol.ClaimPort {
		return func() {}, nil
	}
	if r.portListeners == nil {
		return func() {}, nil
	}
	return r.portListeners.acquire(ctx, claim)
}

func (r *relay) closePortListeners() {
	if r.portListeners != nil {
		r.portListeners.closeAll()
	}
}

func (registry *portListenerRegistry) acquire(ctx context.Context, claim *protocol.Claim) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := claimKey(claim)

	registry.mu.Lock()
	if registry.closed {
		registry.mu.Unlock()
		return nil, errors.New("shared port listener registry is closed")
	}
	if existing := registry.listeners[key]; existing != nil {
		existing.references++
		registry.mu.Unlock()
		return registry.releaseFunc(key, existing), nil
	}
	if len(registry.listeners) >= registry.maxListeners {
		registry.mu.Unlock()
		return nil, errors.New("shared port listener capacity reached")
	}

	listenerCtx, cancel := context.WithCancel(ctx)
	entry := &portListener{references: 1, cancel: cancel}
	for _, ip := range registry.relay.sharedIPs {
		address := net.JoinHostPort(ip, strconv.Itoa(int(claim.Port)))
		switch claim.Transport {
		case protocol.TransportTCP:
			listener, err := registry.listen("tcp", address)
			if err != nil {
				entry.close()
				registry.mu.Unlock()
				return nil, err
			}
			entry.listeners = append(entry.listeners, listener)
		case protocol.TransportUDP:
			packetConn, err := registry.listenPacket("udp", address)
			if err != nil {
				entry.close()
				registry.mu.Unlock()
				return nil, err
			}
			entry.packetConns = append(entry.packetConns, packetConn)
		default:
			entry.close()
			registry.mu.Unlock()
			return nil, errors.New("unsupported shared port transport")
		}
	}
	registry.listeners[key] = entry
	registry.mu.Unlock()

	for _, listener := range entry.listeners {
		go registry.relay.servePort(listenerCtx, listener, claim.IP, claim.Port)
	}
	for _, packetConn := range entry.packetConns {
		go registry.relay.serveUDPPort(listenerCtx, packetConn, claim.IP, claim.Port)
	}
	return registry.releaseFunc(key, entry), nil
}

func (registry *portListenerRegistry) releaseFunc(key string, entry *portListener) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			registry.release(key, entry)
		})
	}
}

func (registry *portListenerRegistry) release(key string, entry *portListener) {
	registry.mu.Lock()
	if registry.listeners[key] != entry {
		registry.mu.Unlock()
		return
	}
	entry.references--
	if entry.references != 0 {
		registry.mu.Unlock()
		return
	}
	delete(registry.listeners, key)
	entry.close()
	registry.mu.Unlock()
}

func (registry *portListenerRegistry) closeAll() {
	registry.mu.Lock()
	if registry.closed {
		registry.mu.Unlock()
		return
	}
	registry.closed = true
	entries := make([]*portListener, 0, len(registry.listeners))
	for _, entry := range registry.listeners {
		entries = append(entries, entry)
	}
	registry.listeners = make(map[string]*portListener)
	registry.mu.Unlock()

	for _, entry := range entries {
		entry.close()
	}
}

func (entry *portListener) close() {
	entry.cancel()
	for _, listener := range entry.listeners {
		_ = listener.Close()
	}
	for _, packetConn := range entry.packetConns {
		_ = packetConn.Close()
	}
}
