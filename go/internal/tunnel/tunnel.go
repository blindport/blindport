// Package tunnel implements the multiplexed bidirectional stream layer on
// top of the framed protocol. Both blindportd (client) and blindport-relay
// (server) use it to exchange application traffic.
package tunnel

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blindport/blindport/internal/protocol"
)

// Conn is a single multiplexed tunnel over an underlying net.Conn.
type Conn struct {
	raw          net.Conn
	writeMu      sync.Mutex
	streamsMu    sync.Mutex
	streams      map[uint32]*Stream
	receiveMu    sync.Mutex
	rxBytes      int64
	rxFrames     int
	nextID       atomic.Uint32
	closed       atomic.Bool
	maxStreams   int
	onOpen       func(stream *Stream) // server-side handler
	onUDPDrop    func()
	onClose      func()
	halfClose    bool
	rxByteLimit  int64
	rxFrameLimit int
}

// MaxConcurrentStreams bounds resources allocated to one tunnel.
const MaxConcurrentStreams = 1024

const (
	tcpStreamReceiveQueueByteSize  = 4 << 20
	tcpStreamReceiveQueueFrameSize = 512
	udpStreamReceiveQueueByteSize  = 512 << 10
	udpStreamReceiveQueueFrameSize = 32
	connReceiveQueueByteSize       = 64 << 20
	connReceiveQueueFrameSize      = 4096
)

const frameWriteTimeout = 10 * time.Second

// New wraps a raw connection.
func New(raw net.Conn, onOpen func(*Stream)) *Conn {
	return newConn(raw, onOpen, MaxConcurrentStreams)
}

// NewWithStreamLimit wraps a raw connection with a lower per-connection stream cap.
func NewWithStreamLimit(raw net.Conn, onOpen func(*Stream), maxStreams int) (*Conn, error) {
	if maxStreams <= 0 || maxStreams > MaxConcurrentStreams {
		return nil, fmt.Errorf("stream limit must be within 1-%d", MaxConcurrentStreams)
	}
	return newConn(raw, onOpen, maxStreams), nil
}

func newConn(raw net.Conn, onOpen func(*Stream), maxStreams int) *Conn {
	return &Conn{
		raw: raw, streams: make(map[uint32]*Stream), onOpen: onOpen, maxStreams: maxStreams,
		rxByteLimit: connReceiveQueueByteSize, rxFrameLimit: connReceiveQueueFrameSize,
	}
}

// SetUDPDropHandler installs an observer for UDP datagrams discarded by the
// receive queue. It must be called before Run.
func (c *Conn) SetUDPDropHandler(handler func()) {
	c.onUDPDrop = handler
}

// EnableTCPHalfClose enables the negotiated TCP half-close extension. It must
// only be called when both peers selected protocol.CapabilityTCPHalfClose.
func (c *Conn) EnableTCPHalfClose() {
	c.halfClose = true
}

// WriteFrame sends a frame with write-mutex protection.
func (c *Conn) WriteFrame(f *protocol.Frame) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.raw.SetWriteDeadline(time.Now().Add(frameWriteTimeout)); err != nil {
		_ = c.Close()
		return fmt.Errorf("set frame write deadline: %w", err)
	}
	err := protocol.WriteFrame(c.raw, f)
	_ = c.raw.SetWriteDeadline(time.Time{})
	if err != nil {
		_ = c.Close()
	}
	return err
}

// OpenStream creates a new outbound stream and informs the peer with an OPEN
// frame. Returns the local Stream handle.
func (c *Conn) OpenStream(proto, src, dst string) (*Stream, error) {
	transport, err := normalizeProtocol(proto)
	if err != nil {
		return nil, err
	}
	id := c.nextID.Add(1)
	s := newStream(c, id)
	s.Protocol = transport
	s.Source = src
	s.Destination = dst
	if err := c.addStream(s); err != nil {
		return nil, err
	}
	if err := c.WriteFrame(&protocol.Frame{Type: protocol.TypeOpen, Stream: id, Proto: string(transport), Src: src, Dst: dst}); err != nil {
		c.removeStream(id)
		return nil, err
	}
	return s, nil
}

// Run starts the read loop, dispatching frames to streams. Blocks until the
// connection closes.
func (c *Conn) Run() error {
	defer c.closeAll()
	for {
		f, err := protocol.ReadFrame(c.raw)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch f.Type {
		case protocol.TypeOpen:
			if c.onOpen == nil {
				return fmt.Errorf("unexpected OPEN for outbound-only tunnel")
			}
			s := newStream(c, f.Stream)
			transport, err := normalizeProtocol(f.Proto)
			if err != nil {
				return fmt.Errorf("invalid OPEN: %w", err)
			}
			s.Protocol = transport
			s.Source = f.Src
			s.Destination = f.Dst
			if err := c.addStream(s); err != nil {
				return fmt.Errorf("invalid OPEN: %w", err)
			}
			go c.onOpen(s)
		case protocol.TypeData, protocol.TypeDatagram:
			s, ok := c.getStream(f.Stream)
			if !ok {
				// DATA can race with CLOSE in the opposite direction. The stream is
				// already isolated, so discard the late payload without taking down
				// unrelated streams on the multiplexed tunnel.
				continue
			}
			if (f.Type == protocol.TypeData && s.Protocol != protocol.TransportTCP) ||
				(f.Type == protocol.TypeDatagram && s.Protocol != protocol.TransportUDP) {
				s.abort()
				continue
			}
			if s.Protocol == protocol.TransportTCP {
				if s.rxClosed.Load() {
					// DATA after CLOSE_WRITE violates the ordered TCP FIN boundary.
					s.abort()
					continue
				}
				if !s.queueTCPPayload(f.Data) {
					s.abort()
				}
				continue
			}
			if s.queueUDPPayload(f.Data) {
				continue
			}
			if c.onUDPDrop != nil {
				c.onUDPDrop()
			}
		case protocol.TypeClose:
			if f.Stream == 0 {
				return fmt.Errorf("CLOSE with zero stream ID")
			}
			if s, ok := c.getStream(f.Stream); ok {
				s.closeRX()
			}
		case protocol.TypeCloseWrite:
			if !c.halfClose {
				return fmt.Errorf("unexpected CLOSE_WRITE without negotiated capability")
			}
			if f.Stream == 0 {
				return fmt.Errorf("CLOSE_WRITE with zero stream ID")
			}
			s, ok := c.getStream(f.Stream)
			if !ok {
				continue
			}
			if s.Protocol != protocol.TransportTCP {
				return fmt.Errorf("CLOSE_WRITE for non-TCP stream %d", f.Stream)
			}
			s.closeRead(false)
		case protocol.TypePing:
			_ = c.WriteFrame(&protocol.Frame{Type: protocol.TypePong})
		case protocol.TypePong:
			// noop
		default:
			return fmt.Errorf("unexpected frame type %q after handshake", f.Type)
		}
	}
}

// Close shuts down the underlying connection.
func (c *Conn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	err := c.raw.Close()
	c.closeStreams()
	return err
}

func (c *Conn) closeAll() {
	_ = c.Close()
	c.closeStreams()
}

func (c *Conn) closeStreams() {
	c.streamsMu.Lock()
	streams := make([]*Stream, 0, len(c.streams))
	for _, s := range c.streams {
		streams = append(streams, s)
	}
	c.streams = make(map[uint32]*Stream)
	c.streamsMu.Unlock()
	for _, s := range streams {
		s.closeTunnel()
	}
}

func (c *Conn) addStream(s *Stream) error {
	if s.ID == 0 {
		return errors.New("zero stream ID")
	}
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()
	if _, ok := c.streams[s.ID]; ok {
		return fmt.Errorf("duplicate stream ID %d", s.ID)
	}
	if len(c.streams) >= c.maxStreams {
		return fmt.Errorf("concurrent stream limit %d reached", c.maxStreams)
	}
	c.streams[s.ID] = s
	return nil
}

func (c *Conn) getStream(id uint32) (*Stream, bool) {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()
	s, ok := c.streams[id]
	return s, ok
}

func (c *Conn) removeStream(id uint32) (*Stream, bool) {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()
	s, ok := c.streams[id]
	if ok {
		delete(c.streams, id)
	}
	return s, ok
}

// ActiveStreamCount returns the number of streams currently registered on the
// multiplexed connection.
func (c *Conn) ActiveStreamCount() int {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()
	return len(c.streams)
}

// Stream is one logical bidirectional connection within a tunnel.
type Stream struct {
	conn        *Conn
	ID          uint32
	Protocol    protocol.Transport
	Source      string
	Destination string
	rxMu        sync.Mutex
	rxBuf       []byte
	rxBufSize   int64
	rxQueue     [][]byte
	rxQueued    int64
	rxFrames    int
	rxNotify    chan struct{}
	doneCh      chan struct{}
	closeOnce   sync.Once
	rxClosed    atomic.Bool
	txCloseOnce sync.Once
	txClosed    atomic.Bool
	txMu        sync.Mutex
}

func newStream(c *Conn, id uint32) *Stream {
	return &Stream{
		conn:     c,
		ID:       id,
		Protocol: protocol.TransportTCP,
		rxNotify: make(chan struct{}, 1),
		doneCh:   make(chan struct{}),
	}
}

func normalizeProtocol(value string) (protocol.Transport, error) {
	switch protocol.Transport(value) {
	case "", protocol.TransportTCP:
		return protocol.TransportTCP, nil
	case protocol.TransportUDP:
		return protocol.TransportUDP, nil
	default:
		return "", fmt.Errorf("unsupported stream protocol %q", value)
	}
}

func (s *Stream) queueTCPPayload(payload []byte) bool {
	return s.queuePayload(payload, tcpStreamReceiveQueueByteSize, tcpStreamReceiveQueueFrameSize)
}

func (s *Stream) queueUDPPayload(payload []byte) bool {
	return s.queuePayload(payload, udpStreamReceiveQueueByteSize, udpStreamReceiveQueueFrameSize)
}

func (s *Stream) queuePayload(payload []byte, byteLimit int64, frameLimit int) bool {
	s.rxMu.Lock()
	defer s.rxMu.Unlock()
	if s.rxClosed.Load() || int64(len(payload)) > byteLimit-s.rxQueued || s.rxFrames >= frameLimit {
		return false
	}
	if !s.conn.reserveReceive(int64(len(payload))) {
		return false
	}
	s.rxQueue = append(s.rxQueue, payload)
	s.rxQueued += int64(len(payload))
	s.rxFrames++
	s.notifyRead()
	return true
}

func (c *Conn) reserveReceive(size int64) bool {
	c.receiveMu.Lock()
	defer c.receiveMu.Unlock()
	if size > c.rxByteLimit-c.rxBytes || c.rxFrames >= c.rxFrameLimit {
		return false
	}
	c.rxBytes += size
	c.rxFrames++
	return true
}

func (c *Conn) releaseReceive(size int64, frames int) {
	c.receiveMu.Lock()
	c.rxBytes -= size
	c.rxFrames -= frames
	c.receiveMu.Unlock()
}

func (s *Stream) notifyRead() {
	select {
	case s.rxNotify <- struct{}{}:
	default:
	}
}

// Read consumes data from the stream.
func (s *Stream) Read(p []byte) (int, error) {
	if s.Protocol != protocol.TransportTCP {
		return 0, errors.New("byte-stream read is unavailable for UDP")
	}
	for {
		s.rxMu.Lock()
		for len(s.rxBuf) == 0 && len(s.rxQueue) > 0 {
			s.rxBuf = s.rxQueue[0]
			s.rxBufSize = int64(len(s.rxBuf))
			s.rxQueue[0] = nil
			s.rxQueue = s.rxQueue[1:]
			if len(s.rxQueue) == 0 {
				s.rxQueue = nil
			}
			if len(s.rxBuf) == 0 {
				s.rxBufSize = 0
				s.rxFrames--
				s.conn.releaseReceive(0, 1)
			}
		}
		if len(s.rxBuf) > 0 {
			n := copy(p, s.rxBuf)
			s.rxBuf = s.rxBuf[n:]
			released := int64(0)
			frames := 0
			if len(s.rxBuf) == 0 {
				s.rxBuf = nil
				released = s.rxBufSize
				s.rxBufSize = 0
				s.rxQueued -= released
				s.rxFrames--
				frames = 1
			}
			if frames > 0 {
				s.conn.releaseReceive(released, frames)
			}
			s.rxMu.Unlock()
			return n, nil
		}
		closed := s.rxClosed.Load()
		s.rxMu.Unlock()
		if closed {
			return 0, io.EOF
		}
		<-s.rxNotify
	}
}

// Write sends data over the stream.
func (s *Stream) Write(p []byte) (int, error) {
	if s.Protocol != protocol.TransportTCP {
		return 0, errors.New("byte-stream write is unavailable for UDP")
	}
	s.txMu.Lock()
	defer s.txMu.Unlock()
	if s.txClosed.Load() {
		return 0, io.ErrClosedPipe
	}
	written := 0
	for len(p) > 0 {
		if s.txClosed.Load() {
			return written, io.ErrClosedPipe
		}
		n := min(len(p), protocol.MaxDataPayloadSize)
		if err := s.conn.WriteFrame(&protocol.Frame{Type: protocol.TypeData, Stream: s.ID, Data: p[:n]}); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// CloseWrite signals EOF to the peer while keeping the receive direction open.
// Without negotiated support it falls back to the legacy full stream close.
func (s *Stream) CloseWrite() error {
	if s.Protocol != protocol.TransportTCP {
		return errors.New("write half-close is unavailable for UDP")
	}
	if !s.conn.halfClose {
		return s.Close()
	}
	s.txMu.Lock()
	defer s.txMu.Unlock()
	select {
	case <-s.doneCh:
		return io.ErrClosedPipe
	default:
	}
	var err error
	s.txCloseOnce.Do(func() {
		s.txClosed.Store(true)
		err = s.conn.WriteFrame(&protocol.Frame{Type: protocol.TypeCloseWrite, Stream: s.ID})
	})
	return err
}

// ReadDatagram consumes exactly one UDP datagram without merging packet boundaries.
func (s *Stream) ReadDatagram(p []byte) (int, error) {
	if s.Protocol != protocol.TransportUDP {
		return 0, errors.New("datagram read is unavailable for TCP")
	}
	for {
		s.rxMu.Lock()
		if len(s.rxQueue) > 0 {
			payload := s.rxQueue[0]
			s.rxQueue[0] = nil
			s.rxQueue = s.rxQueue[1:]
			if len(s.rxQueue) == 0 {
				s.rxQueue = nil
			}
			s.rxQueued -= int64(len(payload))
			s.rxFrames--
			s.conn.releaseReceive(int64(len(payload)), 1)
			s.rxMu.Unlock()
			if len(payload) > len(p) {
				return 0, io.ErrShortBuffer
			}
			return copy(p, payload), nil
		}
		closed := s.rxClosed.Load()
		s.rxMu.Unlock()
		if closed {
			return 0, io.EOF
		}
		<-s.rxNotify
	}
}

// WriteDatagram sends one complete UDP datagram in one protocol frame.
func (s *Stream) WriteDatagram(p []byte) (int, error) {
	if s.Protocol != protocol.TransportUDP {
		return 0, errors.New("datagram write is unavailable for TCP")
	}
	if len(p) > protocol.MaxDatagramPayloadSize {
		return 0, fmt.Errorf("datagram payload too large: %d > %d", len(p), protocol.MaxDatagramPayloadSize)
	}
	if err := s.conn.WriteFrame(&protocol.Frame{Type: protocol.TypeDatagram, Stream: s.ID, Data: p}); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close signals the peer to close the stream and tears down local state.
func (s *Stream) Close() error {
	if !s.closeLocal() {
		s.conn.removeStream(s.ID)
		s.closeRead(true)
		return nil
	}
	s.sendClose()
	return nil
}

// closeRX closes the receive channel (called when peer sends CLOSE or tunnel dies).
func (s *Stream) closeRX() {
	s.markClosed(false, false)
}

func (s *Stream) closeLocal() bool {
	return s.markClosed(true, true)
}

func (s *Stream) closeTunnel() {
	s.markClosed(true, true)
	s.conn.removeStream(s.ID)
	s.closeRead(true)
}

func (s *Stream) markClosed(discard, remove bool) bool {
	closed := false
	s.closeOnce.Do(func() {
		if remove {
			s.conn.removeStream(s.ID)
		}
		s.txClosed.Store(true)
		close(s.doneCh)
		s.closeRead(discard)
		closed = true
	})
	return closed
}

func (s *Stream) closeRead(discard bool) {
	s.rxMu.Lock()
	s.rxClosed.Store(true)
	if discard && s.rxFrames > 0 {
		s.conn.releaseReceive(s.rxQueued, s.rxFrames)
		s.rxBuf = nil
		s.rxBufSize = 0
		for i := range s.rxQueue {
			s.rxQueue[i] = nil
		}
		s.rxQueue = nil
		s.rxQueued = 0
		s.rxFrames = 0
	}
	s.notifyRead()
	s.rxMu.Unlock()
}

func (s *Stream) abort() {
	if !s.closeLocal() {
		return
	}
	go s.sendClose()
}

func (s *Stream) sendClose() {
	s.txMu.Lock()
	defer s.txMu.Unlock()
	_ = s.conn.WriteFrame(&protocol.Frame{Type: protocol.TypeClose, Stream: s.ID})
}
