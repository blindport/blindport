package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/protocol"
)

// TestTunnelEndToEnd connects two tunnel Conns over an in-memory pipe and
// proves bidirectional data flow.
func TestTunnelEndToEnd(t *testing.T) {
	a, b := net.Pipe()

	// "Server" side: echo every stream it accepts.
	server := New(a, func(s *Stream) {
		defer s.Close()
		buf := make([]byte, 64)
		n, err := s.Read(buf)
		if err != nil && err != io.EOF {
			t.Errorf("server read: %v", err)
			return
		}
		_, _ = s.Write(buf[:n])
	})
	go func() { _ = server.Run() }()

	client := New(b, nil)
	go func() { _ = client.Run() }()
	defer client.Close()
	defer server.Close()

	stream, err := client.OpenStream("tcp", "src", "dst")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	stream.conn.raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := stream.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("want ping, got %q", buf[:n])
	}
}

func TestStreamWriteChunksDataFrames(t *testing.T) {
	raw := &bufferConn{}
	c := New(raw, nil)
	s := newStream(c, 1)
	want := bytes.Repeat([]byte("x"), 2*protocol.MaxDataPayloadSize+123)

	n, err := s.Write(want)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(want) {
		t.Fatalf("wrote %d bytes, want %d", n, len(want))
	}

	var got []byte
	for i, wantSize := range []int{protocol.MaxDataPayloadSize, protocol.MaxDataPayloadSize, 123} {
		frame, err := protocol.ReadFrame(&raw.Buffer)
		if err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		if frame.Type != protocol.TypeData || frame.Stream != s.ID {
			t.Fatalf("frame %d = %+v", i, frame)
		}
		if len(frame.Data) != wantSize {
			t.Fatalf("frame %d payload = %d bytes, want %d", i, len(frame.Data), wantSize)
		}
		got = append(got, frame.Data...)
	}
	if raw.Len() != 0 {
		t.Fatalf("unexpected trailing frame data: %d bytes", raw.Len())
	}
	if !bytes.Equal(got, want) {
		t.Fatal("chunked payload differs from input")
	}
}

func TestDatagramStreamPreservesPacketBoundaries(t *testing.T) {
	a, b := net.Pipe()
	opened := make(chan *Stream, 1)
	server := New(a, func(s *Stream) { opened <- s })
	client := New(b, nil)
	go func() { _ = server.Run() }()
	go func() { _ = client.Run() }()
	defer server.Close()
	defer client.Close()

	stream, err := client.OpenStream("udp", "192.0.2.1:1234", "203.0.113.20:10000")
	if err != nil {
		t.Fatal(err)
	}
	peer := <-opened
	if peer.Protocol != protocol.TransportUDP || peer.Source != "192.0.2.1:1234" || peer.Destination != "203.0.113.20:10000" {
		t.Fatalf("OPEN metadata = %+v", peer)
	}
	for _, packet := range [][]byte{[]byte("first"), {}, []byte("third")} {
		if _, err := stream.WriteDatagram(packet); err != nil {
			t.Fatal(err)
		}
	}
	buffer := make([]byte, protocol.MaxDatagramPayloadSize)
	for _, want := range [][]byte{[]byte("first"), {}, []byte("third")} {
		n, err := peer.ReadDatagram(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buffer[:n], want) {
			t.Fatalf("datagram = %q, want %q", buffer[:n], want)
		}
	}
}

func TestStreamDrainsQueuedPayloadAfterPeerClose(t *testing.T) {
	t.Run("TCP", func(t *testing.T) {
		opened := make(chan *Stream, 1)
		frames := []*protocol.Frame{
			{Type: protocol.TypeOpen, Stream: 1, Proto: "tcp"},
			{Type: protocol.TypeData, Stream: 1, Data: []byte("response ")},
			{Type: protocol.TypeData, Stream: 1, Data: []byte("body")},
			{Type: protocol.TypeClose, Stream: 1},
		}
		if err := runTunnelFrames(t, func(stream *Stream) { opened <- stream }, frames); err != nil {
			t.Fatal(err)
		}
		stream := <-opened

		got, err := io.ReadAll(stream)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "response body" {
			t.Fatalf("drained payload = %q", got)
		}
	})

	t.Run("UDP", func(t *testing.T) {
		opened := make(chan *Stream, 1)
		frames := []*protocol.Frame{
			{Type: protocol.TypeOpen, Stream: 1, Proto: "udp"},
			{Type: protocol.TypeDatagram, Stream: 1, Data: []byte("first")},
			{Type: protocol.TypeDatagram, Stream: 1, Data: []byte("second")},
			{Type: protocol.TypeClose, Stream: 1},
		}
		if err := runTunnelFrames(t, func(stream *Stream) { opened <- stream }, frames); err != nil {
			t.Fatal(err)
		}
		stream := <-opened

		buffer := make([]byte, 16)
		for _, want := range []string{"first", "second"} {
			n, err := stream.ReadDatagram(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if string(buffer[:n]) != want {
				t.Fatalf("drained datagram = %q, want %q", buffer[:n], want)
			}
		}
		if _, err := stream.ReadDatagram(buffer); !errors.Is(err, io.EOF) {
			t.Fatalf("final read error = %v, want EOF", err)
		}
	})
}

func TestStreamAPIsRejectWrongTransport(t *testing.T) {
	c := New(&bufferConn{}, nil)
	tcp := newStream(c, 1)
	udp := newStream(c, 2)
	udp.Protocol = protocol.TransportUDP
	if _, err := tcp.WriteDatagram([]byte("packet")); err == nil {
		t.Fatal("TCP stream accepted datagram write")
	}
	if _, err := udp.Write([]byte("bytes")); err == nil {
		t.Fatal("UDP stream accepted byte-stream write")
	}
}

func TestConcurrentStreamLimit(t *testing.T) {
	c := New(&bufferConn{}, func(*Stream) {})
	for id := uint32(1); id <= MaxConcurrentStreams; id++ {
		if err := c.addStream(newStream(c, id)); err != nil {
			t.Fatalf("add stream %d: %v", id, err)
		}
	}
	err := c.addStream(newStream(c, MaxConcurrentStreams+1))
	if err == nil || !strings.Contains(err.Error(), "concurrent stream limit") {
		t.Fatalf("limit error = %v", err)
	}
}

func TestConfiguredStreamLimit(t *testing.T) {
	c, err := NewWithStreamLimit(&bufferConn{}, func(*Stream) {}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.addStream(newStream(c, 1)); err != nil {
		t.Fatal(err)
	}
	if err := c.addStream(newStream(c, 2)); err == nil || !strings.Contains(err.Error(), "limit 1") {
		t.Fatalf("second stream error = %v", err)
	}
	if _, err := NewWithStreamLimit(&bufferConn{}, nil, 0); err == nil {
		t.Fatal("zero stream limit accepted")
	}
}

func TestFrameWriteFailureClosesTunnel(t *testing.T) {
	local, peer := net.Pipe()
	connection := New(local, nil)
	_ = peer.Close()
	if err := connection.WriteFrame(&protocol.Frame{Type: protocol.TypePing}); err == nil {
		t.Fatal("WriteFrame succeeded after peer close")
	}
	if !connection.closed.Load() {
		t.Fatal("failed frame write did not close tunnel")
	}
}

func TestRunRejectsInvalidOpen(t *testing.T) {
	tests := []struct {
		name    string
		onOpen  func(*Stream)
		frames  []*protocol.Frame
		wantErr string
	}{
		{
			name:    "zero ID",
			onOpen:  func(*Stream) {},
			frames:  []*protocol.Frame{{Type: protocol.TypeOpen}},
			wantErr: "zero stream ID",
		},
		{
			name:   "duplicate ID",
			onOpen: func(*Stream) {},
			frames: []*protocol.Frame{
				{Type: protocol.TypeOpen, Stream: 7},
				{Type: protocol.TypeOpen, Stream: 7},
			},
			wantErr: "duplicate stream ID 7",
		},
		{
			name:    "outbound-only role",
			frames:  []*protocol.Frame{{Type: protocol.TypeOpen, Stream: 1}},
			wantErr: "unexpected OPEN",
		},
		{
			name:    "unknown protocol",
			onOpen:  func(*Stream) {},
			frames:  []*protocol.Frame{{Type: protocol.TypeOpen, Stream: 1, Proto: "sctp"}},
			wantErr: "unsupported stream protocol",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runTunnelFrames(t, tt.onOpen, tt.frames)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Run error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestRunIgnoresDataForUnknownStream(t *testing.T) {
	err := runTunnelFrames(t, func(*Stream) {}, []*protocol.Frame{
		{Type: protocol.TypeData, Stream: 99, Data: []byte("unexpected")},
	})
	if err != nil {
		t.Fatalf("Run error = %v, want nil", err)
	}
}

func TestRunClosesOnlySaturatedStream(t *testing.T) {
	tunnelSide, peer := net.Pipe()
	opened := make(chan *Stream, 2)
	c := New(tunnelSide, func(stream *Stream) { opened <- stream })
	runDone := make(chan error, 1)
	go func() { runDone <- c.Run() }()

	if err := protocol.WriteFrame(peer, &protocol.Frame{Type: protocol.TypeOpen, Stream: 1}); err != nil {
		t.Fatalf("open saturated stream: %v", err)
	}
	first := <-opened
	for range streamReceiveQueueSize + 1 {
		if err := protocol.WriteFrame(peer, &protocol.Frame{Type: protocol.TypeData, Stream: 1, Data: []byte("queued")}); err != nil {
			t.Fatalf("fill receive queue: %v", err)
		}
	}
	closed, err := protocol.ReadFrame(peer)
	if err != nil {
		t.Fatalf("read saturated stream close: %v", err)
	}
	if closed.Type != protocol.TypeClose || closed.Stream != first.ID {
		t.Fatalf("close frame = %+v", closed)
	}

	if err := protocol.WriteFrame(peer, &protocol.Frame{Type: protocol.TypeOpen, Stream: 2}); err != nil {
		t.Fatalf("open healthy stream: %v", err)
	}
	second := <-opened
	if err := protocol.WriteFrame(peer, &protocol.Frame{Type: protocol.TypeData, Stream: 2, Data: []byte("healthy")}); err != nil {
		t.Fatalf("write healthy stream: %v", err)
	}
	buf := make([]byte, 16)
	n, err := second.Read(buf)
	if err != nil {
		t.Fatalf("read healthy stream: %v", err)
	}
	if string(buf[:n]) != "healthy" {
		t.Fatalf("healthy stream data = %q", buf[:n])
	}

	_ = peer.Close()
	if err := <-runDone; err != nil {
		t.Fatalf("Run error = %v, want nil", err)
	}
}

func TestRunDropsUDPDatagramBeyondReceiveByteLimit(t *testing.T) {
	tunnelSide, peer := net.Pipe()
	opened := make(chan *Stream, 1)
	c := New(tunnelSide, func(stream *Stream) { opened <- stream })
	var dropped atomic.Int64
	c.SetUDPDropHandler(func() { dropped.Add(1) })
	runDone := make(chan error, 1)
	go func() { runDone <- c.Run() }()

	if err := protocol.WriteFrame(peer, &protocol.Frame{Type: protocol.TypeOpen, Stream: 1, Proto: "udp"}); err != nil {
		t.Fatal(err)
	}
	stream := <-opened
	packet := bytes.Repeat([]byte("u"), protocol.MaxDatagramPayloadSize)
	queuedPackets := streamReceiveQueueByteSize / len(packet)
	for range queuedPackets + 1 {
		if err := protocol.WriteFrame(peer, &protocol.Frame{Type: protocol.TypeDatagram, Stream: 1, Data: packet}); err != nil {
			t.Fatal(err)
		}
	}
	if err := protocol.WriteFrame(peer, &protocol.Frame{Type: protocol.TypePing}); err != nil {
		t.Fatal(err)
	}
	if reply, err := protocol.ReadFrame(peer); err != nil || reply.Type != protocol.TypePong {
		t.Fatalf("queue synchronization reply = %+v, %v", reply, err)
	}
	if _, ok := c.getStream(stream.ID); !ok {
		t.Fatal("UDP receive saturation closed the association stream")
	}
	if got := dropped.Load(); got != 1 {
		t.Fatalf("observed UDP receive queue drops = %d, want 1", got)
	}

	buffer := make([]byte, protocol.MaxDatagramPayloadSize)
	for range queuedPackets {
		if n, err := stream.ReadDatagram(buffer); err != nil || n != len(packet) {
			t.Fatalf("read queued maximum datagram = %d, %v", n, err)
		}
	}
	marker := []byte("after-drop")
	if err := protocol.WriteFrame(peer, &protocol.Frame{Type: protocol.TypeDatagram, Stream: 1, Data: marker}); err != nil {
		t.Fatal(err)
	}
	if n, err := stream.ReadDatagram(buffer); err != nil || !bytes.Equal(buffer[:n], marker) {
		t.Fatalf("read after dropped datagram = %q, %v", buffer[:n], err)
	}

	_ = peer.Close()
	if err := <-runDone; err != nil {
		t.Fatalf("Run error = %v, want nil", err)
	}
}

// TestProtocolFraming sanity checks that framed reads survive split writes.
func TestProtocolFraming(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		_ = protocol.WriteFrame(a, &protocol.Frame{Type: protocol.TypePing})
	}()
	f, err := protocol.ReadFrame(b)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if f.Type != protocol.TypePing {
		t.Fatalf("want ping, got %s", f.Type)
	}
}

func runTunnelFrames(t *testing.T, onOpen func(*Stream), frames []*protocol.Frame) error {
	t.Helper()
	tunnelSide, peer := net.Pipe()
	writeDone := make(chan error, 1)
	go func() {
		defer peer.Close()
		for _, frame := range frames {
			if err := protocol.WriteFrame(peer, frame); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()

	err := New(tunnelSide, onOpen).Run()
	if writeErr := <-writeDone; writeErr != nil && !errors.Is(writeErr, net.ErrClosed) && !errors.Is(writeErr, io.ErrClosedPipe) {
		t.Fatalf("write frames: %v", writeErr)
	}
	return err
}

type bufferConn struct {
	bytes.Buffer
}

func (c *bufferConn) Close() error                     { return nil }
func (c *bufferConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *bufferConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *bufferConn) SetDeadline(time.Time) error      { return nil }
func (c *bufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufferConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }
