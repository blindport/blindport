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
		tunnelSide, peer := net.Pipe()
		opened := make(chan *Stream, 1)
		connection := New(tunnelSide, func(stream *Stream) { opened <- stream })
		runDone := make(chan error, 1)
		go func() { runDone <- connection.Run() }()
		frames := []*protocol.Frame{
			{Type: protocol.TypeOpen, Stream: 1, Proto: "tcp"},
			{Type: protocol.TypeData, Stream: 1, Data: []byte("response ")},
			{Type: protocol.TypeData, Stream: 1, Data: []byte("body")},
			{Type: protocol.TypeClose, Stream: 1},
			{Type: protocol.TypePing},
		}
		for _, frame := range frames {
			if err := protocol.WriteFrame(peer, frame); err != nil {
				t.Fatal(err)
			}
		}
		if frame, err := protocol.ReadFrame(peer); err != nil || frame.Type != protocol.TypePong {
			t.Fatalf("close synchronization = %+v, %v", frame, err)
		}
		stream := <-opened

		got, err := io.ReadAll(stream)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "response body" {
			t.Fatalf("drained payload = %q", got)
		}
		assertReceiveAccounting(t, stream.conn, 0, 0)
		_ = stream.Close()
		_ = peer.Close()
		if err := <-runDone; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("UDP", func(t *testing.T) {
		tunnelSide, peer := net.Pipe()
		opened := make(chan *Stream, 1)
		connection := New(tunnelSide, func(stream *Stream) { opened <- stream })
		runDone := make(chan error, 1)
		go func() { runDone <- connection.Run() }()
		frames := []*protocol.Frame{
			{Type: protocol.TypeOpen, Stream: 1, Proto: "udp"},
			{Type: protocol.TypeDatagram, Stream: 1, Data: []byte("first")},
			{Type: protocol.TypeDatagram, Stream: 1, Data: []byte("second")},
			{Type: protocol.TypeClose, Stream: 1},
			{Type: protocol.TypePing},
		}
		for _, frame := range frames {
			if err := protocol.WriteFrame(peer, frame); err != nil {
				t.Fatal(err)
			}
		}
		if frame, err := protocol.ReadFrame(peer); err != nil || frame.Type != protocol.TypePong {
			t.Fatalf("close synchronization = %+v, %v", frame, err)
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
		assertReceiveAccounting(t, stream.conn, 0, 0)
		_ = stream.Close()
		_ = peer.Close()
		if err := <-runDone; err != nil {
			t.Fatal(err)
		}
	})
}

func TestTCPHalfCloseDrainsLargeReverseResponseAndCleansUp(t *testing.T) {
	const responseFrameCount = 48
	a, b := net.Pipe()
	requestRead := make(chan []byte, 1)
	serverDone := make(chan error, 1)
	server := New(a, func(stream *Stream) {
		defer stream.Close()
		request, err := io.ReadAll(stream)
		if err != nil {
			serverDone <- err
			return
		}
		requestRead <- request
		response := append(bytes.Repeat([]byte("r"), responseFrameCount*protocol.MaxDataPayloadSize), []byte("final reverse response")...)
		if _, err := stream.Write(response); err != nil {
			serverDone <- err
			return
		}
		serverDone <- stream.CloseWrite()
	})
	client := New(b, nil)
	server.EnableTCPHalfClose()
	client.EnableTCPHalfClose()
	serverRun := make(chan error, 1)
	clientRun := make(chan error, 1)
	go func() { serverRun <- server.Run() }()
	go func() { clientRun <- client.Run() }()
	defer server.Close()
	defer client.Close()

	stream, err := client.OpenStream("tcp", "src", "dst")
	if err != nil {
		t.Fatal(err)
	}
	request := []byte("request requiring EOF")
	if _, err := stream.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got := <-requestRead; !bytes.Equal(got, request) {
		t.Fatalf("request = %q, want %q", got, request)
	}

	wantSize := responseFrameCount*protocol.MaxDataPayloadSize + len("final reverse response")
	response, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(response) != wantSize || !bytes.HasSuffix(response, []byte("final reverse response")) {
		t.Fatalf("response length = %d, suffix = %q", len(response), response[max(0, len(response)-22):])
	}
	if wantSize <= 512<<10 {
		t.Fatal("test response no longer exceeds the legacy receive queue")
	}
	assertReceiveAccounting(t, client, 0, 0)
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("after FIN")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write after CloseWrite error = %v", err)
	}
	_ = stream.Close()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, clientOK := client.getStream(stream.ID); !clientOK {
			if _, serverOK := server.getStream(stream.ID); !serverOK {
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	if _, ok := client.getStream(stream.ID); ok {
		t.Fatal("client stream remained registered after full close")
	}
	if _, ok := server.getStream(stream.ID); ok {
		t.Fatal("server stream remained registered after full close")
	}

	_ = client.Close()
	_ = server.Close()
	if err := <-clientRun; err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("client Run error = %v", err)
	}
	if err := <-serverRun; err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("server Run error = %v", err)
	}
}

func TestCloseWriteUsesLegacyCloseWithoutNegotiation(t *testing.T) {
	raw := &bufferConn{}
	connection := New(raw, nil)
	stream := newStream(connection, 1)
	if err := connection.addStream(stream); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	frame, err := protocol.ReadFrame(&raw.Buffer)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != protocol.TypeClose {
		t.Fatalf("legacy CloseWrite frame = %q, want %q", frame.Type, protocol.TypeClose)
	}
}

func TestStreamCloseReleasesLocalStateBeforeWaitingForWriter(t *testing.T) {
	raw := &bufferConn{}
	connection := New(raw, nil)
	stream := newStream(connection, 1)
	if err := connection.addStream(stream); err != nil {
		t.Fatal(err)
	}

	stream.txMu.Lock()
	closeDone := make(chan struct{})
	go func() {
		_ = stream.Close()
		close(closeDone)
	}()
	select {
	case <-stream.doneCh:
	case <-time.After(time.Second):
		t.Fatal("Close did not release local stream state while a writer held the mutex")
	}
	if _, ok := connection.getStream(stream.ID); ok {
		t.Fatal("closed stream remained registered while waiting for the writer")
	}
	select {
	case <-closeDone:
		t.Fatal("Close returned before the writer mutex was released")
	default:
	}
	stream.txMu.Unlock()
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after the writer mutex was released")
	}
}

func TestReceiveAccountingTracksPartialReadAndFullClose(t *testing.T) {
	connection := New(&bufferConn{}, nil)
	stream := newStream(connection, 1)
	if err := connection.addStream(stream); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 100)
	if !stream.queueTCPPayload(payload) {
		t.Fatal("queue payload")
	}
	assertReceiveAccounting(t, connection, 100, 1)
	buffer := make([]byte, 10)
	if n, err := stream.Read(buffer); err != nil || n != len(buffer) {
		t.Fatalf("partial read = %d, %v", n, err)
	}
	// A slice into the frame retains its full allocation until the frame drains.
	assertReceiveAccounting(t, connection, 100, 1)
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	assertReceiveAccounting(t, connection, 0, 0)
}

func TestCloseWriteKeepsPayloadAccountedUntilDrain(t *testing.T) {
	connection := New(&bufferConn{}, nil)
	stream := newStream(connection, 1)
	if err := connection.addStream(stream); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("f"), 2*protocol.MaxDataPayloadSize)
	if !stream.queueTCPPayload(payload[:protocol.MaxDataPayloadSize]) || !stream.queueTCPPayload(payload[protocol.MaxDataPayloadSize:]) {
		t.Fatal("queue payload")
	}
	stream.closeRead(false)
	assertReceiveAccounting(t, connection, int64(len(payload)), 2)

	got, err := io.ReadAll(stream)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("drained payload = %d bytes, %v", len(got), err)
	}
	assertReceiveAccounting(t, connection, 0, 0)
	_ = stream.Close()
}

func TestTunnelCloseReleasesPeerClosedUndrainedPayload(t *testing.T) {
	local, peer := net.Pipe()
	connection := New(local, nil)
	stream := newStream(connection, 1)
	if err := connection.addStream(stream); err != nil {
		t.Fatal(err)
	}
	if !stream.queueTCPPayload(bytes.Repeat([]byte("z"), protocol.MaxDataPayloadSize)) {
		t.Fatal("queue payload")
	}
	stream.closeRX()
	assertReceiveAccounting(t, connection, protocol.MaxDataPayloadSize, 1)
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	assertReceiveAccounting(t, connection, 0, 0)
	_ = peer.Close()
}

func TestRunRejectsUnnegotiatedCloseWrite(t *testing.T) {
	err := runTunnelFrames(t, func(*Stream) {}, []*protocol.Frame{
		{Type: protocol.TypeOpen, Stream: 1},
		{Type: protocol.TypeCloseWrite, Stream: 1},
	})
	if err == nil || !strings.Contains(err.Error(), "without negotiated capability") {
		t.Fatalf("Run error = %v", err)
	}
}

func TestRunClosesStreamReceivingDataAfterCloseWrite(t *testing.T) {
	tunnelSide, peer := net.Pipe()
	opened := make(chan *Stream, 1)
	connection := New(tunnelSide, func(stream *Stream) { opened <- stream })
	connection.EnableTCPHalfClose()
	runDone := make(chan error, 1)
	go func() { runDone <- connection.Run() }()
	defer connection.Close()

	for _, frame := range []*protocol.Frame{
		{Type: protocol.TypeOpen, Stream: 1, Proto: "tcp"},
		{Type: protocol.TypeCloseWrite, Stream: 1},
		{Type: protocol.TypeData, Stream: 1, Data: []byte("after FIN")},
	} {
		if err := protocol.WriteFrame(peer, frame); err != nil {
			t.Fatal(err)
		}
	}
	stream := <-opened
	closeFrame, err := protocol.ReadFrame(peer)
	if err != nil || closeFrame.Type != protocol.TypeClose || closeFrame.Stream != stream.ID {
		t.Fatalf("post-FIN response = %+v, %v", closeFrame, err)
	}
	if payload, err := io.ReadAll(stream); err != nil || len(payload) != 0 {
		t.Fatalf("post-FIN read = %q, %v", payload, err)
	}
	if _, ok := connection.getStream(stream.ID); ok {
		t.Fatal("stream receiving DATA after CLOSE_WRITE remained open")
	}
	_ = peer.Close()
	if err := <-runDone; err != nil {
		t.Fatalf("Run error = %v, want nil", err)
	}
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

func TestSaturatedTCPStreamDoesNotBlockSiblingControlStream(t *testing.T) {
	tunnelSide, peer := net.Pipe()
	opened := make(chan *Stream, 2)
	c := New(tunnelSide, func(stream *Stream) { opened <- stream })
	c.EnableTCPHalfClose()
	runDone := make(chan error, 1)
	go func() { runDone <- c.Run() }()

	if err := protocol.WriteFrame(peer, &protocol.Frame{Type: protocol.TypeOpen, Stream: 1}); err != nil {
		t.Fatalf("open saturated stream: %v", err)
	}
	bulk := <-opened
	payload := bytes.Repeat([]byte("q"), protocol.MaxDataPayloadSize)
	frameCount := tcpStreamReceiveQueueByteSize/protocol.MaxDataPayloadSize + 1
	writeDone := make(chan error, 1)
	go func() {
		for range frameCount {
			if err := protocol.WriteFrame(peer, &protocol.Frame{Type: protocol.TypeData, Stream: 1, Data: payload}); err != nil {
				writeDone <- err
				return
			}
		}
		for _, frame := range []*protocol.Frame{
			{Type: protocol.TypeOpen, Stream: 2, Proto: "tcp"},
			{Type: protocol.TypeData, Stream: 2, Data: []byte("control result")},
			{Type: protocol.TypeCloseWrite, Stream: 2},
		} {
			if err := protocol.WriteFrame(peer, frame); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()
	if err := <-writeDone; err != nil {
		t.Fatalf("finish producer: %v", err)
	}
	control := <-opened
	if control.ID != 2 {
		t.Fatalf("sibling stream ID = %d", control.ID)
	}
	result, err := io.ReadAll(control)
	if err != nil || string(result) != "control result" {
		t.Fatalf("control response = %q, %v", result, err)
	}
	closeFrame, err := protocol.ReadFrame(peer)
	if err != nil || closeFrame.Type != protocol.TypeClose || closeFrame.Stream != bulk.ID {
		t.Fatalf("overflow response = %+v, %v", closeFrame, err)
	}
	if _, ok := c.getStream(bulk.ID); ok {
		t.Fatal("overflowing bulk stream remained registered")
	}
	assertReceiveAccounting(t, c, 0, 0)

	_ = peer.Close()
	if err := <-runDone; err != nil {
		t.Fatalf("Run error = %v, want nil", err)
	}
}

func TestSaturatedTCPQueueUnblocksWhenTunnelCloses(t *testing.T) {
	tunnelSide, peer := net.Pipe()
	opened := make(chan *Stream, 1)
	c := New(tunnelSide, func(stream *Stream) { opened <- stream })
	runDone := make(chan error, 1)
	go func() { runDone <- c.Run() }()

	if err := protocol.WriteFrame(peer, &protocol.Frame{Type: protocol.TypeOpen, Stream: 1}); err != nil {
		t.Fatal(err)
	}
	<-opened
	writeDone := make(chan error, 1)
	go func() {
		for range 48 {
			if err := protocol.WriteFrame(peer, &protocol.Frame{Type: protocol.TypeData, Stream: 1, Data: []byte("blocked")}); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()

	time.Sleep(25 * time.Millisecond)
	if queuedBytes(c) == 0 {
		t.Fatal("test did not queue TCP payload before tunnel shutdown")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("tunnel reader remained blocked on a saturated TCP queue")
	}
	assertReceiveAccounting(t, c, 0, 0)
	_ = peer.Close()
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("peer writer remained blocked after tunnel close")
	}
}

func TestGlobalTCPReceiveBudgetAbortsOnlyOffendingStream(t *testing.T) {
	tunnelSide, peer := net.Pipe()
	opened := make(chan *Stream, 2)
	connection := New(tunnelSide, func(stream *Stream) { opened <- stream })
	connection.rxByteLimit = 2 * protocol.MaxDataPayloadSize
	connection.rxFrameLimit = 8
	runDone := make(chan error, 1)
	go func() { runDone <- connection.Run() }()
	payload := bytes.Repeat([]byte("g"), protocol.MaxDataPayloadSize)

	for _, frame := range []*protocol.Frame{
		{Type: protocol.TypeOpen, Stream: 1, Proto: "tcp"},
		{Type: protocol.TypeData, Stream: 1, Data: payload},
		{Type: protocol.TypeData, Stream: 1, Data: payload},
		{Type: protocol.TypeOpen, Stream: 2, Proto: "tcp"},
		{Type: protocol.TypeData, Stream: 2, Data: payload},
		{Type: protocol.TypePing},
	} {
		if err := protocol.WriteFrame(peer, frame); err != nil {
			t.Fatal(err)
		}
	}
	first, second := <-opened, <-opened
	if first.ID != 1 || second.ID != 2 {
		t.Fatalf("opened streams = %d, %d", first.ID, second.ID)
	}

	seenClose, seenPong := false, false
	for range 2 {
		frame, err := protocol.ReadFrame(peer)
		if err != nil {
			t.Fatal(err)
		}
		seenClose = seenClose || (frame.Type == protocol.TypeClose && frame.Stream == second.ID)
		seenPong = seenPong || frame.Type == protocol.TypePong
	}
	if !seenClose || !seenPong {
		t.Fatalf("overflow replies: close=%t pong=%t", seenClose, seenPong)
	}
	if _, ok := connection.getStream(first.ID); !ok {
		t.Fatal("stream within the global budget was aborted")
	}
	if _, ok := connection.getStream(second.ID); ok {
		t.Fatal("stream exceeding the global budget remained registered")
	}
	assertReceiveAccounting(t, connection, int64(2*len(payload)), 2)

	got := make([]byte, 2*len(payload))
	if _, err := io.ReadFull(first, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat(payload, 2)) {
		t.Fatal("retained stream payload lost ordering")
	}
	assertReceiveAccounting(t, connection, 0, 0)

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
	queuedPackets := udpStreamReceiveQueueByteSize / len(packet)
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

func queuedBytes(connection *Conn) int64 {
	connection.receiveMu.Lock()
	defer connection.receiveMu.Unlock()
	return connection.rxBytes
}

func assertReceiveAccounting(t *testing.T, connection *Conn, wantBytes int64, wantFrames int) {
	t.Helper()
	connection.receiveMu.Lock()
	defer connection.receiveMu.Unlock()
	if connection.rxBytes != wantBytes || connection.rxFrames != wantFrames {
		t.Fatalf(
			"receive accounting = %d bytes, %d frames, want %d bytes, %d frames",
			connection.rxBytes, connection.rxFrames, wantBytes, wantFrames,
		)
	}
}
