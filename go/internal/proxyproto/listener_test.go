package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestWrapListenerAcceptsEncodedHeaders(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		destination string
	}{
		{"IPv4", "192.0.2.1:1234", "198.51.100.2:443"},
		{"IPv6", "[2001:db8::1]:1234", "[2001:db8::2]:443"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header, err := V2(test.source, test.destination)
			if err != nil {
				t.Fatal(err)
			}
			server, client := net.Pipe()
			accepted := &deadlineConn{Conn: server}
			listener, err := WrapListener(&singleConnListener{conn: accepted}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			result := acceptAsync(listener)
			if _, err := client.Write(header); err != nil {
				t.Fatal(err)
			}
			conn := receiveAccepted(t, result)
			defer conn.Close()
			assertTCPAddr(t, conn.RemoteAddr(), test.source)
			assertTCPAddr(t, conn.LocalAddr(), test.destination)
			assertDeadlineWasSetAndCleared(t, accepted)

			payload := []byte("application bytes")
			go func() { _, _ = client.Write(payload) }()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("application payload = %q, want %q", got, payload)
			}
			_ = client.Close()
		})
	}
}

func TestWrapListenerHandlesFragmentedHeaders(t *testing.T) {
	header, err := V2("192.0.2.1:1234", "198.51.100.2:443")
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	listener, err := WrapListener(&singleConnListener{conn: server}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	result := acceptAsync(listener)
	for _, part := range [][]byte{header[:5], header[5:17], header[17:]} {
		if _, err := client.Write(part); err != nil {
			t.Fatal(err)
		}
	}
	conn := receiveAccepted(t, result)
	defer conn.Close()
	assertTCPAddr(t, conn.RemoteAddr(), "192.0.2.1:1234")
	_ = client.Close()
}

func TestWrapListenerLeavesApplicationBytesUnread(t *testing.T) {
	header, err := V2("192.0.2.1:1234", "198.51.100.2:443")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("application bytes")
	accepted := &memoryConn{reader: bytes.NewReader(append(header, payload...))}
	listener, err := WrapListener(&singleConnListener{conn: accepted}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("application payload = %q, want %q", got, payload)
	}
}

func TestWrapListenerIgnoresValidTLVs(t *testing.T) {
	header, err := V2("192.0.2.1:1234", "198.51.100.2:443")
	if err != nil {
		t.Fatal(err)
	}
	header = appendTLV(header, 0xea, []byte("metadata"))
	server, client := net.Pipe()
	listener, err := WrapListener(&singleConnListener{conn: server}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	result := acceptAsync(listener)
	if _, err := client.Write(header); err != nil {
		t.Fatal(err)
	}
	conn := receiveAccepted(t, result)
	defer conn.Close()
	assertTCPAddr(t, conn.RemoteAddr(), "192.0.2.1:1234")
	_ = client.Close()
}

func TestWrapListenerRejectsInvalidHeaders(t *testing.T) {
	valid, err := V2("192.0.2.1:1234", "198.51.100.2:443")
	if err != nil {
		t.Fatal(err)
	}
	validIPv6, err := V2("[2001:db8::1]:1234", "[2001:db8::2]:443")
	if err != nil {
		t.Fatal(err)
	}
	var unspecifiedIPv6 [16]byte
	mappedUnspecifiedIPv6 := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0}
	tests := []struct {
		name     string
		header   []byte
		truncate bool
	}{
		{"truncated", valid[:10], true},
		{name: "signature", header: replaceByte(valid, 0, 0)},
		{name: "version", header: replaceByte(valid, 12, 0x11)},
		{name: "LOCAL command", header: replaceByte(valid, 12, 0x20)},
		{name: "family", header: replaceByte(valid, 13, 0x31)},
		{name: "transport", header: replaceByte(valid, 13, 0x12)},
		{name: "short length", header: withLength(valid, 11)},
		{name: "unspecified source", header: replaceBytes(valid, 16, []byte{0, 0, 0, 0})},
		{name: "IPv6 unspecified source", header: replaceBytes(validIPv6, 16, unspecifiedIPv6[:])},
		{name: "IPv4-mapped unspecified source", header: replaceBytes(validIPv6, 16, mappedUnspecifiedIPv6[:])},
		{name: "zero source port", header: replaceBytes(valid, 24, []byte{0, 0})},
		{name: "oversized payload", header: withLength(valid, maxV2PayloadLength+1)},
		{name: "truncated TLV", header: malformedTLV(valid)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, client := net.Pipe()
			accepted := &deadlineConn{Conn: server}
			listener, err := WrapListener(&singleConnListener{conn: accepted}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			result := acceptAsync(listener)
			if test.truncate {
				go func() {
					_, _ = client.Write(test.header)
					_ = client.Close()
				}()
			} else {
				go func() { _, _ = client.Write(test.header) }()
			}
			if err := receiveRejected(t, result); err == nil {
				t.Fatal("Accept succeeded")
			}
			if !accepted.wasClosed() {
				t.Fatal("accepted connection was not closed")
			}
			_ = client.Close()
		})
	}
}

func TestWrapListenerFailsClosedForDeadlineErrors(t *testing.T) {
	t.Run("set", func(t *testing.T) {
		server, client := net.Pipe()
		defer client.Close()
		accepted := &deadlineConn{Conn: server, failSet: true}
		listener, err := WrapListener(&singleConnListener{conn: accepted}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		if err := receiveRejected(t, acceptAsync(listener)); err == nil {
			t.Fatal("Accept succeeded")
		}
		if !accepted.wasClosed() {
			t.Fatal("connection was not closed after deadline failure")
		}
	})

	t.Run("clear", func(t *testing.T) {
		header, err := V2("192.0.2.1:1234", "198.51.100.2:443")
		if err != nil {
			t.Fatal(err)
		}
		server, client := net.Pipe()
		accepted := &deadlineConn{Conn: server, failClear: true}
		listener, err := WrapListener(&singleConnListener{conn: accepted}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()

		result := acceptAsync(listener)
		go func() { _, _ = client.Write(header) }()
		if err := receiveRejected(t, result); err == nil {
			t.Fatal("Accept succeeded")
		}
		if !accepted.wasClosed() {
			t.Fatal("connection was not closed after deadline failure")
		}
		_ = client.Close()
	})
}

func TestWrapListenerHeaderTimeout(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	accepted := &deadlineConn{Conn: server}
	listener, err := WrapListener(&singleConnListener{conn: accepted}, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := receiveRejected(t, acceptAsync(listener)); err == nil {
		t.Fatal("Accept succeeded")
	}
	if !accepted.wasClosed() {
		t.Fatal("connection was not closed after timeout")
	}
}

func TestWrapListenerRejectsInvalidConfiguration(t *testing.T) {
	if _, err := WrapListener(nil, time.Second); err == nil {
		t.Fatal("WrapListener accepted a nil listener")
	}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	for _, timeout := range []time.Duration{0, -time.Second} {
		if _, err := WrapListener(&singleConnListener{conn: server}, timeout); err == nil {
			t.Fatalf("WrapListener accepted timeout %s", timeout)
		}
	}
}

type acceptResult struct {
	conn net.Conn
	err  error
}

func acceptAsync(listener net.Listener) <-chan acceptResult {
	result := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		result <- acceptResult{conn: conn, err: err}
	}()
	return result
}

func receiveAccepted(t *testing.T, result <-chan acceptResult) net.Conn {
	t.Helper()
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got.conn
	case <-time.After(time.Second):
		t.Fatal("Accept did not return")
		return nil
	}
}

func receiveRejected(t *testing.T, result <-chan acceptResult) error {
	t.Helper()
	select {
	case got := <-result:
		if got.conn != nil {
			_ = got.conn.Close()
			t.Fatal("Accept returned a connection")
		}
		return got.err
	case <-time.After(time.Second):
		t.Fatal("Accept did not return")
		return nil
	}
}

func assertTCPAddr(t *testing.T, address net.Addr, want string) {
	t.Helper()
	got, ok := address.(*net.TCPAddr)
	if !ok {
		t.Fatalf("address type = %T, want *net.TCPAddr", address)
	}
	wantAddr, err := net.ResolveTCPAddr("tcp", want)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IP.Equal(wantAddr.IP) || got.Port != wantAddr.Port {
		t.Fatalf("address = %v, want %v", got, wantAddr)
	}
}

func appendTLV(header []byte, kind byte, value []byte) []byte {
	result := append([]byte(nil), header...)
	result = append(result, kind, 0, 0)
	binary.BigEndian.PutUint16(result[len(header)+1:len(header)+3], uint16(len(value)))
	result = append(result, value...)
	binary.BigEndian.PutUint16(result[14:16], uint16(len(result)-v2FixedHeaderLength))
	return result
}

func malformedTLV(header []byte) []byte {
	result := append([]byte(nil), header...)
	result = append(result, 0xea, 0, 1)
	binary.BigEndian.PutUint16(result[14:16], uint16(len(result)-v2FixedHeaderLength))
	return result
}

func replaceByte(value []byte, offset int, replacement byte) []byte {
	result := append([]byte(nil), value...)
	result[offset] = replacement
	return result
}

func replaceBytes(value []byte, offset int, replacement []byte) []byte {
	result := append([]byte(nil), value...)
	copy(result[offset:], replacement)
	return result
}

func withLength(value []byte, length int) []byte {
	result := append([]byte(nil), value...)
	binary.BigEndian.PutUint16(result[14:16], uint16(length))
	return result
}

type singleConnListener struct {
	conn net.Conn
}

func (l *singleConnListener) Accept() (net.Conn, error) { return l.conn, nil }
func (l *singleConnListener) Close() error              { return nil }
func (l *singleConnListener) Addr() net.Addr            { return &net.TCPAddr{} }

type deadlineConn struct {
	net.Conn
	failSet   bool
	failClear bool

	mu        sync.Mutex
	deadlines []time.Time
	closed    bool
}

func (c *deadlineConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	fail := c.failSet && !deadline.IsZero() || c.failClear && deadline.IsZero()
	c.mu.Unlock()
	if fail {
		return errors.New("deadline failed")
	}
	return c.Conn.SetReadDeadline(deadline)
}

func (c *deadlineConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *deadlineConn) wasClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func assertDeadlineWasSetAndCleared(t *testing.T, conn *deadlineConn) {
	t.Helper()
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.deadlines) != 2 || conn.deadlines[0].IsZero() || !conn.deadlines[1].IsZero() {
		t.Fatalf("read deadlines = %v, want temporary deadline followed by clear", conn.deadlines)
	}
}

type memoryConn struct {
	reader *bytes.Reader
}

func (c *memoryConn) Read(payload []byte) (int, error)  { return c.reader.Read(payload) }
func (c *memoryConn) Write(payload []byte) (int, error) { return len(payload), nil }
func (c *memoryConn) Close() error                      { return nil }
func (c *memoryConn) LocalAddr() net.Addr               { return &net.TCPAddr{} }
func (c *memoryConn) RemoteAddr() net.Addr              { return &net.TCPAddr{} }
func (c *memoryConn) SetDeadline(time.Time) error       { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error   { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error  { return nil }
