package tcpproxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProxyPropagatesBothTCPHalfCloses(t *testing.T) {
	leftClient, leftProxy := tcpPair(t)
	rightProxy, rightServer := tcpPair(t)
	defer leftClient.Close()
	defer rightServer.Close()
	deadline := time.Now().Add(2 * time.Second)
	_ = leftClient.SetDeadline(deadline)
	_ = rightServer.SetDeadline(deadline)

	var observedLeftToRight atomic.Int64
	var observedRightToLeft atomic.Int64
	proxyDone := make(chan Result, 1)
	go func() {
		proxyDone <- ProxyObserved(
			leftProxy,
			rightProxy,
			func(written int) { observedLeftToRight.Add(int64(written)) },
			func(written int) { observedRightToLeft.Add(int64(written)) },
		)
	}()
	request := []byte("request")
	response := bytes.Repeat([]byte("response"), 1024)
	serverDone := make(chan error, 1)
	go func() {
		got, err := io.ReadAll(rightServer)
		if err != nil {
			serverDone <- err
			return
		}
		if !bytes.Equal(got, request) {
			t.Errorf("server request = %q, want %q", got, request)
		}
		if _, err := rightServer.Write(response); err != nil {
			serverDone <- err
			return
		}
		serverDone <- rightServer.CloseWrite()
	}()

	if _, err := leftClient.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := leftClient.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(leftClient)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("client response length = %d, want %d", len(got), len(response))
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	result := <-proxyDone
	if result.LeftToRight != int64(len(request)) || result.RightToLeft != int64(len(response)) {
		t.Fatalf("proxy result = %+v", result)
	}
	if result.LeftToRightErr != nil || result.RightToLeftErr != nil {
		t.Fatalf("clean half-close errors = %v, %v", result.LeftToRightErr, result.RightToLeftErr)
	}
	if observedLeftToRight.Load() != int64(len(request)) || observedRightToLeft.Load() != int64(len(response)) {
		t.Fatalf("observed totals = %d/%d", observedLeftToRight.Load(), observedRightToLeft.Load())
	}
}

func TestProxyObservedCountsSuccessfulPartialWriteBeforeError(t *testing.T) {
	wantErr := errors.New("partial destination failure")
	left := &scriptedEndpoint{reader: bytes.NewReader([]byte("abcdef"))}
	right := &scriptedEndpoint{
		reader: bytes.NewReader(nil),
		write: func([]byte) (int, error) {
			return 3, wantErr
		},
	}
	var observed atomic.Int64
	result := ProxyObserved(left, right, func(written int) { observed.Add(int64(written)) }, nil)
	if result.LeftToRight != 3 || !errors.Is(result.LeftToRightErr, wantErr) {
		t.Fatalf("left-to-right result = %d/%v", result.LeftToRight, result.LeftToRightErr)
	}
	if observed.Load() != 3 {
		t.Fatalf("observed bytes = %d, want 3", observed.Load())
	}
}

func TestProxyAbortsBothEndpointsAfterCopyError(t *testing.T) {
	wantErr := errors.New("reset")
	left := &errorEndpoint{readErr: wantErr, closed: make(chan struct{})}
	right := &errorEndpoint{blockRead: true, closed: make(chan struct{})}
	done := make(chan Result, 1)
	go func() { done <- Proxy(left, right) }()

	select {
	case result := <-done:
		if !errors.Is(result.LeftToRightErr, wantErr) {
			t.Fatalf("left-to-right error = %v, want %v", result.LeftToRightErr, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy did not abort the opposite blocked copy after an error")
	}
	select {
	case <-left.closed:
	default:
		t.Fatal("left endpoint was not closed")
	}
	select {
	case <-right.closed:
	default:
		t.Fatal("right endpoint was not closed")
	}
}

type errorEndpoint struct {
	readErr   error
	blockRead bool
	closed    chan struct{}
	closeOnce sync.Once
}

type scriptedEndpoint struct {
	reader io.Reader
	write  func([]byte) (int, error)
}

func (e *scriptedEndpoint) Read(payload []byte) (int, error) {
	return e.reader.Read(payload)
}

func (e *scriptedEndpoint) Write(payload []byte) (int, error) {
	if e.write != nil {
		return e.write(payload)
	}
	return len(payload), nil
}

func (*scriptedEndpoint) Close() error { return nil }

func (e *errorEndpoint) Read([]byte) (int, error) {
	if e.blockRead {
		<-e.closed
		return 0, io.EOF
	}
	return 0, e.readErr
}

func (e *errorEndpoint) Write(payload []byte) (int, error) { return len(payload), nil }

func (e *errorEndpoint) Close() error {
	e.closeOnce.Do(func() { close(e.closed) })
	return nil
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	defer listener.Close()
	select {
	case server := <-accepted:
		return client, server
	case err := <-acceptErr:
		_ = client.Close()
		t.Fatal(err)
	}
	return nil, nil
}
