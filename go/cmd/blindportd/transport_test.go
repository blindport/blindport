package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type socks5Request struct {
	target   string
	username string
	password string
}

type socks5TestProxy struct {
	listener net.Listener
	upstream string
	reply    byte
	stall    bool

	mu       sync.Mutex
	requests []socks5Request
}

func newSOCKS5TestProxy(t *testing.T, upstream string) *socks5TestProxy {
	return newSOCKS5TestProxyWithBehavior(t, upstream, 0, false)
}

func newSOCKS5TestProxyWithBehavior(t *testing.T, upstream string, reply byte, stall bool) *socks5TestProxy {
	t.Helper()
	listener := listenLocal(t)
	proxy := &socks5TestProxy{listener: listener, upstream: upstream, reply: reply, stall: stall}
	go proxy.serve()
	return proxy
}

func (p *socks5TestProxy) address() string {
	return p.listener.Addr().String()
}

func (p *socks5TestProxy) snapshot() []socks5Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]socks5Request(nil), p.requests...)
}

func (p *socks5TestProxy) targets() []string {
	requests := p.snapshot()
	targets := make([]string, len(requests))
	for index := range requests {
		targets[index] = requests[index].target
	}
	return targets
}

func (p *socks5TestProxy) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *socks5TestProxy) handle(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(reader, greeting); err != nil || greeting[0] != 5 {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(reader, methods); err != nil || !containsByte(methods, 2) {
		return
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return
	}
	username, password, err := readSOCKS5Auth(reader, conn)
	if err != nil {
		return
	}
	if p.stall {
		_, _ = io.Copy(io.Discard, reader)
		return
	}
	target, err := readSOCKS5Target(reader)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.requests = append(p.requests, socks5Request{target: target, username: username, password: password})
	p.mu.Unlock()
	if p.reply != 0 {
		_, _ = conn.Write([]byte{5, p.reply, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	var upstream net.Conn
	if p.upstream != "" {
		upstream, err = net.DialTimeout("tcp", p.upstream, time.Second)
		if err != nil {
			_, _ = conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer upstream.Close()
	}
	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil || upstream == nil {
		return
	}
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(upstream, reader)
		done <- struct{}{}
	}()
	_, _ = io.Copy(conn, upstream)
	_ = conn.Close()
	_ = upstream.Close()
	<-done
}

func readSOCKS5Auth(reader *bufio.Reader, conn net.Conn) (string, string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil || header[0] != 1 {
		return "", "", errors.New("invalid SOCKS5 auth header")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, username); err != nil {
		return "", "", err
	}
	passwordLength, err := reader.ReadByte()
	if err != nil {
		return "", "", err
	}
	password := make([]byte, int(passwordLength))
	if _, err := io.ReadFull(reader, password); err != nil {
		return "", "", err
	}
	if _, err := conn.Write([]byte{1, 0}); err != nil {
		return "", "", err
	}
	return string(username), string(password), nil
}

func readSOCKS5Target(reader *bufio.Reader) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil || header[0] != 5 || header[1] != 1 {
		return "", errors.New("invalid SOCKS5 connect request")
	}
	var host string
	switch header[3] {
	case 1:
		address := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case 3:
		length, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		address := make([]byte, int(length))
		if _, err := io.ReadFull(reader, address); err != nil {
			return "", err
		}
		host = string(address)
	case 4:
		address := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	default:
		return "", fmt.Errorf("unexpected SOCKS5 address type %d", header[3])
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(reader, port); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port[0])<<8|int(port[1]))), nil
}

func containsByte(values []byte, wanted byte) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestSOCKS5ForwardsDomainsAndReusesRandomIsolationCredentials(t *testing.T) {
	proxy := newSOCKS5TestProxy(t, "")
	outbound, err := newOutboundTransport(proxy.address())
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"bootstrap-example.onion:80", "relay-example.onion:5443"} {
		conn, err := outbound.relayDialer.DialContext(context.Background(), "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	requests := proxy.snapshot()
	if len(requests) != 2 {
		t.Fatalf("SOCKS requests = %d, want 2", len(requests))
	}
	if requests[0].target != "bootstrap-example.onion:80" || requests[1].target != "relay-example.onion:5443" {
		t.Fatalf("SOCKS targets = %q, %q", requests[0].target, requests[1].target)
	}
	if requests[0].username == "" || requests[0].password == "" {
		t.Fatal("SOCKS isolation credentials are empty")
	}
	if requests[0].username != requests[1].username || requests[0].password != requests[1].password {
		t.Fatal("SOCKS isolation credentials changed within one transport")
	}
}

func TestBackendBootstrapUsesSOCKS5(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "bootstrap-example.onion" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("backend host/auth = %q/%q", r.Host, r.Header.Get("Authorization"))
		}
		_, _ = io.WriteString(w, `[{"relay_endpoint":"relay-example.onion:5443","product":"relay","subscription_id":"11111111-1111-4111-8111-111111111111"}]`)
	}))
	defer backend.Close()
	proxy := newSOCKS5TestProxy(t, backend.Listener.Addr().String())
	outbound, err := newOutboundTransport(proxy.address())
	if err != nil {
		t.Fatal(err)
	}
	defer outbound.httpClient.CloseIdleConnections()

	config, err := fetchConfigWithClient(context.Background(), outbound.httpClient, "http://bootstrap-example.onion", "test-token")
	if err != nil || len(config) != 1 {
		t.Fatalf("fetch config = %+v, %v", config, err)
	}
	requests := proxy.snapshot()
	if len(requests) != 1 || requests[0].target != "bootstrap-example.onion:80" {
		t.Fatalf("SOCKS targets = %q", proxy.targets())
	}
}

func TestBackendBootstrapDoesNotFollowRedirectsWithBearerToken(t *testing.T) {
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		followed.Store(true)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	outbound, err := newOutboundTransport("")
	if err != nil {
		t.Fatal(err)
	}
	defer outbound.httpClient.CloseIdleConnections()

	_, err = fetchConfigWithClient(context.Background(), outbound.httpClient, redirect.URL, "test-token")
	if err == nil || !strings.Contains(err.Error(), "status 307") {
		t.Fatalf("fetchConfigWithClient() error = %v, want redirect status", err)
	}
	if followed.Load() {
		t.Fatal("bootstrap client followed a redirect carrying the bearer token")
	}
}

func TestCredentialEnrollmentAndRenewalUseConfiguredSOCKS5Client(t *testing.T) {
	backend := newEnrollmentServer(t)
	proxy := newSOCKS5TestProxy(t, backend.server.Listener.Addr().String())
	outbound, err := newOutboundTransport(proxy.address())
	if err != nil {
		t.Fatal(err)
	}
	defer outbound.httpClient.CloseIdleConnections()

	manager, err := openCredentialManager(context.Background(), outbound.httpClient, "http://enrollment-example.onion", "test-token", privateStateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if err := manager.renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	if backend.callCount() != 2 {
		t.Fatalf("enrollment calls = %d, want 2", backend.callCount())
	}
	requests := proxy.snapshot()
	if len(requests) == 0 || requests[0].target != "enrollment-example.onion:80" {
		t.Fatalf("SOCKS targets = %q", proxy.targets())
	}
}

func TestRelayTLSDialUsesSOCKS5Dialer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	proxy := newSOCKS5TestProxy(t, server.Listener.Addr().String())
	outbound, err := newOutboundTransport(proxy.address())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}
	conn, err := dialRelay(context.Background(), outbound.relayDialer, "relay-example.onion:5443", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: relay-example.onion\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	requests := proxy.snapshot()
	if len(requests) != 1 || requests[0].target != "relay-example.onion:5443" {
		t.Fatalf("SOCKS targets = %q", proxy.targets())
	}
}

func TestSOCKS5FailureDoesNotFallBackToDirectDialing(t *testing.T) {
	direct := listenLocal(t)
	proxy := newSOCKS5TestProxyWithBehavior(t, "", 5, false)
	outbound, err := newOutboundTransport(proxy.address())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialRelay(context.Background(), outbound.relayDialer, direct.Addr().String(), nil)
	if err == nil {
		_ = conn.Close()
		t.Fatal("relay dial succeeded after SOCKS failure")
	}
	if len(proxy.snapshot()) != 1 {
		t.Fatal("SOCKS proxy did not receive failed request")
	}
	if tcpListener, ok := direct.(*net.TCPListener); ok {
		_ = tcpListener.SetDeadline(time.Now().Add(30 * time.Millisecond))
	}
	if conn, acceptErr := direct.Accept(); acceptErr == nil {
		_ = conn.Close()
		t.Fatal("target received a direct fallback connection")
	}
}

func TestSOCKS5DialHonorsCancellationAndDeadline(t *testing.T) {
	for _, test := range []struct {
		name        string
		context     func() (context.Context, context.CancelFunc)
		wantedError error
	}{
		{
			name: "cancellation",
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(20*time.Millisecond, cancel)
				return ctx, cancel
			},
			wantedError: context.Canceled,
		},
		{
			name: "deadline",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 20*time.Millisecond)
			},
			wantedError: context.DeadlineExceeded,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			proxy := newSOCKS5TestProxyWithBehavior(t, "", 0, true)
			outbound, err := newOutboundTransport(proxy.address())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := test.context()
			defer cancel()
			started := time.Now()
			_, err = outbound.relayDialer.DialContext(ctx, "tcp", "timeout-example.onion:443")
			if !errors.Is(err, test.wantedError) {
				t.Fatalf("dial error = %v, want %v", err, test.wantedError)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("canceled SOCKS dial took %s", elapsed)
			}
		})
	}
}

func TestDirectModeDialsWithoutSOCKS5(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[]`)
	}))
	defer server.Close()
	outbound, err := newOutboundTransport("")
	if err != nil {
		t.Fatal(err)
	}
	defer outbound.httpClient.CloseIdleConnections()
	if _, err := fetchConfigWithClient(context.Background(), outbound.httpClient, server.URL, "token"); err != nil {
		t.Fatal(err)
	}
	address := strings.TrimPrefix(server.URL, "http://")
	conn, err := outbound.relayDialer.DialContext(context.Background(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func TestSOCKS5AddressValidation(t *testing.T) {
	for _, address := range []string{"localhost", ":9050", "localhost:0", "socks5://localhost:9050"} {
		if _, err := newOutboundTransport(address); err == nil {
			t.Errorf("newOutboundTransport(%q) succeeded", address)
		}
	}
}

func TestSOCKS5RejectsWireGuardModeInsteadOfDialingDirectly(t *testing.T) {
	if err := validateOutboundMode(true, "127.0.0.1:9050"); err == nil {
		t.Fatal("WireGuard mode accepted a SOCKS5 proxy that cannot carry its UDP data plane")
	}
	if err := validateOutboundMode(false, "127.0.0.1:9050"); err != nil {
		t.Fatalf("framed SOCKS5 mode rejected: %v", err)
	}
	if err := validateOutboundMode(true, ""); err != nil {
		t.Fatalf("direct WireGuard mode rejected: %v", err)
	}
}
