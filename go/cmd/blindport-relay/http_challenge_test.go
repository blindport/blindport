package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/protocol"
	"github.com/blindport/blindport/internal/relayauth"
	"github.com/blindport/blindport/internal/tunnel"
)

func TestValidateChallengeRequestSecurity(t *testing.T) {
	validPath := challengePathPrefix + "Abc_123-token"
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "origin form", raw: "GET " + validPath + " HTTP/1.1\r\nHost: Example.COM\r\n\r\n", want: "example.com"},
		{name: "host port", raw: "GET " + validPath + " HTTP/1.1\r\nHost: example.com:80\r\n\r\n", want: "example.com"},
		{name: "matching absolute form", raw: "GET http://example.com" + validPath + " HTTP/1.1\r\nHost: example.com\r\n\r\n", want: "example.com"},
		{name: "post", raw: "POST " + validPath + " HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"},
		{name: "HTTP 1.0", raw: "GET " + validPath + " HTTP/1.0\r\nHost: example.com\r\n\r\n"},
		{name: "missing host", raw: "GET " + validPath + " HTTP/1.1\r\n\r\n"},
		{name: "duplicate host", raw: "GET " + validPath + " HTTP/1.1\r\nHost: example.com\r\nHost: other.example\r\n\r\n"},
		{name: "IP host", raw: "GET " + validPath + " HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n"},
		{name: "noncanonical port", raw: "GET " + validPath + " HTTP/1.1\r\nHost: example.com:080\r\n\r\n"},
		{name: "wrong port", raw: "GET " + validPath + " HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"},
		{name: "absolute host mismatch", raw: "GET http://other.example" + validPath + " HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{name: "absolute scheme mismatch", raw: "GET https://example.com" + validPath + " HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{name: "body", raw: "GET " + validPath + " HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\n\r\nx"},
		{name: "chunked", raw: "GET " + validPath + " HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"},
		{name: "expect", raw: "GET " + validPath + " HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\n\r\n"},
		{name: "other path", raw: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{name: "empty token", raw: "GET " + challengePathPrefix + " HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{name: "extra segment", raw: "GET " + validPath + "/more HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{name: "escaped token", raw: "GET " + challengePathPrefix + "abc%2Ddef HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{name: "query", raw: "GET " + validPath + "?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{name: "pipelined", raw: "GET " + validPath + " HTTP/1.1\r\nHost: example.com\r\n\r\nGET / HTTP/1.1\r\n\r\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := readChallengeRequest(strings.NewReader(test.raw))
			if err == nil {
				var host string
				host, err = validateChallengeRequest(req)
				_ = req.Body.Close()
				if err == nil && host != test.want {
					t.Fatalf("host = %q, want %q", host, test.want)
				}
			}
			if test.want == "" && err == nil {
				t.Fatal("request accepted, want rejection")
			}
			if test.want != "" && err != nil {
				t.Fatalf("valid request rejected: %v", err)
			}
		})
	}
}

func TestReadChallengeRequestBoundsHeaders(t *testing.T) {
	raw := "GET " + challengePathPrefix + "token HTTP/1.1\r\nHost: example.com\r\nX-Fill: " + strings.Repeat("x", challengeHeaderLimit) + "\r\n\r\n"
	if _, err := readChallengeRequest(strings.NewReader(raw)); err == nil {
		t.Fatal("oversized request headers accepted")
	}
}

func TestReadChallengeResponseBoundsAndRejectsUpgrade(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	oversized := "HTTP/1.1 200 OK\r\nContent-Length: " + strings.Repeat("0", challengeHeaderLimit) + "\r\n\r\n"
	if _, err := readChallengeResponse(strings.NewReader(oversized), req); err == nil {
		t.Fatal("oversized response headers accepted")
	}
	body := bytes.Repeat([]byte("x"), challengeResponseBodyLimit+1)
	response := append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n"), body...)
	if _, err := readChallengeResponse(bytes.NewReader(response), req); err == nil {
		t.Fatal("oversized response body accepted")
	}
	if _, err := readChallengeResponse(strings.NewReader("HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: test\r\n\r\n"), req); err == nil {
		t.Fatal("protocol upgrade accepted")
	}
}

func TestHTTPChallengeListenerRoutesOnlyPort80AndCloses(t *testing.T) {
	limits, err := newAdmissionLimits(limitConfig{
		controlHandshakes: 2, totalIngress: 4, sniPeeks: 1, challenges: 2,
		controlPerSource: 1, ingressPerSource: 4, challengeRate: 600, challengeBurst: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	health := newRelayHealth(false, time.Minute, time.Minute)
	r := &relay{
		log: slog.Default(), limits: limits, metrics: &relayMetrics{health: health},
		tunnels: make(map[string]*tunnel.Conn), tunnelSubscriptions: make(map[*tunnel.Conn]string),
		allTunnels: make(map[*tunnel.Conn]struct{}), bandwidth: testBandwidthReporter(),
	}
	relayRaw, agentRaw := net.Pipe()
	relayTunnel := tunnel.New(relayRaw, nil)
	destination := make(chan string, 1)
	forwardedRequest := make(chan *http.Request, 1)
	agentTunnel := tunnel.New(agentRaw, func(stream *tunnel.Stream) {
		destination <- stream.Destination
		request, err := http.ReadRequest(bufio.NewReader(stream))
		if err != nil {
			_ = stream.Close()
			return
		}
		forwardedRequest <- request
		_ = request.Body.Close()
		_, _ = io.WriteString(stream, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nproof")
		_ = stream.Close()
	})
	go func() { _ = relayTunnel.Run() }()
	go func() { _ = agentTunnel.Run() }()
	r.registerTunnel("domain:example.com", protocol.ClaimRelay, relayTunnel, testSubscriptionOne)
	defer r.unregisterTunnel("domain:example.com", protocol.ClaimRelay, relayTunnel)
	defer agentTunnel.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.serveHTTPChallenges(ctx, listener)
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(client, "GET "+challengePathPrefix+"token HTTP/1.1\r\nHost: Example.COM\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	_ = client.Close()
	if response.StatusCode != http.StatusOK || string(responseBody) != "proof" {
		t.Fatalf("response = %d %q", response.StatusCode, responseBody)
	}
	select {
	case got := <-destination:
		if got != "domain:example.com:80" {
			t.Fatalf("destination = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("challenge stream was not opened")
	}
	select {
	case request := <-forwardedRequest:
		if request.Method != http.MethodGet || request.URL.Path != challengePathPrefix+"token" || request.Host != "Example.COM" {
			t.Fatalf("forwarded request = %s %s Host %q", request.Method, request.URL.Path, request.Host)
		}
	case <-time.After(time.Second):
		t.Fatal("challenge request was not replayed")
	}
	cancel()
	_ = listener.Close()
	<-done
	if !r.handlers.stopAndWait(time.Second) {
		t.Fatal("challenge handler did not drain")
	}
	if r.metrics.challenge[challengeSuccess].Load() != 1 || r.metrics.streams[claimKindIndex(protocol.ClaimRelay)].total.Load() != 1 {
		t.Fatal("successful challenge metrics were not recorded")
	}
	reports := r.bandwidth.acc.snapshot()
	if len(reports) != 1 || reports[0].SubscriptionID != testSubscriptionOne || reports[0].Day != "2026-08-09" || reports[0].IngressBytes <= 0 || reports[0].EgressBytes <= 0 {
		t.Fatalf("HTTP-01 bandwidth = %+v", reports)
	}
}

func TestBandwidthCountingWriterCountsSuccessfulPartialWrite(t *testing.T) {
	wantErr := errors.New("partial write")
	reporter := testBandwidthReporter()
	writer := bandwidthCountingWriter{
		Writer: partialHTTPWriter{err: wantErr}, subscriptionID: testSubscriptionOne,
		direction: bandwidthIngress, reporter: reporter,
	}
	n, err := writer.Write([]byte("proof"))
	if n != 2 || !errors.Is(err, wantErr) {
		t.Fatalf("write = %d/%v", n, err)
	}
	want := []relayauth.DailyBandwidthReport{{SubscriptionID: testSubscriptionOne, Day: "2026-08-09", IngressBytes: 2}}
	if got := reporter.acc.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("bandwidth = %+v", got)
	}
}

type partialHTTPWriter struct{ err error }

func (w partialHTTPWriter) Write([]byte) (int, error) { return 2, w.err }

func TestHTTPChallengeNoTunnelDoesNotOpenGeneralProxy(t *testing.T) {
	r := newChallengeTestRelay(t, 10, 2)
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		r.handleHTTPChallengeConn(&challengeAddrConn{Conn: server})
		close(done)
	}()
	_, _ = io.WriteString(client, "GET "+challengePathPrefix+"token HTTP/1.1\r\nHost: absent.example\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	_ = client.Close()
	<-done
	if response.StatusCode != http.StatusNotFound || r.metrics.challenge[challengeNoTunnel].Load() != 1 {
		t.Fatalf("response/metric = %d/%d", response.StatusCode, r.metrics.challenge[challengeNoTunnel].Load())
	}
}

func TestHTTPChallengeDoesNotRouteWildcardClaims(t *testing.T) {
	r := newChallengeTestRelay(t, 10, 2)
	wildcardRaw, wildcardPeer := net.Pipe()
	defer wildcardPeer.Close()
	wildcard := tunnel.New(wildcardRaw, nil)
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "public.example", Scope: protocol.RelayHostnameScopeWildcard}
	r.registerTunnel(claimKey(claim), claim.Kind, wildcard)
	defer r.unregisterTunnel(claimKey(claim), claim.Kind, wildcard)

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		r.handleHTTPChallengeConn(&challengeAddrConn{Conn: server})
		close(done)
	}()
	_, _ = io.WriteString(client, "GET "+challengePathPrefix+"token HTTP/1.1\r\nHost: a.public.example\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	_ = client.Close()
	<-done
	if response.StatusCode != http.StatusNotFound || r.metrics.challenge[challengeNoTunnel].Load() != 1 {
		t.Fatalf("response/metric = %d/%d", response.StatusCode, r.metrics.challenge[challengeNoTunnel].Load())
	}
}

func TestHTTPIngressRedirectsWithoutTunnel(t *testing.T) {
	r := newChallengeTestRelay(t, 10, 2)

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		r.handleHTTPChallengeConn(&challengeAddrConn{Conn: server})
		close(done)
	}()
	_, _ = io.WriteString(client, "GET /some%20path?q=a%2Fb&x=1 HTTP/1.1\r\nHost: Example.COM:80\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	_ = client.Close()
	<-done

	if response.StatusCode != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusPermanentRedirect)
	}
	if got := response.Header.Get("Location"); got != "https://example.com/some%20path?q=a%2Fb&x=1" {
		t.Fatalf("Location = %q", got)
	}
	if len(body) != 0 || response.ContentLength != 0 {
		t.Fatalf("body/content length = %q/%d", body, response.ContentLength)
	}
	if r.metrics.challenge[challengeRedirected].Load() != 1 || r.metrics.streams[claimKindIndex(protocol.ClaimRelay)].total.Load() != 0 {
		t.Fatal("redirect metrics or stream count are incorrect")
	}
}

func TestHTTPIngressRedirectSecurity(t *testing.T) {
	tests := []struct {
		name         string
		request      string
		wantStatus   int
		wantLocation string
	}{
		{
			name:         "query cannot select another host",
			request:      "GET /login?next=https://evil.example/path HTTP/1.1\r\nHost: Example.COM:80\r\n\r\n",
			wantStatus:   http.StatusPermanentRedirect,
			wantLocation: "https://example.com/login?next=https://evil.example/path",
		},
		{
			name:         "network path remains on canonical host",
			request:      "GET //evil.example/path HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantStatus:   http.StatusPermanentRedirect,
			wantLocation: "https://example.com//evil.example/path",
		},
		{
			name:         "encoded header delimiters remain encoded",
			request:      "GET /path?value=%0d%0aX-Injected:%20yes HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantStatus:   http.StatusPermanentRedirect,
			wantLocation: "https://example.com/path?value=%0d%0aX-Injected:%20yes",
		},
		{
			name:       "absolute target cannot select another host",
			request:    "GET http://evil.example/path HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "absolute target cannot contain user info",
			request:    "GET http://user@example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := newChallengeTestRelay(t, 10, 2)
			client, server := net.Pipe()
			done := make(chan struct{})
			go func() {
				r.handleHTTPChallengeConn(&challengeAddrConn{Conn: server})
				close(done)
			}()
			_, _ = io.WriteString(client, test.request)
			response, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			_ = client.Close()
			<-done

			if response.StatusCode != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.wantStatus)
			}
			if got := response.Header.Get("Location"); got != test.wantLocation {
				t.Fatalf("Location = %q, want %q", got, test.wantLocation)
			}
			if got := response.Header.Get("X-Injected"); got != "" {
				t.Fatalf("injected response header = %q", got)
			}
		})
	}
}

func TestHTTPChallengeListenerFailureRemovesReadiness(t *testing.T) {
	r := newChallengeTestRelay(t, 10, 2)
	ctx, cancel := context.WithCancel(context.Background())
	r.shutdown = cancel
	r.metrics.health.listenersUp.Store(true)
	r.metrics.health.observeAuth(nil)
	if !r.metrics.health.ready(time.Now()) {
		t.Fatal("test relay did not start ready")
	}
	r.serveHTTPChallenges(ctx, failingListener{})
	if r.metrics.health.ready(time.Now()) {
		t.Fatal("failed challenge listener remained ready")
	}
	if ctx.Err() == nil {
		t.Fatal("failed challenge listener did not trigger relay shutdown")
	}
}

func TestHTTPChallengeSlowReadHasDeadline(t *testing.T) {
	r := newChallengeTestRelay(t, 10, 2)
	conn := &deadlineConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.11"), Port: 1234}}
	started := time.Now()
	r.handleHTTPChallengeConn(conn)
	if conn.readDeadline.Before(started.Add(challengeReadTimeout-time.Second)) || conn.readDeadline.After(started.Add(challengeReadTimeout+time.Second)) {
		t.Fatalf("read deadline = %s, want about %s", conn.readDeadline.Sub(started), challengeReadTimeout)
	}
	if r.metrics.challenge[challengeInvalid].Load() != 1 || !strings.Contains(conn.written.String(), "400 Bad Request") {
		t.Fatalf("slow read metric/response = %d/%q", r.metrics.challenge[challengeInvalid].Load(), conn.written.String())
	}
}

type deadlineConn struct {
	remote       net.Addr
	readDeadline time.Time
	written      bytes.Buffer
}

func (c *deadlineConn) Read([]byte) (int, error)         { return 0, timeoutError{} }
func (c *deadlineConn) Write(p []byte) (int, error)      { return c.written.Write(p) }
func (c *deadlineConn) Close() error                     { return nil }
func (c *deadlineConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *deadlineConn) RemoteAddr() net.Addr             { return c.remote }
func (c *deadlineConn) SetDeadline(time.Time) error      { return nil }
func (c *deadlineConn) SetWriteDeadline(time.Time) error { return nil }
func (c *deadlineConn) SetReadDeadline(deadline time.Time) error {
	c.readDeadline = deadline
	return nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "read timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type failingListener struct{}

func (failingListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (failingListener) Close() error              { return nil }
func (failingListener) Addr() net.Addr            { return &net.TCPAddr{} }

type challengeAddrConn struct{ net.Conn }

func (c *challengeAddrConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
}

func newChallengeTestRelay(t *testing.T, rate, burst int) *relay {
	t.Helper()
	limits, err := newAdmissionLimits(limitConfig{
		controlHandshakes: 1, totalIngress: 2, sniPeeks: 1, challenges: 1,
		controlPerSource: 1, ingressPerSource: 2, challengeRate: rate, challengeBurst: burst,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &relay{
		log: slog.Default(), limits: limits,
		metrics: &relayMetrics{health: newRelayHealth(false, time.Minute, time.Minute)},
		tunnels: make(map[string]*tunnel.Conn), allTunnels: make(map[*tunnel.Conn]struct{}),
	}
}
