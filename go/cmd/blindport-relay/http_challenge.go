package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
	"time"

	"github.com/blindport/blindport/internal/protocol"
)

const (
	challengeHeaderLimit       = 16 << 10
	challengeResponseBodyLimit = 64 << 10
	challengeReadTimeout       = 5 * time.Second
	challengeResponseTimeout   = 10 * time.Second
	challengeWriteTimeout      = 5 * time.Second
	challengePathPrefix        = "/.well-known/acme-challenge/"
)

const (
	challengeSuccess = iota
	challengeRedirected
	challengeInvalid
	challengeRateLimited
	challengeNoTunnel
	challengeUpstreamError
	challengeOutcomeCount
)

var (
	errHeaderTooLarge = errors.New("HTTP header exceeds limit")
	challengeToken    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)
)

func (r *relay) serveHTTPChallenges(ctx context.Context, ln net.Listener) {
	r.log.Info("HTTP redirect and HTTP-01 ingress listener ready")
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			r.listenerFailed("http_challenge", err)
			return
		}
		r.startIngressHandler(listenerChallenge, conn, func() { r.handleHTTPChallengeConn(conn) })
	}
}

func (r *relay) handleHTTPChallengeConn(conn net.Conn) {
	defer conn.Close()
	index := int(listenerChallenge)
	release, ok := tryAcquire(r.limits.challenges)
	if !ok {
		r.metrics.connections[index].rejected.Add(1)
		r.metrics.challenge[challengeRateLimited].Add(1)
		writeChallengeError(conn, http.StatusServiceUnavailable)
		return
	}
	defer release()
	_ = conn.SetReadDeadline(time.Now().Add(challengeReadTimeout))
	req, err := readChallengeRequest(conn)
	if err != nil {
		r.metrics.challenge[challengeInvalid].Add(1)
		writeChallengeError(conn, http.StatusBadRequest)
		return
	}
	host, isChallenge, err := validateHTTPIngressRequest(req)
	if err != nil {
		r.metrics.challenge[challengeInvalid].Add(1)
		writeChallengeError(conn, challengeStatus(err))
		return
	}
	if !r.limits.challengeRate.allow(conn.RemoteAddr(), time.Now()) {
		r.metrics.connections[index].rejected.Add(1)
		r.metrics.challenge[challengeRateLimited].Add(1)
		writeChallengeError(conn, http.StatusTooManyRequests)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	if !isChallenge {
		r.metrics.challenge[challengeRedirected].Add(1)
		writeHTTPSRedirect(conn, host, req)
		return
	}
	t, subscriptionID := r.getTunnelSubscription("domain:" + host)
	if t == nil {
		r.metrics.challenge[challengeNoTunnel].Add(1)
		writeChallengeError(conn, http.StatusNotFound)
		return
	}
	stream, err := t.OpenStream("tcp", conn.RemoteAddr().String(), "domain:"+host+":80")
	if err != nil {
		r.metrics.challenge[challengeUpstreamError].Add(1)
		writeChallengeError(conn, http.StatusBadGateway)
		return
	}
	defer stream.Close()
	streamIndex := claimKindIndex(protocol.ClaimRelay)
	r.metrics.streams[streamIndex].active.Add(1)
	r.metrics.streams[streamIndex].total.Add(1)
	defer r.metrics.streams[streamIndex].active.Add(-1)

	req.Close = true
	req.Body = http.NoBody
	req.ContentLength = 0
	req.TransferEncoding = nil
	req.RequestURI = ""
	req.URL.Scheme = ""
	req.URL.Host = ""
	if err := req.Write(bandwidthCountingWriter{Writer: stream, subscriptionID: subscriptionID, direction: bandwidthIngress, reporter: r.bandwidth}); err != nil {
		r.metrics.challenge[challengeUpstreamError].Add(1)
		writeChallengeError(conn, http.StatusBadGateway)
		return
	}
	timer := time.AfterFunc(challengeResponseTimeout, func() { _ = stream.Close() })
	resp, err := readChallengeResponse(stream, req)
	if !timer.Stop() || err != nil {
		r.metrics.challenge[challengeUpstreamError].Add(1)
		writeChallengeError(conn, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(challengeWriteTimeout))
	if err := resp.Write(bandwidthCountingWriter{Writer: conn, subscriptionID: subscriptionID, direction: bandwidthEgress, reporter: r.bandwidth}); err != nil {
		r.metrics.challenge[challengeUpstreamError].Add(1)
		return
	}
	r.metrics.challenge[challengeSuccess].Add(1)
}

type bandwidthCountingWriter struct {
	io.Writer
	subscriptionID string
	direction      bandwidthDirection
	reporter       *bandwidthReporter
}

func (w bandwidthCountingWriter) Write(payload []byte) (int, error) {
	n, err := w.Writer.Write(payload)
	if n > 0 && w.reporter != nil {
		w.reporter.add(w.subscriptionID, w.direction, n)
	}
	return n, err
}

func readChallengeRequest(reader io.Reader) (*http.Request, error) {
	limited := newHeaderLimitReader(reader, challengeHeaderLimit)
	buffered := bufio.NewReader(limited)
	req, err := http.ReadRequest(buffered)
	if err != nil {
		return nil, err
	}
	if buffered.Buffered() != 0 {
		_ = req.Body.Close()
		return nil, errors.New("request contains bytes after headers")
	}
	wireHost, err := readWireHost(limited.header.Bytes())
	if err != nil {
		_ = req.Body.Close()
		return nil, err
	}
	req.Host = wireHost
	return req, nil
}

func readWireHost(header []byte) (string, error) {
	end := bytes.Index(header, []byte("\r\n\r\n"))
	requestLineEnd := bytes.Index(header, []byte("\r\n"))
	if end < 0 || requestLineEnd < 0 || requestLineEnd >= end {
		return "", errors.New("malformed HTTP headers")
	}
	mimeReader := textproto.NewReader(bufio.NewReader(bytes.NewReader(header[requestLineEnd+2 : end+4])))
	headers, err := mimeReader.ReadMIMEHeader()
	if err != nil {
		return "", err
	}
	hosts := headers.Values("Host")
	if len(hosts) != 1 {
		return "", errors.New("exactly one Host header is required")
	}
	return hosts[0], nil
}

type challengeRequestError struct{ status int }

func (e challengeRequestError) Error() string { return http.StatusText(e.status) }

func validateChallengeRequest(req *http.Request) (string, error) {
	host, isChallenge, err := validateHTTPIngressRequest(req)
	if err != nil {
		return "", err
	}
	if !isChallenge {
		return "", challengeRequestError{status: http.StatusNotFound}
	}
	return host, nil
}

func validateHTTPIngressRequest(req *http.Request) (string, bool, error) {
	if req.Method != http.MethodGet {
		return "", false, challengeRequestError{status: http.StatusMethodNotAllowed}
	}
	if req.ProtoMajor != 1 || req.ProtoMinor != 1 {
		return "", false, errors.New("HTTP/1.1 required")
	}
	if req.ContentLength > 0 || len(req.TransferEncoding) != 0 || req.Header.Get("Expect") != "" || req.Header.Get("Upgrade") != "" {
		return "", false, errors.New("request body is not allowed")
	}
	host, err := canonicalChallengeHost(req.Host)
	if err != nil {
		return "", false, err
	}
	if req.URL.IsAbs() {
		absoluteHost, err := canonicalChallengeHost(req.URL.Host)
		if err != nil || req.URL.Scheme != "http" || req.URL.User != nil || absoluteHost != host {
			return "", false, errors.New("absolute request target does not match Host")
		}
	}
	if req.URL.Fragment != "" || req.URL.Path == "" || !strings.HasPrefix(req.URL.Path, "/") {
		return "", false, errors.New("invalid request target")
	}
	if !strings.HasPrefix(req.URL.Path, challengePathPrefix) {
		return host, false, nil
	}
	if req.URL.RawQuery != "" || req.URL.RawPath != "" {
		return "", false, challengeRequestError{status: http.StatusNotFound}
	}
	token := strings.TrimPrefix(req.URL.Path, challengePathPrefix)
	if !challengeToken.MatchString(token) {
		return "", false, challengeRequestError{status: http.StatusNotFound}
	}
	return host, true, nil
}

func canonicalChallengeHost(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", errors.New("Host is required")
	}
	host := value
	if strings.Contains(value, ":") {
		var port string
		var err error
		host, port, err = net.SplitHostPort(value)
		if err != nil || port != "80" {
			return "", errors.New("Host port must be 80")
		}
	}
	host = strings.ToLower(host)
	claim := &protocol.Claim{Kind: protocol.ClaimRelay, Domain: host}
	if protocol.ValidateClaim(claim) != nil {
		return "", errors.New("Host is not a valid domain")
	}
	return host, nil
}

func challengeStatus(err error) int {
	var requestErr challengeRequestError
	if errors.As(err, &requestErr) {
		return requestErr.status
	}
	return http.StatusBadRequest
}

func readChallengeResponse(reader io.Reader, req *http.Request) (*http.Response, error) {
	buffered := bufio.NewReader(newHeaderLimitReader(reader, challengeHeaderLimit))
	resp, err := http.ReadResponse(buffered, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode == http.StatusSwitchingProtocols {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("unsupported upstream status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, challengeResponseBodyLimit+1))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(body) > challengeResponseBodyLimit {
		return nil, errors.New("upstream response body exceeds limit")
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.TransferEncoding = nil
	resp.Trailer = nil
	resp.Close = true
	resp.Header.Del("Trailer")
	return resp, nil
}

func writeChallengeError(conn net.Conn, status int) {
	_ = conn.SetWriteDeadline(time.Now().Add(challengeWriteTimeout))
	message := http.StatusText(status) + "\n"
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(message), message)
}

func writeHTTPSRedirect(conn net.Conn, host string, req *http.Request) {
	_ = conn.SetWriteDeadline(time.Now().Add(challengeWriteTimeout))
	target := *req.URL
	target.Scheme = "https"
	target.Host = host
	target.User = nil
	_, _ = fmt.Fprintf(
		conn,
		"HTTP/1.1 %d %s\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		http.StatusPermanentRedirect,
		http.StatusText(http.StatusPermanentRedirect),
		target.String(),
	)
}

type headerLimitReader struct {
	reader    io.Reader
	remaining int
	done      bool
	tail      []byte
	header    bytes.Buffer
}

func newHeaderLimitReader(reader io.Reader, limit int) *headerLimitReader {
	return &headerLimitReader{reader: reader, remaining: limit}
}

func (r *headerLimitReader) Read(p []byte) (int, error) {
	if r.done {
		return r.reader.Read(p)
	}
	if r.remaining == 0 {
		return 0, errHeaderTooLarge
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= n
	_, _ = r.header.Write(p[:n])
	combined := append(append([]byte(nil), r.tail...), p[:n]...)
	if bytes.Contains(combined, []byte("\r\n\r\n")) {
		r.done = true
	} else if len(combined) > 3 {
		r.tail = append(r.tail[:0], combined[len(combined)-3:]...)
	} else {
		r.tail = append(r.tail[:0], combined...)
	}
	if n == 0 && err == nil && r.remaining == 0 {
		return 0, errHeaderTooLarge
	}
	return n, err
}
