package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/blindport/blindport/internal/protocol"
)

type dnsLookupResult struct {
	addresses []net.IP
	err       error
}

type scriptedHostnameResolver struct {
	mu      sync.Mutex
	results []dnsLookupResult
	calls   int
}

func (r *scriptedHostnameResolver) LookupNetIP(_ context.Context, _ string) ([]net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := r.results[min(r.calls, len(r.results)-1)]
	r.calls++
	return append([]net.IP(nil), result.addresses...), result.err
}

func (r *scriptedHostnameResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type stableRelayDialer struct {
	mu        sync.Mutex
	addresses []string
	dialed    chan struct{}
}

func (d *stableRelayDialer) DialContext(_ context.Context, _ string, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addresses = append(d.addresses, address)
	d.mu.Unlock()
	select {
	case d.dialed <- struct{}{}:
	default:
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, err := protocol.ReadFrame(server)
		if err != nil {
			return
		}
		if err := protocol.WriteFrame(server, &protocol.Frame{Type: protocol.TypeHelloOK, Version: protocol.CurrentVersion}); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, server)
	}()
	return client, nil
}

func (d *stableRelayDialer) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addresses...)
}

func TestWatchRelayDNSSignalsChangedAddressSet(t *testing.T) {
	resolver := &scriptedHostnameResolver{results: []dnsLookupResult{
		{addresses: []net.IP{net.ParseIP("192.0.2.10")}},
		{addresses: []net.IP{net.ParseIP("192.0.2.20")}},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changed := watchRelayDNS(ctx, "relay.example:5443", resolver, time.Millisecond)
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("DNS address set change was not reported")
	}
}

func TestWatchRelayDNSIgnoresUnchangedAndReorderedSets(t *testing.T) {
	resolver := &scriptedHostnameResolver{results: []dnsLookupResult{
		{addresses: []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")}},
		{addresses: []net.IP{net.ParseIP("2001:db8::10"), net.ParseIP("192.0.2.10")}},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changed := watchRelayDNS(ctx, "relay.example:5443", resolver, time.Millisecond)
	waitForDNSCalls(t, resolver, 3)
	select {
	case <-changed:
		t.Fatal("unchanged DNS address set restarted the worker")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestWatchRelayDNSRetainsLastSetAcrossLookupFailure(t *testing.T) {
	resolver := &scriptedHostnameResolver{results: []dnsLookupResult{
		{addresses: []net.IP{net.ParseIP("192.0.2.10")}},
		{err: errors.New("temporary DNS failure")},
		{addresses: []net.IP{net.ParseIP("192.0.2.10")}},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changed := watchRelayDNS(ctx, "relay.example:5443", resolver, time.Millisecond)
	waitForDNSCalls(t, resolver, 3)
	select {
	case <-changed:
		t.Fatal("temporary DNS lookup failure restarted the worker")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestWatchRelayDNSSignalsRecoveryAfterInitialLookupFailure(t *testing.T) {
	resolver := &scriptedHostnameResolver{results: []dnsLookupResult{
		{err: errors.New("initial DNS failure")},
		{addresses: []net.IP{net.ParseIP("192.0.2.20")}},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changed := watchRelayDNS(ctx, "relay.example:5443", resolver, time.Millisecond)
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("DNS recovery was not reported")
	}
}

func TestWatchRelayDNSSkipsIPLiteralEndpoints(t *testing.T) {
	resolver := &scriptedHostnameResolver{results: []dnsLookupResult{{addresses: []net.IP{net.ParseIP("192.0.2.10")}}}}
	for _, endpoint := range []string{"192.0.2.10:5443", "[2001:db8::10]:5443"} {
		if changed := watchRelayDNS(context.Background(), endpoint, resolver, time.Millisecond); changed != nil {
			t.Fatalf("IP literal endpoint %q enabled DNS monitoring", endpoint)
		}
	}
	if calls := resolver.callCount(); calls != 0 {
		t.Fatalf("IP literal endpoints made %d DNS lookups", calls)
	}
}

func TestWorkerDNSChangeRedialsHostnameEndpoint(t *testing.T) {
	endpoint := "relay.example:5443"
	resolver := &scriptedHostnameResolver{results: []dnsLookupResult{
		{addresses: []net.IP{net.ParseIP("192.0.2.10")}},
		{addresses: []net.IP{net.ParseIP("192.0.2.20")}},
	}}
	dialer := &stableRelayDialer{dialed: make(chan struct{}, 2)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runWorkerWithEntitlementAndDNS(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), workerPlan{
			SubscriptionID: testSubscriptionID1, RelayAddr: endpoint, Upstream: "app:80", Claim: &protocol.Claim{Kind: protocol.ClaimRelay, Domain: "site.example"},
		}, "token", dialer, nil, nil, nil, resolver, time.Millisecond)
		close(done)
	}()
	for range 2 {
		select {
		case <-dialer.dialed:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("worker did not redial after DNS address set change")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
	if addresses := dialer.snapshot(); len(addresses) != 2 || addresses[0] != endpoint || addresses[1] != endpoint {
		t.Fatalf("dial addresses = %q, want original hostname endpoint", addresses)
	}
	config, err := (&tlsMaterial{}).configForEndpoint(endpoint, "")
	if err != nil {
		t.Fatal(err)
	}
	if config.ServerName != "relay.example" {
		t.Fatalf("TLS ServerName = %q, want relay hostname", config.ServerName)
	}
}

func waitForDNSCalls(t *testing.T, resolver *scriptedHostnameResolver, calls int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for resolver.callCount() < calls {
		if time.Now().After(deadline) {
			t.Fatalf("DNS lookups = %d, want at least %d", resolver.callCount(), calls)
		}
		time.Sleep(time.Millisecond)
	}
}
