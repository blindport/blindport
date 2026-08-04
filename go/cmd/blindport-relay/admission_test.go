package main

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestSourceLimiterBoundsTotalAndPerSourceAndReleases(t *testing.T) {
	limiter := newSourceLimiter(2, 1)
	firstAddr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1000}
	secondAddr := &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1001}
	releaseFirst, ok := limiter.acquire(firstAddr)
	if !ok {
		t.Fatal("first acquire rejected")
	}
	if _, ok := limiter.acquire(firstAddr); ok {
		t.Fatal("per-source overflow accepted")
	}
	releaseSecond, ok := limiter.acquire(secondAddr)
	if !ok {
		t.Fatal("second source rejected")
	}
	if _, ok := limiter.acquire(&net.TCPAddr{IP: net.ParseIP("192.0.2.3")}); ok {
		t.Fatal("global overflow accepted")
	}
	releaseFirst()
	releaseFirst()
	releaseSecond()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.total != 0 || len(limiter.sources) != 0 {
		t.Fatalf("limiter retained state: total=%d sources=%v", limiter.total, limiter.sources)
	}
}

func TestDirectPeerUnmapsIPv4MappedIPv6(t *testing.T) {
	got, ok := directPeer(&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.9")})
	if !ok || got != netip.MustParseAddr("192.0.2.9") {
		t.Fatalf("directPeer() = %v, %t", got, ok)
	}
}

func TestHandlerTrackerRejectsStartsAfterDrain(t *testing.T) {
	var ran atomic.Bool
	tracker := &handlerTracker{}
	if !tracker.start(func() { ran.Store(true) }) {
		t.Fatal("initial handler rejected")
	}
	if !tracker.stopAndWait(time.Second) || !ran.Load() {
		t.Fatal("handler did not drain")
	}
	if tracker.start(func() {}) {
		t.Fatal("handler started after drain")
	}
}

func TestLimitConfigValidation(t *testing.T) {
	valid := limitConfig{
		controlHandshakes: 10, totalIngress: 20, sniPeeks: 5, challenges: 5,
		controlPerSource: 2, ingressPerSource: 4, challengeRate: 60, challengeBurst: 10,
	}
	if _, err := newAdmissionLimits(valid); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []limitConfig{
		{},
		{controlHandshakes: 10, totalIngress: 20, sniPeeks: 21, challenges: 5, controlPerSource: 2, ingressPerSource: 4, challengeRate: 60, challengeBurst: 10},
		{controlHandshakes: 10, totalIngress: 20, sniPeeks: 5, challenges: 21, controlPerSource: 2, ingressPerSource: 4, challengeRate: 60, challengeBurst: 10},
		{controlHandshakes: 10, totalIngress: 20, sniPeeks: 5, challenges: 5, controlPerSource: 11, ingressPerSource: 4, challengeRate: 60, challengeBurst: 10},
		{controlHandshakes: 10, totalIngress: 20, sniPeeks: 5, challenges: 5, controlPerSource: 2, ingressPerSource: 21, challengeRate: 60, challengeBurst: 10},
	} {
		if _, err := newAdmissionLimits(cfg); err == nil {
			t.Fatalf("newAdmissionLimits(%+v) succeeded", cfg)
		}
	}
}

func TestSourceTokenBucketsAllowBurstRefillAndIndependentVantages(t *testing.T) {
	limiter := newSourceTokenBuckets(60, 2, 2)
	now := time.Unix(100, 0)
	first := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}
	second := &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 2}
	if !limiter.allow(first, now) || !limiter.allow(first, now) || limiter.allow(first, now) {
		t.Fatal("per-source burst was not enforced")
	}
	if !limiter.allow(second, now) {
		t.Fatal("independent validation vantage shared another source's allowance")
	}
	if !limiter.allow(first, now.Add(time.Second)) {
		t.Fatal("token bucket did not refill")
	}
}
