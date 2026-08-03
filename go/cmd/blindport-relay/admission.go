package main

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

type limitConfig struct {
	controlHandshakes int
	totalIngress      int
	sniPeeks          int
	challenges        int
	controlPerSource  int
	ingressPerSource  int
	challengeRate     int
	challengeBurst    int
}

func (c limitConfig) validate() error {
	if c.controlHandshakes <= 0 || c.totalIngress <= 0 || c.sniPeeks <= 0 || c.challenges <= 0 || c.controlPerSource <= 0 || c.ingressPerSource <= 0 || c.challengeRate <= 0 || c.challengeBurst <= 0 {
		return fmt.Errorf("all concurrency limits must be positive")
	}
	if c.controlPerSource > c.controlHandshakes {
		return fmt.Errorf("per-source control limit cannot exceed control handshake limit")
	}
	if c.ingressPerSource > c.totalIngress {
		return fmt.Errorf("per-source ingress limit cannot exceed total ingress limit")
	}
	if c.sniPeeks > c.totalIngress {
		return fmt.Errorf("SNI peek limit cannot exceed total ingress limit")
	}
	if c.challenges > c.totalIngress {
		return fmt.Errorf("HTTP challenge limit cannot exceed total ingress limit")
	}
	return nil
}

type admissionLimits struct {
	controlSources *sourceLimiter
	ingressSources *sourceLimiter
	handshakes     chan struct{}
	sniPeeks       chan struct{}
	challenges     chan struct{}
	challengeRate  *sourceTokenBuckets
}

func newAdmissionLimits(cfg limitConfig) (*admissionLimits, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &admissionLimits{
		controlSources: newSourceLimiter(cfg.controlHandshakes, cfg.controlPerSource),
		ingressSources: newSourceLimiter(cfg.totalIngress, cfg.ingressPerSource),
		handshakes:     make(chan struct{}, cfg.controlHandshakes),
		sniPeeks:       make(chan struct{}, cfg.sniPeeks),
		challenges:     make(chan struct{}, cfg.challenges),
		challengeRate:  newSourceTokenBuckets(cfg.challengeRate, cfg.challengeBurst, cfg.totalIngress),
	}, nil
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

type sourceTokenBuckets struct {
	mu         sync.Mutex
	rate       float64
	burst      float64
	maxSources int
	sources    map[netip.Addr]tokenBucket
}

func newSourceTokenBuckets(perMinute, burst, maxSources int) *sourceTokenBuckets {
	return &sourceTokenBuckets{
		rate: float64(perMinute) / float64(time.Minute), burst: float64(burst),
		maxSources: maxSources, sources: make(map[netip.Addr]tokenBucket),
	}
}

func (l *sourceTokenBuckets) allow(addr net.Addr, now time.Time) bool {
	source, ok := directPeer(addr)
	if !ok {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	bucket, exists := l.sources[source]
	if !exists {
		if len(l.sources) >= l.maxSources {
			fullRefill := time.Duration(l.burst/l.rate) + 1
			for tracked, stale := range l.sources {
				if now.Sub(stale.last) >= fullRefill {
					delete(l.sources, tracked)
				}
			}
			if len(l.sources) >= l.maxSources {
				return false
			}
		}
		bucket = tokenBucket{tokens: l.burst, last: now}
	}
	if elapsed := now.Sub(bucket.last); elapsed > 0 {
		bucket.tokens = min(l.burst, bucket.tokens+float64(elapsed)*l.rate)
		bucket.last = now
	}
	if bucket.tokens < 1 {
		l.sources[source] = bucket
		return false
	}
	bucket.tokens--
	l.sources[source] = bucket
	return true
}

type sourceLimiter struct {
	mu        sync.Mutex
	total     int
	maxTotal  int
	perSource int
	sources   map[netip.Addr]int
}

func newSourceLimiter(maxTotal, perSource int) *sourceLimiter {
	return &sourceLimiter{maxTotal: maxTotal, perSource: perSource, sources: make(map[netip.Addr]int)}
}

func (l *sourceLimiter) acquire(addr net.Addr) (func(), bool) {
	source, ok := directPeer(addr)
	if !ok {
		return nil, false
	}
	l.mu.Lock()
	if l.total >= l.maxTotal || l.sources[source] >= l.perSource {
		l.mu.Unlock()
		return nil, false
	}
	l.total++
	l.sources[source]++
	l.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			l.total--
			l.sources[source]--
			if l.sources[source] == 0 {
				delete(l.sources, source)
			}
			l.mu.Unlock()
		})
	}, true
}

func directPeer(addr net.Addr) (netip.Addr, bool) {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		parsed, ok := netip.AddrFromSlice(tcp.IP)
		return parsed.Unmap(), ok
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		parsed, ok := netip.AddrFromSlice(udp.IP)
		return parsed.Unmap(), ok
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return netip.Addr{}, false
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return parsed.Unmap(), true
}

func tryAcquire(semaphore chan struct{}) (func(), bool) {
	select {
	case semaphore <- struct{}{}:
		return func() { <-semaphore }, true
	default:
		return nil, false
	}
}

type handlerTracker struct {
	mu      sync.Mutex
	closing bool
	wg      sync.WaitGroup
}

func (t *handlerTracker) start(fn func()) bool {
	t.mu.Lock()
	if t.closing {
		t.mu.Unlock()
		return false
	}
	t.wg.Add(1)
	t.mu.Unlock()
	go func() {
		defer t.wg.Done()
		fn()
	}()
	return true
}

func (t *handlerTracker) stopAndWait(timeout time.Duration) bool {
	t.mu.Lock()
	t.closing = true
	t.mu.Unlock()
	done := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}
