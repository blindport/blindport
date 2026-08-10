package main

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"time"

	"github.com/blindport/blindport/internal/relayauth"
)

const (
	minHeartbeatInterval = 5 * time.Second
	maxHeartbeatInterval = 5 * time.Minute
)

type heartbeatTicker interface {
	Chan() <-chan time.Time
	Stop()
}

type timeHeartbeatTicker struct {
	ticker *time.Ticker
}

func (t timeHeartbeatTicker) Chan() <-chan time.Time { return t.ticker.C }
func (t timeHeartbeatTicker) Stop()                  { t.ticker.Stop() }

type heartbeatReporter struct {
	log      *slog.Logger
	interval time.Duration
	snapshot func(time.Time) relayauth.Heartbeat
	report   func(context.Context, relayauth.Heartbeat) error
	ticker   func(time.Duration) heartbeatTicker
}

func newHeartbeatReporter(logger *slog.Logger, metrics *relayMetrics, edgeID string, interval time.Duration, subscriptions func() ([]string, bool), report func(context.Context, relayauth.Heartbeat) error) *heartbeatReporter {
	return &heartbeatReporter{
		log: logger, interval: interval,
		snapshot: func(now time.Time) relayauth.Heartbeat {
			heartbeat := metrics.heartbeatSnapshot(edgeID, now)
			heartbeat.ActiveSubscriptionIDs, heartbeat.ActiveSubscriptionIDsTruncated = subscriptions()
			return heartbeat
		},
		report: report,
		ticker: func(interval time.Duration) heartbeatTicker {
			return timeHeartbeatTicker{ticker: time.NewTicker(interval)}
		},
	}
}

func (r *relay) activeSubscriptionIDs() ([]string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	unique := make(map[string]struct{}, len(r.tunnelSubscriptions))
	for _, subscriptionID := range r.tunnelSubscriptions {
		if canonicalSubscriptionID(subscriptionID) {
			unique[subscriptionID] = struct{}{}
		}
	}
	ids := make([]string, 0, len(unique))
	for subscriptionID := range unique {
		ids = append(ids, subscriptionID)
	}
	sort.Strings(ids)
	truncated := len(ids) > relayauth.MaxHeartbeatActiveSubscriptions
	if truncated {
		ids = ids[:relayauth.MaxHeartbeatActiveSubscriptions]
	}
	return ids, truncated
}

func (r *heartbeatReporter) run(ctx context.Context) {
	r.send(ctx)
	ticker := r.ticker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.Chan():
			r.send(ctx)
		}
	}
}

func (r *heartbeatReporter) send(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if err := r.report(ctx, r.snapshot(time.Now())); err != nil && ctx.Err() == nil {
		r.log.Warn("relay heartbeat report failed")
	}
}

func validateHeartbeatConfig(edgeID, token string, interval time.Duration) (bool, error) {
	if edgeID == "" && token == "" {
		return false, nil
	}
	if edgeID == "" || token == "" {
		return false, fmt.Errorf("relay edge ID and heartbeat token must be configured together")
	}
	if _, err := validateOfflineEdgeID(edgeID); err != nil {
		return false, err
	}
	if !isLowerHexToken(token) {
		return false, fmt.Errorf("heartbeat token must be exactly 64 lowercase hexadecimal characters")
	}
	if interval < minHeartbeatInterval || interval > maxHeartbeatInterval {
		return false, fmt.Errorf("heartbeat interval must be within 5 seconds and 5 minutes")
	}
	return true, nil
}

func isLowerHexToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	for index := range token {
		character := token[index]
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func (m *relayMetrics) heartbeatSnapshot(edgeID string, now time.Time) relayauth.Heartbeat {
	components := m.health.components(now)
	heartbeat := relayauth.Heartbeat{
		EdgeID: edgeID,
		Ready:  m.health.ready(now),
		Components: relayauth.HealthComponents{
			Authorization: components["authorization"], Certificate: components["certificate"], Lifecycle: components["lifecycle"],
			Listeners: components["listeners"], WireGuard: components["wireguard"],
		},
	}
	for kind := range m.tunnels {
		heartbeat.ActiveTunnels = saturatingAddNonnegative(heartbeat.ActiveTunnels, m.tunnels[kind].active.Load())
		heartbeat.ActiveStreams = saturatingAddNonnegative(heartbeat.ActiveStreams, m.streams[kind].active.Load())
		for direction := range m.bytes[kind] {
			heartbeat.ForwardedBytesTotal = saturatingAddUint64(heartbeat.ForwardedBytesTotal, m.bytes[kind][direction].Load())
		}
	}
	for kind := range m.connections {
		heartbeat.AcceptedConnectionsTotal = saturatingAddUint64(heartbeat.AcceptedConnectionsTotal, m.connections[kind].accepted.Load())
	}
	return heartbeat
}

func saturatingAddNonnegative(total, value int64) int64 {
	if value <= 0 {
		return total
	}
	if value > math.MaxInt64-total {
		return math.MaxInt64
	}
	return total + value
}

func saturatingAddUint64(total int64, value uint64) int64 {
	if value > uint64(math.MaxInt64-total) {
		return math.MaxInt64
	}
	return total + int64(value)
}
