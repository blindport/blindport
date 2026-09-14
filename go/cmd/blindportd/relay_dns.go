package main

import (
	"context"
	"net"
	"time"
)

const relayDNSRefreshInterval = provisioningRefreshInterval

// hostnameResolver permits deterministic DNS monitoring without changing the
// hostname passed to the relay dialer.
type hostnameResolver interface {
	LookupNetIP(context.Context, string) ([]net.IP, error)
}

type systemHostnameResolver struct {
	resolver *net.Resolver
}

func (r systemHostnameResolver) LookupNetIP(ctx context.Context, host string) ([]net.IP, error) {
	addresses, err := r.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	resolved := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		resolved = append(resolved, net.IP(address.AsSlice()))
	}
	return resolved, nil
}

// watchRelayDNS reports one change to a hostname's resolved address set. DNS
// failures retain the latest known set so a healthy tunnel stays connected.
func watchRelayDNS(ctx context.Context, endpoint string, resolver hostnameResolver, interval time.Duration) <-chan struct{} {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil || net.ParseIP(host) != nil || resolver == nil {
		return nil
	}
	if interval <= 0 {
		interval = relayDNSRefreshInterval
	}
	changed := make(chan struct{}, 1)
	go func() {
		defer close(changed)
		known, ok := lookupRelayIPSet(ctx, resolver, host)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				resolved, resolvedOK := lookupRelayIPSet(ctx, resolver, host)
				if !resolvedOK {
					continue
				}
				if !ok {
					changed <- struct{}{}
					return
				}
				if sameRelayIPSet(known, resolved) {
					continue
				}
				changed <- struct{}{}
				return
			}
		}
	}()
	return changed
}

func lookupRelayIPSet(ctx context.Context, resolver hostnameResolver, host string) (map[string]struct{}, bool) {
	lookupCtx, cancel := context.WithTimeout(ctx, outboundDialTimeout)
	defer cancel()
	addresses, err := resolver.LookupNetIP(lookupCtx, host)
	if err != nil {
		return nil, false
	}
	set := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		set[address.String()] = struct{}{}
	}
	return set, true
}

func sameRelayIPSet(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for address := range a {
		if _, ok := b[address]; !ok {
			return false
		}
	}
	return true
}
