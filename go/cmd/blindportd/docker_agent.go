package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxOrderResponse  = 256 << 10
	orderRetryInitial = 10 * time.Second
	orderRetryMaximum = 5 * time.Minute
)

type orderRequest struct {
	Product     string `json:"product"`
	Domain      string `json:"domain,omitempty"`
	Transport   string `json:"transport"`
	Delivery    string `json:"delivery"`
	BillingTerm string `json:"billing_term"`
}

type orderResponse struct {
	OrderKey     string `json:"order_key"`
	Subscription struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"subscription"`
	Payment json.RawMessage `json:"payment,omitempty"`
	State   string          `json:"state"`
}

type orderAPIClient struct {
	client  *http.Client
	backend string
	token   string
}

func (c *orderAPIClient) put(ctx context.Context, declaration mapping) (*orderResponse, error) {
	body, err := json.Marshal(orderRequest{
		Product: declaration.Product, Domain: declaration.Domain, Transport: declaration.Transport,
		Delivery: "framed", BillingTerm: declaration.BillingTerm,
	})
	if err != nil {
		return nil, fmt.Errorf("encode order request: %w", err)
	}
	endpoint := strings.TrimRight(c.backend, "/") + "/api/v1/client/orders/" + url.PathEscape(declaration.OrderKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create order request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("put order %q: %w", declaration.OrderKey, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("order %q status %d", declaration.OrderKey, resp.StatusCode)
	}
	var result orderResponse
	if err := decodeBoundedJSONLoose(resp.Body, maxOrderResponse, &result); err != nil {
		return nil, fmt.Errorf("decode order %q: %w", declaration.OrderKey, err)
	}
	if result.OrderKey != declaration.OrderKey {
		return nil, fmt.Errorf("order response key %q does not match %q", result.OrderKey, declaration.OrderKey)
	}
	if validateSubscriptionID(result.Subscription.ID) != nil || result.Subscription.Status == "" {
		return nil, fmt.Errorf("order %q returned invalid subscription", declaration.OrderKey)
	}
	switch result.State {
	case "awaiting_domain", "awaiting_payment", "payment_pending", "active", "attention_required":
	default:
		return nil, fmt.Errorf("order %q returned unknown state %q", declaration.OrderKey, result.State)
	}
	return &result, nil
}

func decodeBoundedJSONLoose(body io.Reader, limit int64, destination any) error {
	return decodeBoundedJSONReader(body, limit, destination, false)
}

type orderCacheEntry struct {
	declaration          mapping
	subscription         string
	state                string
	fallbackDeclaration  mapping
	fallbackSubscription string
	nextAttempt          time.Time
	retryInterval        time.Duration
}

type planReconciler interface {
	Reconcile([]workerPlan) error
}

type dockerAgent struct {
	docker        dockerContainerLister
	static        []mapping
	orders        *orderAPIClient
	fetchConfig   func(context.Context) ([]provisioning, error)
	supervisor    planReconciler
	relayOverride string
	pollInterval  time.Duration
	logger        *slog.Logger
	now           func() time.Time
	desired       []mapping
	orderCache    map[string]*orderCacheEntry
}

func (a *dockerAgent) run(ctx context.Context) {
	a.reconcile(ctx)
	ticker := time.NewTicker(a.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.reconcile(ctx)
		}
	}
}

func (a *dockerAgent) reconcile(ctx context.Context) {
	snapshot, err := discoverDockerMappings(ctx, a.docker)
	if err != nil {
		a.logger.Warn("discover Docker mappings", "err", err)
	} else if err := validateDockerSnapshot(a.static, snapshot); err != nil {
		a.logger.Warn("validate Docker snapshot", "err", err)
	} else {
		a.desired = snapshot
		a.pruneOrderCache(snapshot)
	}

	resolved, err := a.resolveMappings(ctx)
	if err != nil {
		a.logger.Warn("resolve Docker orders", "err", err)
	}
	cfg, err := a.fetchConfig(ctx)
	if err != nil {
		a.logger.Warn("fetch config", "err", err)
		return
	}
	mappings := append(append([]mapping(nil), a.static...), resolved...)
	plans, err := buildAvailableMappingPlans(mappings, cfg, a.relayOverride)
	if err != nil {
		a.logger.Warn("build Docker tunnel plans", "err", err)
		return
	}
	if err := a.supervisor.Reconcile(plans); err != nil && !errors.Is(err, context.Canceled) {
		a.logger.Warn("reconcile tunnel workers", "err", err)
	}
}

func (a *dockerAgent) resolveMappings(ctx context.Context) ([]mapping, error) {
	now := a.now()
	result := make([]mapping, 0, len(a.desired))
	var resolutionErrors []error
	for _, item := range a.desired {
		if item.Product == "" {
			result = append(result, item)
			continue
		}
		entry, exists := a.orderCache[item.OrderKey]
		if !exists || !sameOrderDeclaration(entry.declaration, item) {
			replacement := &orderCacheEntry{declaration: item, retryInterval: orderRetryInitial}
			if exists && entry.subscription != "" {
				replacement.fallbackDeclaration = entry.declaration
				replacement.fallbackSubscription = entry.subscription
			} else if exists && entry.fallbackSubscription != "" {
				replacement.fallbackDeclaration = entry.fallbackDeclaration
				replacement.fallbackSubscription = entry.fallbackSubscription
			}
			entry = replacement
			a.orderCache[item.OrderKey] = entry
		}
		shouldPut := entry.subscription == "" || entry.state == "attention_required"
		if shouldPut && (entry.nextAttempt.IsZero() || !now.Before(entry.nextAttempt)) {
			response, err := a.orders.put(ctx, item)
			if err != nil {
				entry.nextAttempt = now.Add(entry.retryInterval)
				entry.retryInterval = nextOrderRetry(entry.retryInterval)
				resolutionErrors = append(resolutionErrors, err)
			} else {
				entry.subscription = response.Subscription.ID
				entry.state = response.State
				entry.fallbackDeclaration = mapping{}
				entry.fallbackSubscription = ""
				if response.State == "attention_required" {
					entry.nextAttempt = now.Add(entry.retryInterval)
					entry.retryInterval = nextOrderRetry(entry.retryInterval)
				} else {
					entry.nextAttempt = time.Time{}
					entry.retryInterval = orderRetryInitial
				}
			}
		}
		if entry.subscription != "" {
			result = append(result, resolvedOrderMapping(item, entry.subscription))
		} else if entry.fallbackSubscription != "" {
			result = append(result, resolvedOrderMapping(entry.fallbackDeclaration, entry.fallbackSubscription))
		}
	}
	if len(resolutionErrors) > 0 {
		return result, errors.Join(resolutionErrors...)
	}
	return result, nil
}

func resolvedOrderMapping(declaration mapping, subscriptionID string) mapping {
	declaration.SubscriptionID = subscriptionID
	declaration.Product = ""
	declaration.Domain = ""
	declaration.Transport = ""
	declaration.BillingTerm = ""
	return declaration
}

func (a *dockerAgent) pruneOrderCache(snapshot []mapping) {
	wanted := make(map[string]struct{})
	for _, item := range snapshot {
		if item.Product != "" {
			wanted[item.OrderKey] = struct{}{}
		}
	}
	for key := range a.orderCache {
		if _, ok := wanted[key]; !ok {
			delete(a.orderCache, key)
		}
	}
}

func nextOrderRetry(current time.Duration) time.Duration {
	if current <= 0 {
		return orderRetryInitial
	}
	next := current * 2
	if next > orderRetryMaximum {
		return orderRetryMaximum
	}
	return next
}
