package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const provisioningRefreshInterval = 30 * time.Second

// provisioningCoordinator keeps the local mapping intent separate from the
// versioned response. Legacy mode freezes its first successful subscription so
// later topology changes cannot silently choose a different product.
type provisioningCoordinator struct {
	mappings      []mapping
	legacy        *legacyCoordinator
	relayOverride string
	allowMissing  bool
}

type legacyCoordinator struct {
	selection             legacySelection
	upstream              string
	httpChallengeUpstream string
	subscriptionID        string
}

func newMappingProvisioningCoordinator(mappings []mapping, relayOverride string, allowMissing bool) *provisioningCoordinator {
	return &provisioningCoordinator{mappings: append([]mapping(nil), mappings...), relayOverride: relayOverride, allowMissing: allowMissing}
}

func newLegacyProvisioningCoordinator(selection legacySelection, upstream, httpChallengeUpstream, relayOverride string) *provisioningCoordinator {
	return &provisioningCoordinator{relayOverride: relayOverride, legacy: &legacyCoordinator{
		selection: selection, upstream: upstream, httpChallengeUpstream: httpChallengeUpstream,
	}}
}

func (c *provisioningCoordinator) plans(result provisioningResult) ([]workerPlan, error) {
	if result.V2 != nil {
		mappings, err := c.planMappingsV2(result.V2)
		if err != nil {
			return nil, err
		}
		if c.allowMissing {
			return buildAvailableV2MappingPlans(mappings, result.V2, c.relayOverride)
		}
		return buildV2MappingPlans(mappings, result.V2, c.relayOverride)
	}
	if result.V1 == nil {
		return nil, errors.New("provisioning response has no usable configuration")
	}
	mappings, err := c.planMappingsV1(result.V1)
	if err != nil {
		return nil, err
	}
	if c.allowMissing {
		return buildAvailableMappingPlans(mappings, result.V1, c.relayOverride)
	}
	return buildMappingPlans(mappings, result.V1, c.relayOverride)
}

func (c *provisioningCoordinator) planMappingsV1(config []provisioning) ([]mapping, error) {
	if c.legacy == nil {
		return c.mappings, nil
	}
	if c.legacy.subscriptionID == "" {
		plans, err := buildLegacyPlans(config, c.legacy.selection, c.legacy.upstream, c.legacy.httpChallengeUpstream, c.relayOverride)
		if err != nil {
			return nil, err
		}
		if len(plans) == 0 {
			return nil, errors.New("legacy provisioning selected no workers")
		}
		c.legacy.subscriptionID = plans[0].SubscriptionID
		c.legacy.upstream = plans[0].Upstream
	}
	return []mapping{{SubscriptionID: c.legacy.subscriptionID, Upstream: c.legacy.upstream, HTTPChallengeUpstream: c.legacy.httpChallengeUpstream, TLSMode: tlsModePassthrough, Source: "legacy flags"}}, nil
}

func (c *provisioningCoordinator) planMappingsV2(config *provisioningV2) ([]mapping, error) {
	if c.legacy == nil {
		return c.mappings, nil
	}
	if c.legacy.subscriptionID == "" {
		legacyRows := make([]provisioning, 0, len(config.Subscriptions))
		for _, subscription := range config.Subscriptions {
			row, err := legacyProvisioning(subscription)
			if err != nil {
				return nil, err
			}
			legacyRows = append(legacyRows, row)
		}
		plans, err := buildLegacyPlans(legacyRows, c.legacy.selection, c.legacy.upstream, c.legacy.httpChallengeUpstream, "")
		if err != nil {
			return nil, err
		}
		if len(plans) == 0 {
			return nil, errors.New("legacy provisioning selected no workers")
		}
		c.legacy.subscriptionID = plans[0].SubscriptionID
		c.legacy.upstream = plans[0].Upstream
	}
	return []mapping{{SubscriptionID: c.legacy.subscriptionID, Upstream: c.legacy.upstream, HTTPChallengeUpstream: c.legacy.httpChallengeUpstream, TLSMode: tlsModePassthrough, Source: "legacy flags"}}, nil
}

func legacyProvisioning(subscription provisioningSubscription) (provisioning, error) {
	if len(subscription.Edges) == 0 {
		return provisioning{}, errors.New("v2 subscription has no edges")
	}
	row := provisioning{RelayEndpoint: subscription.Edges[0].Endpoint, Product: subscription.Product, Transport: subscription.Transport, SubscriptionID: subscription.SubscriptionID}
	if subscription.AssignedIP != nil {
		row.AssignedIP = *subscription.AssignedIP
	}
	if subscription.AssignedPort != nil {
		row.AssignedPort = *subscription.AssignedPort
	}
	if subscription.Domain != nil {
		row.Domain = *subscription.Domain
	}
	if _, err := claimFromProvisioning(row); err != nil {
		return provisioning{}, fmt.Errorf("invalid v2 legacy subscription: %w", err)
	}
	return row, nil
}

type provisioningFetcher func(context.Context) (provisioningResult, error)

// runProvisioningReconciler applies a successful initial plan before workers
// exist. During later refreshes only terminal or authoritative plan failures
// remove workers; infrastructure failures retain the last known good plan.
func runProvisioningReconciler(ctx context.Context, fetch provisioningFetcher, coordinator *provisioningCoordinator, supervisor planReconciler, interval time.Duration, logf func(string, error)) error {
	if interval <= 0 {
		interval = provisioningRefreshInterval
	}
	apply := func(initial bool) error {
		result, err := fetch(ctx)
		if err != nil {
			if !initial && provisioningFailure(err) == provisioningTerminal {
				if reconcileErr := supervisor.Reconcile(nil); reconcileErr != nil && !errors.Is(reconcileErr, context.Canceled) {
					logf("stop tunnel workers after terminal provisioning failure", reconcileErr)
				}
			}
			return err
		}
		plans, err := coordinator.plans(result)
		if err != nil {
			if !initial {
				if reconcileErr := supervisor.Reconcile(nil); reconcileErr != nil && !errors.Is(reconcileErr, context.Canceled) {
					logf("stop tunnel workers after invalid provisioning", reconcileErr)
				}
			}
			return err
		}
		return supervisor.Reconcile(plans)
	}
	if err := apply(true); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := apply(false); err != nil && !errors.Is(err, context.Canceled) {
				logf("refresh provisioning", err)
			}
		}
	}
}
