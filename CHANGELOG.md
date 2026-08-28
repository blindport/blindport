# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Annual-only bidirectional routed Blindport IP, with durable assignment history,
  reviewed paid TCP/25 exceptions, and fail-closed nftables policy reconciliation.
- Optional stablecoin checkout through Lightning Swap or Boltz, with prefilled external
  invoice links, per-payment provider snapshots, a conservative satoshi floor, a
  dedicated kill switch, and LND-only settlement.
- Approximate cached Bitcoin/USD price labels, bounded unpaid Relay name holds,
  and structured recovery when another payment method is already pending.
- A reusable Blindport logo system with profile, favicon, app icon, and social
  preview exports, plus Open Graph and large-card metadata for shared links.
- A checksum-verifying Linux installer and an interactive first-run token prompt.
- Per-account NWC connection setup with explicit automatic-renewal consent and a
  public-relay egress policy for wallet-provided connection URIs.
- Provider-edge Port assignments with a stable hostname and explicit ingress IPs,
  plus owner-edge routing for framed dedicated IP inventory.
- Proportional bonus service time for Lightning Swap minimum top-ups, and
  prorated exact Relay to wildcard upgrades with DNS-gated atomic activation.
- Opt-in PROXY protocol v2 for TCP upstreams, wildcard-aware HTTP-01 forwarding,
  and a Traefik wildcard Relay deployment example.

### Changed

- The dashboard now prioritizes the next endpoint action, resumes open invoices,
  cancels safe unpaid orders, and hides advanced account and agent details.
- Docker agent examples use an environment token and named identity volume.
- TCP tunnels apply bounded backpressure instead of closing a stream when a slow
  public receiver fills the per-stream queue.
- Lightning Swap checkout now uses a percent-encoded BOLT11 query parameter in a new
  provider tab and no longer requires provider API credentials or prepared orders.
- Customer-owned wildcard Relay subscriptions now route their base hostname in
  addition to all descendants at the existing wildcard price. Base DNS remains
  optional, while exact routes retain precedence.
- Customer-owned wildcard Relay subscriptions require only their retained TXT
  ownership challenge before initial and renewal payments. Routing CNAME records
  can be changed later for a no-downtime migration.
- Legacy NIP-04-only NWC providers can be enabled explicitly while NIP-44 v2
  remains preferred and required by default.

## [0.2.3] - 2026-08-04

### Added

- Blindport Relay for publishing TLS services through managed or customer-owned
  hostnames without terminating customer TLS.
- Blindport Port for forwarding one shared public TCP or UDP endpoint, and
  Blindport IP for either low-privilege framed TCP forwarding or a complete
  routed public IPv4 interface through WireGuard.
- Anonymous bearer-token accounts with opaque public identifiers, monthly or
  yearly service terms, direct Lightning payments, optional NWC automatic
  renewal, and optional SMTP expiration reminders.
- A responsive dashboard and admin control panel for orders, payments, client
  setup, account status, and service statistics.
- Linux `blindportd` binaries and containers with static mappings, Docker
  discovery, native routed WireGuard, and optional Tor SOCKS5 transport.
- End-to-end mutual TLS between agents and relays, GPG-signed source releases,
  checksummed CI-built binaries, multi-architecture GHCR images, and
  digest-pinned deployment references.
