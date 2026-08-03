# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Optional encrypted expiration reminder addresses, durable seven-day and one-day
  LNemail delivery, an operator-funded NWC budget with lookup-before-retry payment
  handling, strict send-price caps, and non-sensitive outbox status in the admin UI.
- Production NWC payments and automatic renewal through a compiled, single-shot
  Bun helper pinned to `@getalby/sdk` 8.0.3, with strict NIP-44/capability checks,
  encrypted rotating credential storage, LND-authoritative reconciliation,
  conservative lookup-before-retry semantics, durable leases/attempt state, and
  wallet controls that never disclose connection URIs.
- Fixed monthly (30 service days) and yearly (365 service days) billing with
  per-subscription price snapshots, per-payment term/amount/period snapshots,
  explicit API catalog and response fields, responsive Web term controls, and
  a default-off yearly issuance gate for migration-safe rolling deployment.
- Customer-owned Relay subscriptions now receive unique 128-bit-random CNAME
  targets at claim creation, with exact direct-CNAME ownership verification and
  explicit DNS record fields in v1-compatible API responses. Pre-rollout pending
  TXT claims retain their bounded legacy verification path.
- Random UUIDv4 public account identifiers with legacy v1 compatibility, plus an
  atomic pricing-first anonymous order API that discloses the bearer token once.
- A responsive pricing-first Web experience and built-in client guide covering
  product choices, installation, TLS, Docker, WireGuard, Tor, and troubleshooting.
- Native SOCKS5 transport in `blindportd` for Tor-routed backend and relay
  connections, version reporting, and additional loopback relay control listeners.
- Canary onion-service and versioned-download wiring, with expanded shared TCP and
  UDP inventory for production trials.
- Canary deployment controls for pre-DNS internal TLS, source-restricted
  pre-LND testing, and per-service CPU and memory ceilings.
- Optional routed WireGuard Blindport IP delivery with disjoint provider-routed `/32`
  inventory, signed agent key enrollment, fail-closed relay reconciliation,
  Linux source-policy routing, relay metrics, dashboard selection, and kernel
  dataplane e2e coverage.
- UDP Blindport Port leases with transport-aware allocation, versioned datagram
  framing, bounded relay source associations, agent UDP upstream forwarding,
  fixed-cardinality metrics, and full-stack echo coverage.
- Backend mini Certificate Authority (Ed25519 root, self-signed, persisted
  under `CA_DIR`) that issues short-lived client and relay server
  certificates.
- `GET /api/v1/client/cert` returns a backend-issued mTLS client cert for
  the authenticated user; `POST /internal/v1/relay/cert` does the same for
  relay nodes authenticated with the shared relay secret.
- Relay control plane terminates mutual TLS using the backend-issued
  server cert and requires + verifies a client cert from the same CA.
- `blindportd` automatically fetches its client cert at startup and dials
  the relay with `tls.Dial`. An `-insecure-skip-tls` flag remains for
  development.
- Pay-with-Cashu dashboard button: server-side QR (segno SVG) for the
  mint-issued BOLT11 invoice and live polling that auto-redeems the minted
  ecash as soon as the mint reports the invoice paid. From the user's
  side only a Lightning wallet is required.
- Bundled [Nutshell](https://github.com/cashubtc/nutshell) Cashu mint in
  the dev compose stack so end-to-end Cashu redemption runs offline.
- Relay IP pool expanded to eight slots (`10.50.0.10..17`) so the
  cumulative e2e suite no longer needs a volume reset between runs.
- End-to-end tests: real Cashu redemption against the bundled mint,
  mini-CA client cert issuance, and relay mTLS enforcement (positive +
  negative paths).

### Fixed

- Tunnel streams now drain TCP payloads and UDP datagrams queued before a peer
  `CLOSE`, preventing response truncation when data and closure arrive together.
- WireGuard relay reconciliation now updates peers in place so recurring
  desired-state polls preserve learned roaming endpoints and handshakes.
- The routed agent accepts its shipped `51820` routing table and rule priority.
- Mini-CA certificates now embed `SubjectKeyIdentifier` (root + leaves)
  and `AuthorityKeyIdentifier` (leaves), which Python 3.14's stdlib
  `ssl` module requires when verifying a chain.

### Security

- The client<->relay tunnel is no longer reachable without a
  backend-issued client certificate. Application-layer revocation (token
  disable on the backend) still applies on top, so a compromised but
  unrevoked token cannot outlive its certificate's 30-day TTL.
