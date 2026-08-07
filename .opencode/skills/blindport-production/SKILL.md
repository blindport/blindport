---
name: blindport-production
description: Use ONLY when deploying, diagnosing, monitoring, or testing Blindport production across Servers.Guru and mynymbox.
---

# Blindport Production

## Production Sites

- Servers.Guru SSH: `ssh root@blindport.com -i ~/.ssh/blindport_servers_guru_ed25519`
- Servers.Guru address: `78.17.212.128`
- Servers.Guru stack: `/opt/blindport/canary`, Compose project `blindport-canary`
- mynymbox SSH: `ssh root@89.125.35.70 -i ~/.ssh/blindport_servers_guru_ed25519`
- mynymbox addresses: `89.125.35.70`, `89.125.35.71`, `89.125.35.72`, and
  `2a14:1ec7:f903:4::/64`
- mynymbox Relay stack: `/opt/blindport/relay`, Compose project `blindport-relay`
- Public readiness: `https://blindport.com/api/v1/health/ready`
- Production Docker architecture: `amd64` (`x86_64` remotely).

Address roles are explicit. `89.125.35.70` is the mynymbox shared Relay, Port, and
control ingress address. `89.125.35.71` and `89.125.35.72` are framed Blindport IP
inventory and must remain in `RELAY_PUBLIC_IPS` plus `FRAMED_IP_ENDPOINTS` while
assigned, reserved, or quarantined. The backend catalog and lease records are the
stock authority. Do not remove inventory to represent a sale. Do not offer either
address as routed WireGuard inventory unless mynymbox confirms provider routing or
the required proxy-ARP design is tested end to end.

## HA Boundary

Relay and Port data-plane HA use provider-specific control endpoints and one tunnel
per edge. Managed Relay, Relay pool, and Port wildcard DNS names contain one ingress
address per provider. DNS round robin does not withdraw unhealthy answers by itself.

The Servers.Guru PostgreSQL volume is currently the sole control-plane authority.
Do not publish the mynymbox address for `blindport.com` or describe the website as HA
until both sites use one fenced writer endpoint with external quorum, shared signer
and secrets, redundant LND access, and readiness-based DNS steering. A reverse proxy
from mynymbox to Servers.Guru is not website HA.

The intended DNS set after each prerequisite is met is:

- `relay-sg.blindport.com` A `78.17.212.128`
- `relay-mynymbox.blindport.com` A `89.125.35.70`
- `*.relay.blindport.com` and `*.ingress.blindport.com` A records for both providers
- `*.port.blindport.com` A records for both providers
- `blindport.com` A records for both providers only after control-plane HA exists

Use 30 to 60 second TTLs where supported. Verify authoritative answers and both
provider paths independently before changing customer-facing round robin records.

Do not place account tokens, NWC URIs, wallet secrets, database URLs, macaroons,
private keys, or secret-file contents in commands, logs, patches, or summaries.
Use server-side encrypted credentials or non-echoing pipes when a live diagnostic
requires authorization. Never print the resulting value.

## Before A Deployment

1. Inspect local `git status`, the release commit, and its complete diff.
2. Inspect both sites' live images, health, restart counts, relevant `.env` key
   presence, Compose checksums, rollback scripts, architectures, network addresses,
   memory, and disk capacity.
3. Treat every live image and Compose checksum as one coordinated deployment
   baseline. Another release may occur concurrently. Abort and rebase if any
   baseline changes.
4. Build from a clean detached worktree or isolated release branch. Never build
   from the dirty main worktree.
5. Run focused tests, full relevant suites, `./deploy/validate.sh`, and
   `prek run --all-files`. Record known unrelated hook failures explicitly.
6. Build an immutable local tag `blindport-backend:canary-<short-revision>` for
   `linux/amd64`. Probe the installed package and compiled NWC helper before export.

## Deployment Transaction

Keep release artifacts under the repository's ignored `tmp/` directory. Export
the image, gzip it, checksum it, transfer it to remote `/tmp`, verify the remote
checksum and gzip integrity, then load it with Docker.

Use one-use guarded scripts per site that:

1. Verifies the expected live image and Compose checksum.
2. Backs up `.env` and `compose.yaml` under that site's stack `backups/` directory.
3. Installs `rollback-<revision>.sh` in that site's stack directory before mutation.
4. Changes only intended `.env` keys and Compose content.
5. Runs `docker compose ... config --quiet`.
6. Recreates only the required service with `--no-deps --force-recreate`.
7. Automatically restores both backups on any failure.
8. Requires healthy state, zero restarts, the intended image, and feature-specific
   runtime assertions before success.

For Relay changes, deploy and validate the new mynymbox edge before changing backend
provisioning or public wildcard DNS. Roll back DNS first, then backend provisioning,
then the edge. Never let an advertised edge lack the matching agent claim or Relay
authorization.

Build and transfer every changed backend, Relay, and downloadable agent artifact.
Use immutable revision tags for container images and verify the agent version and
checksum before publishing it. The Caddy admin API is disabled. Caddy configuration changes require container
recreation. Backend-only releases must not recreate unrelated services.

## Production Verification

- Confirm readiness components: database, migrations, Lightning, reconciler.
- Confirm the backend is healthy with zero restarts after a delayed check.
- Confirm all Compose services remain healthy.
- Probe each provider-specific Relay control address and each provider ingress path
  directly, without relying only on round robin DNS.
- Verify Port provisioning contains one claim per provider and framed IP provisioning
  selects only the address-owning edge.
- Verify public HTTP behavior, OpenAPI/schema changes, and public asset hashes when
  relevant.
- Scan recent logs without printing them. Report only counts and assert that no
  `nostr+walletconnect://` URI or `?secret=` value appears.
- Validate rollback syntax, modes, backups, and previous image availability.
- Remove only transferred files from remote `/tmp`; retain rollback artifacts and
  the previous image.

Never push. Create local Conventional Commits only when explicitly part of the
requested work.
