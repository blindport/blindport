# Blindport

Blindport is an experimental Bitcoin-paid reachability service for self-hosted
origins. Framed delivery uses an authenticated outbound tunnel to multiplex TCP
streams or UDP datagrams to configured local upstreams. Routed Blindport IP delivery
uses WireGuard to assign a provider-routed public IPv4 `/32` directly to the
customer host without NAT.

[Source](https://github.com/blindport/blindport) |
[Issues](https://github.com/blindport/blindport/issues) |
[Releases](https://github.com/blindport/blindport/releases) |
[Security](SECURITY.md)

> Blindport is pre-1.0 software. Review the threat model, deployment manifests,
> and operational requirements before exposing production services.

The three products use distinct ingress identities:

- **Blindport IP** leases one dedicated public IP. `framed` delivery forwards
  configured TCP listeners; `wireguard` delivery routes the full IPv4 `/32` to
  a Linux customer host.
- **Blindport Port** leases exactly one `(shared public IP, port, TCP or UDP)` socket.
  Shared addresses are separate inventory from dedicated Blindport IP addresses.
- **Blindport Relay** leases one hostname. A shared TLS listener reads ClientHello SNI
  without terminating TLS and forwards the raw TCP stream. An optional,
  challenge-only HTTP listener forwards bounded ACME HTTP-01 validation requests
  to a separate customer upstream; it is not a general HTTP relay.

TLS for user traffic, when used, terminates at the user's upstream. Blindport Port
supports TCP or UDP. WireGuard Blindport IP is the only routed interface mode; framed
Blindport IP, Blindport Port, and Blindport Relay remain application forwarding products.

Blindport Relay supports provider-managed names strictly below configured wildcard
suffixes and customer-owned names proven by pointing one exact DNS CNAME record
at a subscription-specific random target before payment. The managed suffix apex
is reserved for the provider and cannot be leased. Blindport currently reads
customer DNS through a recursive resolver; it is not an authoritative DNS server.
Customer-owned names must be non-apex subdomains with a direct, DNS-only CNAME;
flattened, proxied, and wildcard customer records are not supported in the canary.
Future registrar or authoritative-DNS integrations can automate the same
subscription and verification API flow.

Accounts use a one-time Crockford base32 bearer token. The primary payment path
is direct Lightning through LND. Cashu and Nostr Wallet Connect adapters remain
experimental and are not exposed by the dashboard. In particular, Cashu quote
recovery and reconciliation are not production-ready.

Subscriptions support fixed monthly (30 service days) and yearly (365 service
days) terms. Prices are snapshotted when a subscription is created, and each
payment snapshots its amount and exact service period before settlement.
Yearly issuance is controlled by `BILLING_YEARLY_ENABLED` so operators can enable
it only after completing the migration-first rolling deployment.
Accounts can optionally store an encrypted email address for seven-day and one-day
expiration reminders. Delivery is disabled by default and uses an operator-funded,
budget-limited NWC connection to pay LNemail's per-message Lightning invoice.

## Repository layout

| Path | Contents |
| --- | --- |
| `backend/` | FastAPI control plane, allocation, payments, UI, and tunnel certificate authority. |
| `go/` | `blindport-relay`, `blindportd`, and the v0 tunnel implementation. |
| `docker/` | Container builds and the local Compose stack. |
| `tests/e2e/` | Full-stack tests for payment, authorization, and forwarding. |
| `docs/` | Architecture, protocol, and operating notes. |
| `tools/nwc-helper/` | Single-shot Bun NWC protocol executable built into the backend image. |

## Container images

Signed releases publish these multi-architecture images from this repository:

| Image | Purpose | Platforms |
| --- | --- | --- |
| `ghcr.io/blindport/blindport-backend` | Control plane, Web UI, migrations, and NWC helper. | `linux/amd64`, `linux/arm64` |
| `ghcr.io/blindport/blindport-relay` | Provider edge relay. | `linux/amd64`, `linux/arm64` |
| `ghcr.io/blindport/blindportd` | Customer tunnel and Docker discovery agent. | `linux/amd64`, `linux/arm64`, `linux/arm/v7` |

Release notes include a `blindport-images.env` asset with digest-pinned image
references. Prefer those immutable references for deployments. Stable releases
also update `latest`, `vMAJOR.MINOR`, and, after `v1.0.0`, `vMAJOR` aliases.
Prereleases update only their exact tag.

```sh
docker pull ghcr.io/blindport/blindportd:latest
gh attestation verify oci://ghcr.io/blindport/blindportd:latest \
  -R blindport/blindport \
  --signer-workflow blindport/blindport/.github/workflows/release.yaml
```

See [Self-hosting Blindport](docs/self-hosting.md) for control-plane and relay
deployment. Agent configuration is documented in [docs/agent.md](docs/agent.md).
Maintainer release steps are documented in [docs/releasing.md](docs/releasing.md).

## Development stack

```sh
docker compose -f docker/docker-compose.yaml up -d --build
docker compose -f docker/docker-compose.yaml exec -T tester pytest /repo/tests/e2e -v
docker compose -f docker/docker-compose.yaml down -v
```

The dashboard is at `http://localhost:8000`. Compose uses mock Lightning/NWC
adapters, a development Nutshell mint, and a fixed development-only WireGuard
keypair. Routed e2e coverage requires a Linux host with kernel WireGuard support.

The development Compose stack is not a production deployment. Production canary
and split control/relay manifests, secret preparation, and validation are under
[`deploy/`](deploy/OPERATIONS.md). These deployments pull released GHCR images;
they do not build application images on the server.

## Local development

Use Python 3.11 or newer, Bun 1.3.11, and Go 1.26.5. Python 3.14 is the canonical
interpreter for dependency lock regeneration. The Go module retains a Go 1.25.0
compatibility floor.

```sh
python -m venv .venv
. .venv/bin/activate
pip install --require-hashes -r backend/requirements-dev.txt
pip install --no-deps ./backend
pytest backend/tests -q
ruff check backend

python -m playwright install chromium
pytest tests/browser -q

cd go
go mod verify
go vet ./...
go build ./...
go test ./...
go test -race ./...
```

Run `prek run --all-files` before submitting changes.

`backend/pyproject.toml` is the dependency source of truth. The pinned
`coincurve` source build requires `build-essential`, `libffi-dev`, and
`pkg-config` on Debian or Ubuntu. Regenerate the committed locks after dependency
changes with Python 3.14 only:

```sh
python3.14 -m piptools compile -Uv --generate-hashes --strip-extras --allow-unsafe --no-header \
  --output-file backend/requirements.txt backend/pyproject.toml
python3.14 -m piptools compile -Uv --generate-hashes --strip-extras --allow-unsafe --no-header --extra dev \
  --output-file backend/requirements-dev.txt backend/pyproject.toml
```

## Architecture

The backend reserves scarce capacity before creating an external payment
request. Payment settlement commits that reservation into an active lease.
Unpaid reservation timeouts release only the owning payment's hold. Active
expiration removes authorization immediately, then quarantines dedicated Blindport IP and
Blindport Port assignments before reuse. Expired subscriptions can be paid again
after quarantine, but may receive a different resource.

Direct LND invoices use a durable, deterministic outbox. Provider timeouts or a
process failure after invoice creation can be recovered by payment hash without
issuing a second invoice. Production requires a dedicated invoice HMAC key shared
by all API replicas; see [`docs/operating.md`](docs/operating.md).

For framed delivery, the client and relay exchange length-prefixed JSON frames
over a long-lived TCP connection. The bearer token authorizes one explicit
resource claim, while backend-issued mutual TLS certificates bind the tunnel to
the same user. For routed delivery, the same client identity signs enrollment
of a separate local WireGuard key, and the relay reconciles authorized peers and
provider-routed `/32` routes from backend desired state. See
[`docs/protocol.md`](docs/protocol.md) for the current open v0 draft and
[`docs/architecture.md`](docs/architecture.md) for system details. Agent static
multi-mapping and Docker label configuration is documented in
[`docs/agent.md`](docs/agent.md).

Blindport Relay can use DNS active-active ingress when every advertised relay edge is
included in backend provisioning. The agent maintains an independent tunnel to
each provisioned edge. DNS does not preserve established TCP sessions. Framed
Blindport IP and Blindport Port remain pinned to their assigned primary relay socket
inventory; routed Blindport IP remains pinned to its configured WireGuard endpoint
and provider route.

## License

Blindport is available under the [MIT License](LICENSE).
