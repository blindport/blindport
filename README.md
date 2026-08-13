# Blindport

Blindport is an experimental Bitcoin-paid reachability service for self-hosted
origins. Framed delivery uses an authenticated outbound tunnel to multiplex TCP
streams or UDP datagrams to configured local upstreams. Routed Blindport IP delivery
uses WireGuard to assign a static provider-routed public IPv4 `/32` directly to
the customer host without NAT. The same address receives inbound traffic and
sources outbound traffic sent through the interface.

Use framed Relay or Port delivery by default for domains and individual services:
it needs no network-administration capability and works with ordinary relay ingress
inventory. Use routed WireGuard only when the workload needs a complete public IPv4
interface, native UDP or ICMP behavior, arbitrary ports, or protocols beyond TCP and
UDP, and the Linux host can grant `CAP_NET_ADMIN`.

[Source](https://github.com/blindport/blindport) |
[Issues](https://github.com/blindport/blindport/issues) |
[Releases](https://github.com/blindport/blindport/releases) |
[Security](SECURITY.md)

Brand exports for project profiles and integrations are available in
[`backend/src/blindport/static/`](backend/src/blindport/static/): use
`brand-avatar.png` for square avatars, `brand-wordmark.svg` for horizontal
placements, and `brand-social.png` for 1200 by 630 link previews.

> Blindport is pre-1.0 software. Review the threat model, deployment manifests,
> and operational requirements before exposing production services.

The three products use distinct ingress identities:

- **Blindport IP** leases one dedicated public IP as an annual-only WireGuard
  `/32`. It routes TCP, UDP, ICMP, arbitrary ports, and outbound traffic to a
  privileged Linux customer host. New outbound TCP connections to port 25 are
  blocked unless the operator approves a paid exception for the current lease.
  Historical framed IP records remain readable and can operate only through
  their existing paid period; they cannot receive new payments or renewals.
- **Blindport Port** leases one canonical `(shared public IP, port, TCP or UDP)`
  socket. An optional provider-edge topology mirrors that port through distinct
  provider-local public IPs and advertises one stable hostname. Shared addresses
  are separate inventory from dedicated Blindport IP addresses.
- **Blindport Relay** leases one hostname. By default, `blindportd` obtains and
  renews a Let's Encrypt certificate, terminates TLS on the customer host, and
  forwards plaintext to the configured local app. Advanced passthrough keeps TLS
  termination and certificate management in an existing origin server.

Automatic Relay TLS terminates in the customer agent, not at the Blindport edge.
Blindport Port supports TCP or UDP. WireGuard is the only currently issued
Blindport IP delivery mode. Blindport Port and Blindport Relay remain application
forwarding products; framed Blindport IP is retained only for historical service.

Blindport Relay supports provider-managed names strictly below configured wildcard
suffixes, exact customer-owned names for 3,000 sats per 30 days, and customer-owned
wildcard bases for 7,500 sats per 30 days. Exact customer names use one direct CNAME
to a subscription-specific random target. Wildcard bases use a TXT ownership challenge
and a wildcard CNAME to a Relay pool target, route strict descendant names, and require
TLS passthrough to the customer origin. The managed suffix apex is reserved for the
provider and cannot be leased. Blindport currently reads customer DNS through a
recursive resolver; it is not an authoritative DNS server. CNAME flattening and
CDN-proxied records are not supported in the hosted beta. Future registrar or
authoritative-DNS integrations can automate the same subscription and verification API
flow.

An active exact customer-owned Relay can be upgraded to a wildcard at the exact
hostname's immediate parent. The unused exact term is valued at its snapshotted
daily rate and applied as a noncash discount to the selected wildcard term. The
exact route stays active until wildcard DNS is verified and the upgrade payment
settles, then the wildcard replaces it atomically.

Unpaid managed names are held for 30 minutes and customer-owned names for one
hour. One account may hold at most two unpaid Relay claims, and the background
reconciler releases elapsed claims, limiting no-cost name reservation abuse.

Accounts use a one-time Crockford base32 bearer token for recovery and agent access.
The public browser UI can optionally enroll discoverable passkeys backed by revocable
opaque sessions; passkey authentication never reveals the bearer token. The primary
payment path is direct Lightning through LND. Nostr Wallet Connect is optional
wallet control over BOLT11 invoices. Operators may separately enable a stablecoin
checkout. New installs use Lightning Swap, as recommended by Megalithic's guide:
Blindport opens a new provider tab using the snapshotted origin and
`/?invoice=<percent-encoded BOLT11>`, which prefills the LND invoice in the provider
UI before the customer selects the configured stablecoin network. Boltz remains an
optional prefilled checkout provider. Blindport receives Lightning bitcoin and
activates service only after LND reports settlement; no provider callback can activate
service. Legacy persisted Cashu payment rows remain readable, but Cashu runtime
support has been removed.

Blindport Port and Relay support fixed monthly (30 service days) and yearly (365
service days) terms. New Blindport IP subscriptions use 365 service days only.
Prices are snapshotted when a subscription is created, and each payment snapshots
its amount, stablecoin surcharge, and service period before settlement. Lightning
Swap provider minimum top-ups earn proportional bonus service time, rounded up to
a whole service day.
Yearly issuance is controlled by `BILLING_YEARLY_ENABLED`; Blindport IP sales have
no capacity while that gate is disabled.
Accounts can optionally store an encrypted address for ACCOUNT lifecycle mail,
including activation, renewal, seven-day and one-day expiration notices, and actual
expiry. SERVICE announcements use separate consent. A privacy-preserving unified
outbox stores references and recipient generations, not message material. Its worker
is independent of payment reconciliation; it drains legacy outboxes, expands queue-time
campaign snapshots in bounded pages, and retries only before an ambiguous SMTP boundary.

## Repository layout

| Path | Contents |
| --- | --- |
| `backend/` | FastAPI control plane, allocation, payments, UI, and tunnel certificate authority. |
| `go/` | `blindport-relay`, `blindportd`, and the v0 tunnel implementation. |
| `docker/` | Container builds and the local Compose stack. |
| `examples/` | Runnable customer deployment examples. |
| `tests/e2e/` | Full-stack tests for payment, authorization, and forwarding. |
| `docs/` | Architecture, protocol, and operating notes. |
| `tools/nwc-helper/` | Single-shot Bun NWC protocol executable built into the backend image. |

## Container images

GitHub Actions builds these multi-architecture convenience images from signed
release tags:

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
```

Using these images means trusting GitHub Actions and GHCR. Users who do not place
CI inside their trust boundary should verify the GPG-signed release tag and build
the checked-out source locally.

See [Self-hosting Blindport](docs/self-hosting.md) for control-plane and relay
deployment. The [high-availability notes](docs/ha.md) describe the local fault lab and
the additional infrastructure required for a two-provider deployment. Agent configuration is documented in [docs/agent.md](docs/agent.md).
Maintainer release steps are documented in [docs/releasing.md](docs/releasing.md).

For active hosted endpoints, install the Linux agent as your normal user:

```sh
curl -fsSL https://blindport.com/downloads/install.sh | sh
```

In the dashboard, set each local target (for example, `127.0.0.1:8080`), explicitly
accept the Let's Encrypt Subscriber Agreement for automatic Relay HTTPS, and install
the generated version 2 config. Then start the persistent user service:

```sh
blindportd -install-user-service
```

The command prompts for the account token if needed. Docker deployments use
`BLINDPORT_TOKEN` and a named volume for client identity and certificate state.
The runnable [Docker example](examples/docker/README.md) connects an existing
paid Relay directly to an application container without adding a reverse proxy.

## Development stack

```sh
docker compose -f docker/docker-compose.yaml up -d --build
docker compose -f docker/docker-compose.yaml exec -T tester pytest /repo/tests/e2e -v
docker compose -f docker/docker-compose.yaml down -v
```

The dashboard is at `http://localhost:8000`. Compose uses mock Lightning/NWC
adapters and a fixed development-only WireGuard keypair. Routed e2e coverage
requires a Linux host with kernel WireGuard support.

The development Compose stack is not a production deployment. Production single-host
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

`backend/pyproject.toml` is the dependency source of truth. Regenerate the
committed locks after dependency changes with Python 3.14 only:

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
Blindport Port assignments before reuse. Expired Port and Relay subscriptions can
be paid again after quarantine or renewal grace as applicable. Historical framed
IP subscriptions cannot be paid again.

Direct LND invoices use a durable, deterministic outbox. Provider timeouts or a
process failure after invoice creation can be recovered by payment hash without
issuing a second invoice. Production requires a dedicated invoice HMAC key shared
by all API replicas; see [`docs/operating.md`](docs/operating.md).

Stablecoin checkout uses the same durable invoice and settlement path. Blindport
snapshots the selected provider and checkout origin on each payment. Boltz receives
a prefilled external URL. Lightning Swap defaults to USDC on Solana and opens a new
tab at the snapshotted origin with the percent-encoded BOLT11 in its `invoice` query
parameter, prefilled for the provider UI. `STABLECOIN_SWAP_MIN_INVOICE_SATS` is a
conservative static floor; any resulting minimum top-up earns proportional service
time rounded up to a whole day. LND settlement remains authoritative.
The hosted UI may show a cached approximate USD value from mempool.space for
orientation; satoshi prices remain authoritative when that optional feed is stale
or unavailable.

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
each provisioned edge. DNS does not preserve established TCP sessions. Historical
framed Blindport IP and current Blindport Port remain pinned to their assigned
primary relay socket inventory; routed Blindport IP remains pinned to its
configured WireGuard endpoint and provider route.

## Contact

Email [support@blindport.com](mailto:support@blindport.com) or follow Blindport on
[Nostr](https://njump.me/npub1xqthzgt6zv39l3tanlmlxa6aay48n0j3lukxzgs0ygwg5g5j8elquxchn8).

## License

Blindport is available under the [MIT License](LICENSE).
