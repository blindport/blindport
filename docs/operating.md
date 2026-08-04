# Operating Blindport

## Production configuration

Set `ENVIRONMENT=production` to enable fail-fast production validation. The
production backend requires PostgreSQL through psycopg, direct Lightning through
a non-mock adapter, externally run migrations, absolute CA storage, positive
prices, and strong application and account tokens. Cashu cannot be enabled in
production. NWC is optional alongside mandatory direct Lightning when its helper
and credential security requirements are configured. The checked-in deployment
manifests intentionally leave it disabled. A representative baseline is:

```text
ENVIRONMENT=production
DATABASE_URL=postgresql+psycopg://blindport:<database-password>@postgres.example.net/blindport
DATABASE_MIGRATE_ON_STARTUP=false
PAYMENT_ENABLED_METHODS=lightning
PAYMENT_LIGHTNING_ADAPTER=lnd
PAYMENT_RECONCILIATION_ENABLED=true
PAYMENT_RECONCILIATION_INTERVAL_SECONDS=10
PAYMENT_RECONCILIATION_BATCH_SIZE=100
PAYMENT_RECONCILIATION_STARTUP_GRACE_SECONDS=30
PAYMENT_RECONCILIATION_STALE_AFTER_SECONDS=60
LND_REST_URL=https://lnd.internal.example.net:8080
LND_CERT_PATH=/run/secrets/lnd-tls-cert
LND_MACAROON_PATH=/run/secrets/lnd-invoice-macaroon
LND_INVOICE_HMAC_KEY=<64-lowercase-hex-characters>
SECRET_KEY=<random-application-value-of-at-least-32-characters>
TOKEN_HASH_KEY=<distinct-random-value-of-at-least-32-characters>
RELAY_SECRET=<distinct-random-value-of-at-least-32-characters>
ADMIN_TOKEN=<random-Crockford-token-of-at-least-32-characters>
CA_DIR=/var/lib/blindport/ca
LEGACY_CLIENT_CERT_ISSUANCE_ENABLED=false
IP_MONTHLY_SATS=7500
IP_YEARLY_SATS=75000
PORT_MONTHLY_SATS=1500
PORT_YEARLY_SATS=15000
RELAY_MONTHLY_SATS=3000
RELAY_YEARLY_SATS=30000
BILLING_YEARLY_ENABLED=false
IP_ENABLED=true
IP_SALES_PAUSED=false
PORT_ENABLED=true
PORT_SALES_PAUSED=false
RELAY_ENABLED=true
RELAY_SALES_PAUSED=false
RELAY_MANAGED_DOMAIN_CAP=25
RELAY_CUSTOMER_DOMAINS_ENABLED=true
ACCOUNT_MAX_NON_CANCELLED_SUBSCRIPTIONS=20
ACCOUNT_MAX_OPEN_PAYMENTS=5
TOKEN_BYTES=16
DEBUG=false
```

Keep database credentials, the LND macaroon, `LND_INVOICE_HMAC_KEY`,
`SECRET_KEY`, `TOKEN_HASH_KEY`, `RELAY_SECRET`, `ADMIN_TOKEN`, and CA private
key in the deployment secret store. These five security credentials must be
distinct in production. Changing `TOKEN_HASH_KEY` invalidates all stored account
and admin bearer tokens. The relay receives only `RELAY_SECRET`.
Generate the invoice key with `openssl rand -hex 32`. Use the same value on every
API replica and retain it with database backups. Do not rotate or remove it while
a pending Lightning payment lacks a locally bound invoice. Validation errors
identify invalid fields but do not include their values.

Use a dedicated LND macaroon restricted to the three RPCs the adapter calls:
`/lnrpc.Lightning/GetInfo`, `/lnrpc.Lightning/AddInvoice`, and
`/lnrpc.Lightning/LookupInvoice`. Do not mount `admin.macaroon`. Keep LND REST on
a private network or VPN and restrict its listener to the control host.

Run migrations as a one-shot deployment job before starting or replacing API
replicas:

```sh
blindport-migrate upgrade
blindport-migrate current --check
```

Do not enable `DATABASE_MIGRATE_ON_STARTUP` in production. Every API replica
verifies the migration revision during startup and readiness.

Monthly terms grant exactly 30 service days and yearly terms grant exactly 365
service days. A subscription snapshots both configured prices when it is created.
Each payment then snapshots its selected term, amount, and period length, and
settlement uses only that payment snapshot. Changing prices or the subscription's
preferred term cannot alter an already-created invoice. Revision `0009` backfills
existing subscriptions and payments as monthly, derives each existing yearly
price as ten times its monthly snapshot, and retains server-side defaults for a
prior backend during a rolling deployment. Deploy the migration before new API
replicas and set all six price variables consistently on every replica. Keep
`BILLING_YEARLY_ENABLED=false` while any prior backend replica can serve traffic,
because prior code settles every payment as 30 days. After every old API and
reconciliation worker is drained, set the flag to `true` on all new replicas.
Every yearly price must equal exactly ten times its corresponding monthly price.

Revision `0011` adds optional encrypted expiration reminder preferences and a
provider-neutral outbox. Revision `0013` upgrades deployed `0012` databases to the
generic SMTP schema. Keep `REMINDER_EMAIL_ENABLED=false` through that migration. To
enable it, configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY=starttls|tls`,
`SMTP_FROM_EMAIL`, and `SMTP_TIMEOUT_SECONDS`. Configure `SMTP_USERNAME` and the
file-backed `SMTP_PASSWORD` together, or omit both for a trusted relay. Production
requires TLS. Recipient addresses use the rotatable credential keyring with a
distinct AES-GCM AAD purpose, and the database stores no recipient, subject, or body
plaintext. SMTP acceptance marks a delivery sent. Definitive transient rejections
retry with bounded backoff; permanent rejections fail. Disconnects or timeouts after
the SMTP send boundary become terminal `delivery_ambiguous` records so the same
message is not sent twice. A stale `sending` lease is recovered the same way.
Disabling reminders cancels only queued work and cannot retract an in-flight send.
Revision `0013` permanently scrubs the retired delivery fields. Its downgrade is a
schema no-op for the rewritten publication chain and does not make a deployed
pre-`0013` application compatible; restore the matching pre-migration backup to roll
back to that image.

Revision `0012` adds idempotent Docker agent orders and uniquely links their
optional initial NWC payment before wallet access. Deploy the migration before
the backend, then deploy continuously reconciling agents. Older agents continue
to use existing subscriptions. Treat authority to deploy labeled containers as
spending authority for NWC-enabled accounts, enforce wallet-side budgets, and
prefer a narrowly authorized Docker socket proxy.

## Inventory

Configure dedicated and shared inventory consistently on the backend and relay:

```text
backend: RELAY_PUBLIC_IPS=203.0.113.11,203.0.113.12
backend: RELAY_SHARED_IPS=203.0.113.10
backend: RELAY_SHARED_TCP_PORTS=10000-10007
backend: RELAY_SHARED_UDP_PORTS=10000-10007
backend: RELAY_CONTROL_URL=relay-primary.example.net:5443
backend: RELAY_CONTROL_URLS=relay-a.example.net:5443,relay-b.example.net:5443

relay:   BLINDPORT_RELAY_IPS=203.0.113.11,203.0.113.12
relay:   BLINDPORT_RELAY_SHARED_IPS=203.0.113.10
relay:   BLINDPORT_RELAY_SHARED_TCP_PORTS=10000-10007
relay:   BLINDPORT_RELAY_SHARED_UDP_PORTS=10000-10007
relay:   BLINDPORT_RELAY_HTTP_CHALLENGE=:80
```

The dedicated and shared lists must be disjoint. Bind all addresses on the
relay host before starting the process. The relay validates lists and ranges,
requests certificate SANs for both IP sets, and pre-binds every control,
dedicated, shared-port, and SNI listener. Any bind failure aborts startup and
closes listeners already opened during that attempt.

Relay control endpoints use strict `host:port` syntax without a URL scheme or
path. DNS names and IP literals are canonicalized, IPv6 uses `[address]:port`,
scoped IPv6 addresses are rejected, and canonical duplicates in
`RELAY_CONTROL_URLS` are removed. An empty `RELAY_CONTROL_URLS` uses the
primary `RELAY_CONTROL_URL` value. Framed Blindport IP and Blindport Port receive only that
primary endpoint.

The default control endpoint is now `relay:5443`. Existing settings using URL
syntax, such as `http://relay:9000`, must migrate to a plain `host:port` value;
URL-scheme compatibility is intentionally not provided.

### Routed WireGuard inventory

Routed Blindport IP is optional. Allocate IPv4 addresses that the hosting provider
routes to the relay host, then configure a pool disjoint from every framed and
shared listener address:

```text
backend: WIREGUARD_PUBLIC_IPS=198.51.100.20,198.51.100.21
backend: WIREGUARD_RELAY_PUBLIC_KEY=<relay-public-key>
backend: WIREGUARD_ENDPOINT=relay-primary.example.net:51820
backend: WIREGUARD_MTU=1420
backend: WIREGUARD_PERSISTENT_KEEPALIVE_SECONDS=25
backend: WIREGUARD_RECONCILE_INTERVAL_SECONDS=10
backend: WIREGUARD_RECONCILE_MAX_STALENESS_SECONDS=90

relay:   BLINDPORT_RELAY_WIREGUARD=1
relay:   BLINDPORT_RELAY_WIREGUARD_INTERFACE=bpwg0
relay:   BLINDPORT_RELAY_WIREGUARD_KEY_FILE=/run/secrets/blindport-wireguard-key
relay:   BLINDPORT_RELAY_WIREGUARD_PORT=51820
relay:   BLINDPORT_RELAY_WIREGUARD_MTU=1420
relay:   BLINDPORT_RELAY_WIREGUARD_INTERVAL=10s
relay:   BLINDPORT_RELAY_WIREGUARD_MAX_STALENESS=90s
```

Generate and persist the relay key with standard WireGuard tooling, expose only
the public key to the backend, and keep the private key file regular,
owner-only, and stable across restarts. The
`BLINDPORT_RELAY_WIREGUARD_KEY` environment value exists for development only.
Enable IPv4 forwarding on the relay host and route every configured address to
that host, but do not bind those addresses to relay listener interfaces. The
relay installs active `/32` link routes and blackholes all other managed
inventory. Do not add SNAT or DNAT; preserving both endpoint addresses is part
of the routed product contract.

The relay retains the last good desired state during short backend failures. At
maximum staleness it removes all peers, blackholes the full pool, and fails
readiness until a valid snapshot is applied. A process with no successful
startup snapshot fails closed immediately, persistent kernel apply failures use
the same staleness limit, and graceful shutdown waits for the routed plane to
fail closed. Keep
`RESOURCE_REUSE_QUARANTINE_SECONDS` strictly greater than maximum staleness plus
one reconcile interval. Current support is one relay key and endpoint, IPv4
`/32` inventory, and no BGP automation. Provider routing and relay failover are
operator responsibilities.

Each backend transport pool uses one inclusive decimal range. Ports must be within
`1-65535`, ordered, and no more than 4096 entries. Keep pools much smaller when
each port is a separate listener.

## DNS

Use a normal HTTPS name for the backend. Blindport IP and Blindport Port clients use
assigned socket identities and do not require DNS. Blindport Relay supports three
operating models:

1. **Managed wildcard:** set a strict comma-separated suffix list such as
   `RELAY_MANAGED_SUFFIXES=relay.example.net`. Publish wildcard A/AAAA or
   CNAME records beneath each suffix toward the SNI ingress. Customer leases
   may be nested below the suffix, but the suffix apex itself is reserved and
   rejected.
2. **Customer-owned CNAME verification:** a non-apex customer subdomain receives
   a unique target such as `<32-lowercase-hex>.pool.example.net` at subscription
   creation. The customer publishes one CNAME from the canonical requested
   hostname to that exact target. Blindport checks automatically when creating
   each initial or renewal invoice;
   `POST /api/v1/subscriptions/{public_id}/verify-domain` remains available for immediate
   feedback before paying. Configure
   `RELAY_DOMAIN_CLAIM_TTL_SECONDS` to bound unpaid name holds and
   `RELAY_DNS_TIMEOUT_SECONDS` to bound each recursive lookup. The initial
   deadline also applies to provider-managed and successfully verified unpaid
   claims; verification does not extend it. Existing pending rows with a TXT
   token continue using their returned `_blindport-challenge.<hostname>` TXT
   record only until the existing claim deadline. New claims have no TXT token.
3. **Future registrar or authoritative-DNS automation:** an integration may
   publish the required records and use the same control-plane API. Blindport
   does not currently implement this automation.

### Blindport Relay certificates

Blindport Relay does not terminate customer TLS. Each customer origin must obtain and
retain the certificate for its leased hostname. Customer-owned names can use
their normal DNS-01 workflow. Managed names can use the optional HTTP-01 path:

1. Activate and pay for the Blindport Relay subscription.
2. Run `blindportd` with both the TLS `upstream` and a separate plaintext
   `http_challenge_upstream`.
3. Configure the origin ACME client to answer HTTP-01 on that second upstream.
4. Test with the CA staging directory before requesting a production certificate.

The relay accepts only bounded HTTP/1.1 `GET` requests with canonical domain Host
headers. It forwards `/.well-known/acme-challenge/<token>` to the dedicated
challenge upstream, processes one response, and closes the connection. Other valid
paths receive a bodyless same-host `308` redirect to HTTPS and are never forwarded.
HTTP ingress is rate limited, but Blindport cannot determine whether a CA issued a
certificate and does not enforce an issuance count. Operators must account for CA
limits across all managed names. Let's Encrypt currently documents a limit of 50
new certificates per registered domain per seven days; keep `RELAY_MANAGED_DOMAIN_CAP`
conservative and prefer customer-owned domains as usage grows.

The backend is a recursive DNS client, not an authoritative DNS server. Give it
access to a trustworthy recursive resolver over the network, and monitor `502`
or `503` verification responses as resolver failures. It queries the direct
CNAME record with resolver search disabled and a configured total lifetime.
NXDOMAIN, missing CNAME answers (including A/AAAA flattening), nonmatching direct
targets (including chains and alternate pool names), and lookup timeouts are
ordinary unsuccessful verification results and do not create payments.

For every `RELAY_POOL_DOMAINS` base, publish wildcard A/AAAA or CNAME ingress
records for its generated children. A pool base can contain at most 220 ASCII
characters so the generated 32-character label and separator remain a valid DNS
hostname. The allocator balances retained apex assignments and child targets by
their configured base.

An active Blindport Relay subscription loses authorization exactly at
`current_period_end`. Its domain remains reserved to that subscription until
`RELAY_RENEWAL_GRACE_SECONDS` after the period end (seven days by default,
configurable from 136 seconds to 30 days). Creating a renewal invoice rechecks
the exact assigned CNAME. The owner must create and settle renewal payment before
that deadline. Lazy
reaping reconciles open Lightning and NWC payments before cancellation, then
clears the domain, verification state, and relay-pool metadata only when no open
payment remains. Provider-check failures and `PROCESSING` payments retain the
claim for operator reconciliation. Any later claimant starts the managed or
customer-owned verification flow from the beginning.

For DNS active-active Blindport Relay ingress, publish multiple healthy relay targets
with low TTLs and include every advertised edge in
`RELAY_CONTROL_URLS`. The agent opens an independent claim tunnel to each
provisioned edge. DNS is not a health-aware load balancer and does not preserve
existing TCP sessions when an answer or edge changes. Advertising an edge that
is absent from provisioning can direct traffic to a node without the tunnel.
Dedicated Blindport IP and shared Blindport Port failover still need routing or address
movement outside Blindport.

## Firewall

| Surface | Protocol | Required access |
| --- | --- | --- |
| backend API (8000 or reverse-proxied 443) | TCP | users and relays |
| Blindport Relay HTTP redirect and HTTP-01 listener | TCP 80 | public HTTP clients and ACME validators |
| relay control (default 5443) | TCP with mutual TLS | blindportd clients |
| dedicated Blindport IP listener ports | TCP | public clients |
| shared Blindport Port TCP range | TCP | public clients |
| shared Blindport Port UDP range | UDP | public clients |
| Blindport Relay SNI listener | TCP/TLS passthrough | public clients |
| routed WireGuard endpoint (default 51820) | UDP | blindportd clients |
| routed Blindport IP inventory | IPv4, any transport | public clients |
| relay admin (default 127.0.0.1:9090) | HTTP | private probes and Prometheus only |
| Nutshell mint (when used) | TCP/HTTPS | backend and wallet path as deployed |

Keep the relay admin listener on loopback or a private management network. It
does not authenticate requests and must not be exposed publicly. Relay probes
and metrics are:

- `GET /livez` reports process liveness.
- `GET /readyz` requires bound relay listeners, a current server certificate
  outside `BLINDPORT_RELAY_CERT_READY_MARGIN`, and usable backend authorization.
  Backend infrastructure failures retain readiness only until
  `BLINDPORT_RELAY_REAUTH_MAX_STALENESS`; a rejected relay secret fails readiness
  immediately. When WireGuard is enabled it also requires a successfully
  applied desired-state snapshot. Shutdown marks readiness unavailable before
  draining handlers.
- `GET /metrics` exposes fixed-cardinality Prometheus counters and gauges. Labels
  contain listener, claim kind, direction, or fixed outcomes, never claim IPs,
  domains, user IDs, or tokens.
  Routed gauges report configured peers and active prefixes without exposing
  keys or leased addresses.

Backend probes are:

- `GET /api/v1/health/live` reports process liveness without checking dependencies.
- `GET /api/v1/health/ready` checks `SELECT 1`, the Alembic migration head, the
  configured direct Lightning adapter, and reconciler freshness whenever the
  worker is enabled (it is required in production). The reconciler reports
  `starting` during its bounded startup grace and returns `503` if it has never
  completed by then or its last completed cycle is stale.
- `GET /api/v1/health` remains compatible and has the same readiness semantics
  as `/api/v1/health/ready`.

Probe responses contain component names and status values only. Compose uses the
explicit readiness path to order development services.

Set relay concurrency controls according to host capacity. Defaults are 256
concurrent control handshakes, 4096 total ingress connections or UDP source
associations, 512 concurrent
SNI inspections, 8 control handshakes per direct source IP, 128 ingress
connections per direct source IP, and 256 streams per tunnel. Configure these
with `BLINDPORT_RELAY_MAX_CONTROL_HANDSHAKES`, `BLINDPORT_RELAY_MAX_INGRESS`,
`BLINDPORT_RELAY_MAX_SNI_PEEKS`, `BLINDPORT_RELAY_MAX_CONTROL_PER_SOURCE`,
`BLINDPORT_RELAY_MAX_INGRESS_PER_SOURCE`, and
`BLINDPORT_RELAY_MAX_STREAMS_PER_TUNNEL`. All limits are fail-fast startup
settings. Per-source state lasts only while the admitted handshake or ingress
connection or UDP association is active. UDP associations expire after
`BLINDPORT_RELAY_UDP_ASSOCIATION_IDLE` (two minutes by default, bounded from one
second to one hour), and each has a bounded 32-datagram ingress queue.
Queued payload is additionally capped at 512 KiB per association and per tunnel
stream, so maximum-size datagrams reach the byte limit before the item limit.

Per-source limits use the direct TCP or UDP peer address with IPv4-mapped IPv6
normalized to IPv4. They do not trust forwarded HTTP headers. Behind a TCP proxy
the proxy is the observed source, and large NAT populations share one source
budget. Adjust these limits for that topology; Blindport does not currently parse
the PROXY protocol.

HTTP ingress adds the backward-compatible `BLINDPORT_RELAY_MAX_HTTP_CHALLENGES`,
`BLINDPORT_RELAY_HTTP_CHALLENGE_RATE`, and
`BLINDPORT_RELAY_HTTP_CHALLENGE_BURST` settings. The rate counts valid redirect and
challenge requests per minute per direct peer, not certificate issuances. Behind
one L7 frontend, all requests share that frontend's allowance.

`BLINDPORT_RELAY_SHUTDOWN_TIMEOUT` defaults to 15 seconds. On `SIGINT` or
`SIGTERM`, the relay stops accepting traffic, closes every registered tunnel,
drains tracked handlers up to that timeout, and then shuts down the admin
server. Set the container stop grace period above the relay timeout.

## Certificates and secrets

Terminate public HTTPS for the backend with a conventional reverse proxy. User
traffic through framed Blindport IP, TCP Blindport Port, or Blindport Relay is raw TCP; any
user-facing TLS certificate belongs on the user's upstream. UDP Blindport Port
forwards complete datagrams without terminating an application protocol.
Routed Blindport IP forwards IP packets without terminating or inspecting application
protocols.

The backend mini-CA protects client-to-relay control connections. Persist the
production PostgreSQL database and `CA_DIR`, restrict the CA private key, and set
the relay's `BLINDPORT_RELAY_SECRET` to the backend's dedicated `RELAY_SECRET`.
That secret protects relay-to-backend resolution and certificate issuance, so it
must not be exposed to clients. Relay certificate requests are restricted to
configured control endpoint hostnames and inventory addresses.

Public signup and browser/admin login use process-local fixed-window limits. They
trust the ASGI client address and HMAC it with a per-process key. Buckets stop
enforcing at the end of the window and are removed on a subsequent direct-limit
check; they are never written to the database.
Expose the backend only through a proxy whose forwarded-address handling is
explicitly trusted. The application never parses arbitrary forwarded headers
itself. Payment creation, domain verification, and client certificate enrollment
use durable account-derived limits. Per-account subscription and open payment
limits remain authoritative across source addresses.

Hosted Blindport access logging is disabled at HAProxy, Caddy, and Uvicorn. Relay
logs use fixed event and claim-kind fields rather than visitor addresses, leased
addresses, domains, or account identifiers. Production containers use journald,
and the host must install `deploy/journald-blindport.conf` to delete operational
logs within 30 days. Source addresses still exist transiently in sockets, active
admission state, tunnel metadata, routed packets, and customer-controlled origins.

Production requires `LEGACY_CLIENT_CERT_ISSUANCE_ENABLED=false`. Current agents
enroll a locally generated Ed25519 key through the v2 CSR endpoint and retain it
under `BLINDPORT_STATE_DIR`. Place that directory on persistent secret storage
with mode `0700`; the credential file is mode `0600`. Use one state directory
and daemon per account. Back it up separately from the backend database. The
backend stores only public credential data.

Renewal reuses the enrolled key and advances an idempotent generation. A valid
persisted credential can load while the backend is unavailable, although the
current agent still needs the backend to fetch subscription provisioning at
startup. If the state key is lost, stop the daemon and remove that user's
`clientcredential` row through controlled operator maintenance before enrolling
a replacement. This immediately excludes any mismatched WireGuard peer from
relay desired state, and the new identity can replace it with a signed
generation-1 enrollment. This is intentionally not a bearer-token API
operation.

The v0 relay validates the account CN but does not yet reauthorize certificate
serials. Deleting or replacing a credential row therefore prevents token-only
reenrollment but does not revoke previously issued leaves. Rotate the account
bearer credential through controlled operator maintenance, or rotate CA trust,
when immediate device cutoff is required.

Development-only switches `BLINDPORT_RELAY_DISABLE_MTLS=1` and
`BLINDPORT_INSECURE_SKIP_TLS=1` remove tunnel transport authentication and must not
be used for production.

## Database migrations

SQLite remains the default for the local single-process stack. Production can
use PostgreSQL through psycopg 3, for example:

```text
DATABASE_URL=postgresql+psycopg://blindport:secret@postgres.example.net/blindport
```

Alembic revisions ship inside the installed Python package. Inspect or upgrade
the configured database with:

```sh
blindport-migrate current --check
blindport-migrate upgrade
```

`DATABASE_MIGRATE_ON_STARTUP` defaults to `true` for local and single-process
development compatibility. A production deployment with multiple API replicas
must run exactly one migration job before rolling out the application, then set
`DATABASE_MIGRATE_ON_STARTUP=false` on every replica. Disabled startup migration
still verifies that the database is at this build's migration head and refuses
to serve unless the revisions match exactly. Consequently, an old application
image also refuses to run against a newer schema.

Pre-Alembic prototype SQLite volumes are unsupported. Discard them and start
with a fresh database. Do not
stamp an old volume as current because its schema has not been migration-tested.

The product namespace rename is also a clean break. Do not reuse a pre-rename
database, CA directory, agent state directory, browser storage, environment
configuration, or Docker labels. No compatibility migration or fallback is
provided, and a pre-rename database may carry the same Alembic revision while
containing incompatible enum values. Provision fresh state for Blindport.

Python 3.11 remains the minimum runtime, but dependency locks are generated and
compared only with Python 3.14. Building the pinned `coincurve` source archive
on Debian or Ubuntu requires `build-essential`, `libffi-dev`, and `pkg-config`.

## Capacity and concurrency

Capacity is reserved before payment adapter calls. Alert on `409` payment
responses and expand the matching inventory on both backend and relay before
selling more leases. Reservation duration is bounded by
`RESOURCE_RESERVATION_TTL_SECONDS` (60 seconds to 24 hours).

Set relay `BLINDPORT_RELAY_REAUTH_INTERVAL` and
`BLINDPORT_RELAY_REAUTH_MAX_STALENESS` as Go durations such as `45s` and `90s`.
Maximum staleness must be at least one interval. Set backend
`RESOURCE_REUSE_QUARANTINE_SECONDS` so it strictly exceeds maximum staleness plus
one reauthorization interval:

```text
RESOURCE_REUSE_QUARANTINE_SECONDS >
  BLINDPORT_RELAY_REAUTH_MAX_STALENESS + BLINDPORT_RELAY_REAUTH_INTERVAL
```

The defaults are 180 seconds, 90 seconds, and 45 seconds respectively. This
ordering prevents a newly assigned customer from sharing an identity with an
old tunnel retained during a backend outage.

When the reuse deadline elapses, the resource reaper checks any open renewal
payment before clearing the assignment. A settled payment reactivates it;
pending, processing, or uncertain provider state retains the assignment until
the payment reaches a state that permits safe release.

The active-expiry Blindport Relay renewal hold is also the domain handoff quarantine.
`RELAY_RENEWAL_GRACE_SECONDS` defaults to seven days and cannot be below
136 seconds, which is strictly greater than the documented 90-second
stale-authorization default plus one 45-second reauthorization interval. It
reserves the name only and does not extend relay authorization. Periodic relay
reauthorization removes an expired
claim from an established tunnel on the next successful check, subject only to
the configured maximum staleness during backend errors.

External Lightning invoices are capped by the remaining resource reservation or
Blindport Relay claim/renewal eligibility. `PAYMENT_EXPIRY_SAFETY_SECONDS` (15
seconds by default) is removed before requesting an invoice, and windows below
`PAYMENT_MIN_PAYABLE_SECONDS` (30 seconds by default) are rejected. This is an
invoice safety interval, not settlement grace. With LND it must be at least the
configured request timeout. When LND completes within that timeout, this keeps
provider-side invoice creation within local eligibility. Preflight lookup time
is deducted from the relative expiry sent to LND, and the bound local deadline
follows LND's remaining invoice lifetime without exceeding eligibility. The
reaper still reconciles the provider at the deadline before allowing a domain
handoff. Domain claim, renewal, and resource reservation settings must each be
longer than the minimum payable duration plus this safety interval.

The timeout bound assumes LND stops or completes `AddInvoice` within the client
request timeout. An intermediary or provider operation that continues after the
client has timed out remains ambiguous until lookup by payment hash finds it.
Alert on repeatedly unbound outbox rows and investigate LND or proxy latency
before their local deadlines elapse.

Each backend replica promptly runs a background scan, then runs at the fixed
`PAYMENT_RECONCILIATION_INTERVAL_SECONDS` rate. A cycle selects at most
`PAYMENT_RECONCILIATION_BATCH_SIZE` pending Lightning or NWC payments in payment
ID order. Provider state is checked before local expiry, and failures are logged
per payment without stopping later rows. Disabled methods are excluded before
the batch limit is applied. Keep the stale threshold at least twice the interval,
and alert on an unavailable `reconciler` readiness component. The settings are
bounded to prevent accidental hot loops, unbounded scans, and ineffective
freshness probes.

All replicas may run the scan. No leader election or distributed lock is
required: the conditional payment transition and subscription update are one
database transaction, so concurrent settlement attempts credit one billing
period using that payment's snapshotted day count. Production still requires
PostgreSQL for this multi-replica model.

Invoice creation commits a durable outbox row before LND is called. The row owns
capacity and contains a random UUID, expected payment hash, and bounded local
deadline. Its preimage is derived with `LND_INVOICE_HMAC_KEY`. LND is queried by
hash before add and after an ambiguous add failure; recovered invoice amount,
memo, and hash are verified before the BOLT11 string is bound locally. Same-method
API retries return the original open payment. An unavailable provider returns
`502` while retaining the row for the background reconciler. Never change the
HMAC key on only part of a replica set. PostgreSQL serializes issuance, expiry,
and binding for each payment row across replicas. Drain or resolve unbound
pending invoices before coordinated key rotation.

SQLite is suitable only for the single-process experimental stack. Use
PostgreSQL for concurrent production API workers; partial unique indexes and
transactional candidate retries arbitrate allocation conflicts between them.

NWC uses the compiled `/usr/local/bin/blindport-nwc-helper`, which handles one
bounded JSON request on stdin and one bounded JSON response on stdout. It accepts
only strict `nostr+walletconnect://` URIs with lowercase 32-byte wallet and secret
keys, one or more `wss` relays, and only `relay`, `secret`, and optional `lud16`
query fields. Before validation, payment, or lookup, it requires `nip44_v2`,
`pay_invoice`, and `lookup_invoice`; NIP-04 fallback is never allowed.

To enable NWC, retain `lightning` in `PAYMENT_ENABLED_METHODS`, set
`PAYMENT_NWC_ADAPTER=nwc`, add `nwc` to the allowlist, and install
`CREDENTIAL_ENCRYPTION_KEY` as a file-backed secret. The value is one or more
comma-separated, distinct 32-byte keys encoded as 64 lowercase hexadecimal
characters. The first key encrypts; key fingerprints select older keys for
decryption. Keep old keys until all credentials have been rewritten under the
new primary. Never reuse the invoice HMAC key or another application secret.
Set `NWC_ALLOWED_RELAY_HOSTS` to an exact comma-separated list of trusted relay
hostnames. Wildcards are not accepted. This bounds the helper's outbound WebSocket
connections to standard `wss` port 443 and must include every relay used by customer
NWC credentials.

NWC credentials are AES-256-GCM encrypted with a random 96-bit nonce. The public
account UUID and credential purpose are authenticated as AAD. Migration `0010`
revokes all pre-production plaintext values, retains the legacy `nwc_uri` column
only for rolling old-backend reads, and prevents old replicas from restoring a
non-null value. API responses expose only connection status, capabilities, and
last validation time.
Credential replacement and deletion are blocked while an NWC payment is open, because
safe lookup must retain the same wallet connection generation used for the attempt.

Blindport's LND invoice and payment hash are authoritative. Every NWC cycle checks
LND first. After an attempted send, the backend performs NWC lookup before any
retry. Pending, settled, unsupported, timed-out, or otherwise inconclusive lookup
never resends. Only explicit outgoing `failed` or `not_found`, while LND remains
open and backoff/attempt bounds permit it, can authorize another send. Definitive
wallet quota, restriction, authorization, expiry, and insufficient-balance
rejections of the pay request disable automatic renewal. Invalid hashes,
preimage mismatches, transport failures, malformed post-send responses, and
lookup errors remain pending for LND and wallet reconciliation and never release
an active subscription based only on the wallet response.
Operators should alert on long-lived `unknown` NWC states and investigate before
manually changing payment state.
Automatic renewal of a customer-owned Relay hostname also repeats its exact CNAME
check before creating the NWC invoice.

Cashu is experimental. The backend claims a payment before mint or swap and
marks uncertain external failures `FAILED`; it does not report those proofs as
recoverable. Alert on payments left `PROCESSING` after a crash and reconcile
them against the mint before changing local state. Cashu quote issuance,
minting, swapping, and token submission are rejected after local payment or
domain eligibility expires. Mint quote expiry cannot currently be bounded or
reconciled by the backend, so do not use Cashu for production domain claims.
The background reconciler intentionally never processes Cashu. Alert on
`PROCESSING` Cashu rows, which indicate an operator must determine provider state
before making any local correction; uncertain Cashu failures are never retried
automatically.

## Anonymous operation and compliance

Blindport accounts do not require identity fields, and the software can be run
without a KYC workflow. That configuration does not remove obligations imposed
by infrastructure or payment providers, abuse handling, sanctions controls,
tax rules, or applicable local law. Operators must assess those requirements for
their deployment and jurisdiction. This documentation is operational guidance,
not legal advice.

## Backups

Back up the database and `CA_DIR` together before every migration. For
PostgreSQL, take and verify a `pg_dump` backup (or a storage snapshot with an
equivalent restore test). Back up the configured payment backend or mint
according to its own recovery model. Losing the database loses lease and
payment state; losing the CA key requires tunnel certificate rotation.
Retain `SECRET_KEY`, `TOKEN_HASH_KEY`, `RELAY_SECRET`,
`LND_INVOICE_HMAC_KEY`, and every active `CREDENTIAL_ENCRYPTION_KEY` keyring
entry with the matching backup. Store encrypted copies offsite
and test restoration into an isolated environment.

Application rollback requires the database revision expected by the old image.
Stop all API replicas, then either restore the matching pre-migration database
and `CA_DIR` backup or run a downgrade that has been verified for that exact
application revision. Before `blindport-migrate downgrade <revision>`, take a
fresh backup and confirm that both the downgrade and target application support
the resulting schema. A forward schema with an old application is unsupported,
not a normal rollback state, and exact-head startup verification rejects it.

## Production manifests

The checked-in canary and split-host Compose manifests are documented in
[`deploy/OPERATIONS.md`](../deploy/OPERATIONS.md). The one-host canary uses an
SNI multiplexer and is intended for manual and invited testing. Move relay
ingress to the split relay host before unrestricted public signup.
