# Operating Blindport

## Production configuration

Set `ENVIRONMENT=production` to enable fail-fast production validation. The
production backend requires PostgreSQL through psycopg, direct Lightning through
a non-mock adapter, externally run migrations, absolute CA storage, positive
prices, and strong application and account tokens. NWC is optional alongside
mandatory direct Lightning when its helper and credential security requirements
are configured. The checked-in deployment manifests intentionally leave it
disabled. A representative baseline is:

```text
ENVIRONMENT=production
PUBLIC_SITE_URL=https://api.example.com
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
IP_YEARLY_SATS=50000
PORT_MONTHLY_SATS=1000
PORT_YEARLY_SATS=10000
RELAY_MONTHLY_SATS=2000
RELAY_YEARLY_SATS=20000
RELAY_WILDCARD_MONTHLY_SATS=5000
RELAY_WILDCARD_YEARLY_SATS=50000
WIREGUARD_SMTP_EGRESS_FEE_SATS=33333
BILLING_YEARLY_ENABLED=true
IP_ENABLED=true
IP_SALES_PAUSED=false
PORT_ENABLED=true
PORT_SALES_PAUSED=false
RELAY_ENABLED=true
RELAY_SALES_PAUSED=false
RELAY_MANAGED_DOMAIN_CAP=25
RELAY_CUSTOMER_DOMAINS_ENABLED=true
RELAY_MANAGED_DOMAIN_CLAIM_TTL_SECONDS=1800
RELAY_DOMAIN_CLAIM_TTL_SECONDS=3600
ACCOUNT_MAX_NON_CANCELLED_SUBSCRIPTIONS=20
ACCOUNT_MAX_OPEN_PAYMENTS=5
ACCOUNT_MAX_PENDING_RELAY_CLAIMS=2
BTC_USD_PRICE_ENABLED=true
BTC_USD_PRICE_REFRESH_SECONDS=300
BTC_USD_PRICE_MAX_STALE_SECONDS=1800
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

Monthly terms for Port and Relay grant exactly 30 service days, and yearly terms
grant exactly 365 service days. New Blindport IP subscriptions are WireGuard-only
and yearly-only. A subscription snapshots both configured prices when it is created.
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
`SMTP_FROM_EMAIL`, and `SMTP_TIMEOUT_SECONDS`. Configure `SMTP_USERNAME` and use
`SMTP_PASSWORD_FILE` as the file-backed operator input together, or omit both for a trusted relay. Production
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

Revision `0018` adds optional service-announcement email, separate from expiration
reminders. Set `ANNOUNCEMENT_EMAIL_ENABLED=true` only after migration `0018`, SMTP,
and `CREDENTIAL_ENCRYPTION_KEY_FILE` are installed. Addresses are separately encrypted
and never returned by the API. Administrators create a draft, review the eligible
recipient count, then queue it in a separate browser-session-authenticated action.
Campaign content is plain text, recipients are snapshotted by account and address
generation only, and the outbox stores no plaintext addresses. The SMTP safety boundary
matches expiration reminders: a send-side disconnect is terminal `delivery_ambiguous`.

Revision `0022` introduces the unified privacy-preserving notification outbox. ACCOUNT
consent covers activation, renewal, seven-day, one-day, and actual-expiry lifecycle
events; SERVICE consent covers announcements only. `notification_reconciliation` is
independent of payment reconciliation and exposes its own readiness component. It
discovers lifecycle events, drains legacy reminder and announcement rows, expands each
queued campaign in bounded snapshot pages, and delivers unified rows. SMTP acceptance
is terminal; retryable failures retry before the SMTP boundary, while interrupted or
ambiguous sends are terminal `delivery_ambiguous`. Existing legacy outboxes remain
drain-only during migration.

Revision `0023` adds passkey credentials, one-time WebAuthn challenges, and opaque
customer browser sessions. Apply `0023` before deploying this backend. Browser sessions
store only domain-separated HMAC hashes, require a matching CSRF header for mutations,
and expire after `BROWSER_SESSION_MAX_AGE_SECONDS`; rotating `SECRET_KEY` revokes every
customer browser session and pending WebAuthn ceremony. Bearer tokens remain unchanged
for agents, API clients, and account recovery, but are kept only in browser local storage
and are never embedded in dashboard HTML or returned by passkey authentication.

Keep `PASSKEYS_ENABLED=false` for the schema and application rollout. Set
`WEBAUTHN_RP_ID` to the exact public API hostname, `WEBAUTHN_ORIGIN` to the canonical
HTTPS `PUBLIC_SITE_URL`, and `WEBAUTHN_RP_NAME` to the user-visible service name on every
API replica. All replicas must share PostgreSQL and `SECRET_KEY`. After old API replicas
are drained and registration plus discoverable authentication have been tested on the
public origin, enable passkeys on every replica together. Passkeys remain unavailable on
the onion origin; token login continues to work there. A downgrade to `0022` deletes all
passkeys and browser sessions, so rollback should normally restore the matching
pre-migration database backup instead.

Revision `0024` replaces separate reminder and announcement recipient preferences with
one explicitly consented encrypted notification recipient. It does not infer consent from
the retired columns and cancels queued legacy and unified deliveries during cutover. Stop
old API and notification workers before the migration and do not run them against the new
schema. The downgrade recreates empty legacy preference columns but cannot reconstruct the
old encrypted recipients; restore the matching backup for a pre-`0024` application rollback.

Revision `0025` adds the latest per-edge subscription connection observation. Deploy the
new backend before new Relays. Legacy Relays omit the optional snapshot and leave connection
observations unchanged. New Relays report at most 1,000 sorted active public subscription IDs;
an explicit truncation marker prevents omitted IDs from being treated as disconnected. Roll
back Relays before the backend because older backends reject the new strict heartbeat fields.

Offline entitlement provisioning is disabled by default. The v2 endpoint returns an
edge-specific signed artifact and an identical explicit claim object, so agents can build
plans without decoding the artifact. Enable it only after all relays and agents support the
format: configure a dedicated owner-only, unencrypted Ed25519 PKCS#8 PEM at an absolute
`OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE`, a stable `OFFLINE_ENTITLEMENT_KEY_ID`, and canonical
`RELAY_EDGES` JSON mapping every configured control endpoint to one stable edge ID. The PEM
is mounted only on API backends. With the default `OFFLINE_ENTITLEMENT_GRACE_SECONDS=604800`,
set `RESOURCE_REUSE_QUARANTINE_SECONDS` and `RELAY_RENEWAL_GRACE_SECONDS` to at least
`604921` before setting `OFFLINE_ENTITLEMENTS_ENABLED=true`; both constraints are strictly
greater than grace plus 120 seconds. The ordinary disabled defaults remain 180 seconds and
seven days. Roll out support with the feature flag false, drain old API replicas, verify every
edge mapping, then enable in a separate configuration rollout.

Each Relay uses the corresponding stable edge ID as `RELAY_EDGE_ID`, the same approved
grace limit as `OFFLINE_ENTITLEMENT_MAX_GRACE_SECONDS`, and the canonical JSON public
keyring in `OFFLINE_ENTITLEMENT_PUBLIC_KEYS`. Set
`OFFLINE_ENTITLEMENTS_ENABLED=false` until the separate Relay enablement rollout. The
Relay receives no signer or private key. Its fallback admits only a v2 account certificate
with one exact `urn:blindport:client:<canonical-uuid>` URI SAN and its bound signed
artifact, and only for typed backend infrastructure failures.
Set `BLINDPORT_RELAY_CERTIFICATE_CACHE_DIR` to an absolute canonical persistent directory
owned by the Relay process with mode `0700`. The Relay fetches and validates online
certificate material first, then atomically stores `certificate.json` with mode `0600`.
On restart it reads that cache only after a typed backend infrastructure failure. Bad Relay
secrets, protocol errors, malformed successful responses, changed exact DNS/IP SANs,
expired certificates, unsafe files, and changed certificate authorities remain terminal.
The official Compose definitions mount `/var/lib/blindport` as the `relay-state` volume.
Treat that volume as private key material and include it in protected edge-state backups.
Set one stable `RELAY_EDGE_ID` per Relay and keep the default 30-second
`BLINDPORT_RELAY_HEARTBEAT_INTERVAL`. Generate one unique 32-byte token per edge. Mount only
that edge's token through `BLINDPORT_RELAY_HEARTBEAT_TOKEN_FILE`, and mount the canonical
edge-to-token JSON map only on the backend through `RELAY_HEARTBEAT_KEYS_FILE`. The Relay posts
fixed-cardinality readiness and aggregate counters plus a bounded active subscription-presence
snapshot through the secret-authenticated control API. The presence snapshot contains public
subscription IDs but no source addresses, upstream addresses, domains, or traffic content. The
backend retains only the latest health row and per-subscription observation for each configured
edge. Heartbeat failures never alter Relay readiness; admin fleet and connection state becomes
stale after `RELAY_HEARTBEAT_STALE_SECONDS`.
When `BANDWIDTH_METRICS_ENABLED=true` on the backend and
`BLINDPORT_RELAY_BANDWIDTH_METRICS=true` on each edge, authenticated cumulative reports produce
UTC-day inbound and outbound totals. Retained subscription/day totals support customer and product
reporting. Separate edge/day totals support the admin VPS view without retaining an
edge-to-subscription relationship. Both aggregate tables follow `BANDWIDTH_RETENTION_DAYS`; the
short-lived edge, boot, and subscription cursors remain only for deduplication and migration `0031`
uses those available cursors to seed recent edge totals.
This fallback is limited to framed tunnels. It does not alter routed WireGuard,
which continues using its enrolled desired-state reconciliation path and never
uses an entitlement cache or proof. Framed agents refresh provisioning every 30
seconds (or at the Docker discovery interval), retain the last plan through a
typed infrastructure failure only while a valid signed artifact remains within
its grace period, and remove workers on an online denial or malformed
authoritative response.

Revision `0012` adds idempotent Docker agent Relay and Port orders and uniquely links their
optional initial NWC payment before wallet access. Deploy the migration before
the backend, then deploy continuously reconciling agents. Older agents continue
to use existing subscriptions. Treat authority to deploy labeled containers as
spending authority for NWC-enabled accounts, enforce wallet-side budgets, and
prefer a narrowly authorized Docker socket proxy.

## Inventory

Configure shared inventory consistently on the backend and relay. Configure the
dedicated listener list only while historical framed IP records remain active:

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

`RELAY_PUBLIC_IPS` and `BLINDPORT_RELAY_IPS` are legacy framed-service settings,
not current sale inventory. The dedicated and shared lists must be disjoint. Bind
all addresses on the relay host before starting the process. The relay validates lists and ranges,
requests certificate SANs for both IP sets, and pre-binds every control,
dedicated, shared-port, and SNI listener. Any bind failure aborts startup and
closes listeners already opened during that attempt.

Relay control endpoints use strict `host:port` syntax without a URL scheme or
path. DNS names and IP literals are canonicalized, IPv6 uses `[address]:port`,
scoped IPv6 addresses are rejected, and canonical duplicates in
`RELAY_CONTROL_URLS` are removed. An empty `RELAY_CONTROL_URLS` uses the
primary `RELAY_CONTROL_URL` value. Historical framed Blindport IP and current
Blindport Port retain that primary endpoint for older agents. Current agents also consume provider-edge
assignments when configured as described below.

The default control endpoint is now `relay:5443`. Existing settings using URL
syntax, such as `http://relay:9000`, must migrate to a plain `host:port` value;
URL-scheme compatibility is intentionally not provided.

### Routed WireGuard inventory

WireGuard is required whenever Blindport IP sales are enabled. Allocate IPv4
addresses that the hosting provider routes to the relay host, then configure a
pool disjoint from every historical framed and shared listener address:

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

Blindport IP is WireGuard-only and annual-only. Keep
`BILLING_YEARLY_ENABLED=true` whenever IP sales are offered. Existing issued
payment snapshots remain settleable, but historical framed or monthly IP
subscriptions cannot create another payment or renewal.

The relay image includes nftables and owns only the `inet blindport` table. It
atomically replaces that table during desired-state reconciliation. Do not create
an operator table with the same family and name. Keep the host's independent
INPUT, FORWARD, and OUTPUT policy in separate tables; Blindport policy does not
replace later operator policy. It blocks customer access to the relay host,
non-global IPv4 destinations, invalid leased sources, and outbound TCP port 25
without an approved exception. Return traffic for established inbound sessions
remains allowed.

`BLINDPORT_RELAY_WIREGUARD_ALLOW_PRIVATE_DESTINATIONS=1` exists only for the
isolated Docker E2E topology. Never set it on an Internet-connected relay.

The production `compose.wireguard.yaml` overlays expose routed inventory to the
backend, mount `secrets/wireguard-key` on the relay, and grant it `NET_ADMIN`;
the base manifests do none of these. The overlay runs the relay as UID 0 because
Docker does not retain `NET_ADMIN` effectively for the image's non-root user;
all other capabilities remain dropped and `no-new-privileges` stays enabled. Set
`WIREGUARD_RELAY_PUBLIC_KEY` to that key's public half. Persist
`net.ipv4.ip_forward=1` on the host, permit UDP 51820, and verify provider return
routing before enabling sales. A netlink or nftables failure prevents routed
readiness and route activation.

During rollout, deploy the nftables-aware relay before the annual routed-IP
backend. It can consume the old v1 snapshot and defaults TCP/25 to denied. Drain
all old relay processes before exposing v2 state or recording exceptions; an old
relay does not enforce the routed policy.

Approve a TCP/25 exception only after reviewing the intended use and safeguards
and confirming receipt of at least `WIREGUARD_SMTP_EGRESS_FEE_SATS`. The admin
records the use, fee, review reference, and revocation state against the current
lease. Approval is removed on quarantine, release, suspension, or reassignment.
Ports 465 and 587 are not included in this default block.

Dedicated IPs remain unavailable for reuse for seven days by default after an
assignment ends. Configure `IP_REUSE_QUARANTINE_SECONDS` between one hour and 90
days according to inventory and reputation risk. Do not shorten it below the
WireGuard reconciliation interval plus maximum staleness. Keep an account
suspended, rather than expiring and recycling its address, while an abuse case is
still under review.

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

Each backend transport pool uses one inclusive decimal range within `1-65535`.
`PORT_TCP_CAPACITY` and `PORT_UDP_CAPACITY` independently cap advertised and
allocated leases at no more than 4096 per transport, even when the configured
numeric range is wider. Relays bind only ports with an authenticated active
tunnel and enforce `BLINDPORT_RELAY_MAX_PORT_LISTENERS`; keep that limit at least
as large as the sum of the two advertised capacities.

### Provider edge assignments

Use `FRAMED_IP_ENDPOINTS` only while historical framed dedicated IP addresses
belong to more than one relay host. It is a JSON object containing every
`RELAY_PUBLIC_IPS` address exactly once. Each value is the owning relay control endpoint:

```text
RELAY_PUBLIC_IPS=198.51.100.20,203.0.113.20
FRAMED_IP_ENDPOINTS={"198.51.100.20":"relay-a.example.net:5443","203.0.113.20":"relay-b.example.net:5443"}
```

The owner binds the address through `BLINDPORT_RELAY_IPS`; other relay nodes must
not bind or advertise it. This maps inventory to a provider but does not make one
provider-assigned dedicated IP portable between providers.

Cross-provider Blindport Port uses one canonical shared inventory address and the
same allocated TCP or UDP port at every edge. Configure every provider-specific
control endpoint and public ingress address in `PORT_HA_EDGES`:

```text
RELAY_SHARED_IPS=198.51.100.30
RELAY_CONTROL_URL=relay-a.example.net:5443
RELAY_CONTROL_URLS=relay-a.example.net:5443,relay-b.example.net:5443
PORT_HOSTNAME_SUFFIX=port.example.net
PORT_HA_EDGES=[{"endpoint":"relay-a.example.net:5443","ip":"198.51.100.30"},{"endpoint":"relay-b.example.net:5443","ip":"203.0.113.30"}]
```

The backend model requires exactly one canonical `RELAY_SHARED_IPS` address and
at least two unique edge addresses. The primary mapping must pair
`RELAY_CONTROL_URL` with that canonical address. The backend authorizes one claim
per edge, while old agents continue opening only the primary claim. Upgrade agents
before treating a Port subscription as redundant. Bind and verify each edge's local
inventory before enabling these backend mappings. Treat `PORT_HOSTNAME_SUFFIX` as
immutable after customer hostnames have been published because it is not stored per
subscription.

Each Relay can set `BLINDPORT_RELAY_SHARED_IPS` to its provider-local IPv4 and
IPv6 addresses. One authorized Port claim atomically opens the allocated TCP or
UDP port on every local shared address and forwards them through the same agent
tunnel. A failure to bind either family rejects the claim and closes all partial
listeners.

Publish wildcard A and AAAA records below `PORT_HOSTNAME_SUFFIX` with one healthy
address per provider. A Port subscription exposes
`<subscription-id>.<PORT_HOSTNAME_SUFFIX>` as its stable CNAME target and lists all
explicit provider IP and port pairs. DNS round robin is not health steering: a
failed answer may remain cached, existing streams are not migrated, and client
retry behavior determines convergence.

## DNS

Use a normal HTTPS name for the backend. Blindport IP and Blindport Port clients use
assigned socket identities and do not require DNS. Blindport Relay supports three
operating models:

1. **Managed wildcard:** set a strict comma-separated suffix list such as
   `RELAY_MANAGED_SUFFIXES=relay.example.net`. Publish wildcard A/AAAA or
   CNAME records beneath each suffix toward the SNI ingress. Customer leases
   may be nested below the suffix, but the suffix apex itself is reserved and
   rejected.
2. **Customer-owned verification:** an exact non-apex customer subdomain receives
   a unique target such as `<32-lowercase-hex>.pool.example.net` at subscription
   creation. The customer publishes one CNAME from the canonical requested
   hostname to that exact target. A wildcard claim instead requires only TXT ownership
   proof at `<base>` before payment. Publish `blindport-verification=<token>` as an
   additional TXT value at that name, alongside existing SPF or site-verification
   TXT values. Its DNS-only `*.<base>` CNAME to the selected pool target controls
   routing and can be added after setup. The wildcard record does not match `<base>`
   itself. The wildcard price routes the base plus all descendants, but pointing the
   base separately to the same pool target is optional and neither routing record is
   checked for payment. Use CNAME for a subdomain base. A conventional CNAME cannot
   be used at a zone apex because that owner name must also contain NS and SOA records.
   [RFC 2181 section 6.1](https://www.rfc-editor.org/rfc/rfc2181.html#section-6.1)
   requires those apex records, while
   [section 10.1](https://www.rfc-editor.org/rfc/rfc2181.html#section-10.1)
   prohibits other data at a CNAME owner. For Blindport's
   hostname target, use the authoritative DNS service's ALIAS, ANAME, or
   CNAME-flattening feature at the apex. These non-standard features normally resolve
   the target and synthesize A and/or AAAA answers for clients. Direct apex A/AAAA
   records are standards-compliant only when their addresses are explicitly maintained;
   do not copy transient addresses resolved from the Relay pool target. Blindport checks
   the applicable proof automatically when creating each
   initial or renewal invoice;
   `POST /api/v1/subscriptions/{public_id}/verify-domain` remains available for immediate
   feedback before paying. Configure
   `RELAY_MANAGED_DOMAIN_CLAIM_TTL_SECONDS` (30 minutes by default) and
   `RELAY_DOMAIN_CLAIM_TTL_SECONDS` (one hour by default) to bound unpaid name
   holds. `ACCOUNT_MAX_PENDING_RELAY_CLAIMS` limits one account to two unpaid
   Relay claims. Configure
   `RELAY_DNS_TIMEOUT_SECONDS` to bound each ownership check's total DNS lifetime.
   The initial customer deadline also applies after successful verification;
   verification does not extend it. Any pending token-bearing claim uses its
   claimed hostname as the TXT owner name. New exact claims have no TXT token;
   wildcard claims retain their TXT token for renewal verification.
3. **Operator DNS supervision:** an opt-in worker checks exact configured public A/AAAA
   sets through multiple explicit recursive resolvers and retains one latest sanitized
   observation per name. It does not mutate authoritative DNS. A future fenced registrar or
   authoritative-DNS adapter may publish or withdraw records and use the same control-plane
   API.

### Blindport Relay certificates

Blindport Relay does not terminate customer TLS. Each customer origin must obtain and
retain the certificate for its leased hostname. Customer-owned names can use
their normal DNS-01 workflow. Managed names can use the optional HTTP-01 path:

1. Activate and pay for the Blindport Relay subscription.
2. Run `blindportd` with both the TLS `upstream` and a separate plaintext
   `http_challenge_upstream`.
3. Configure the origin ACME client to answer HTTP-01 on that second upstream.
4. Test with the CA staging directory before requesting a production certificate.

The HTTP-01 path supports exact hostnames routed by either an exact or wildcard
Relay claim. It cannot issue an ACME wildcard certificate. Use DNS-01 at the origin
for `*.example.com`; use HTTP-01 when the origin proxy requests an exact certificate
such as `app.example.com`. In both cases TLS terminates on the customer machine.

Set a mapping's `proxy_protocol` to `v2` when the origin proxy needs the direct
client address. Configure both its TLS and HTTP challenge listeners to trust only
the exact private `blindportd` address. The proxy can then produce
`X-Forwarded-For` after TLS termination. Without this option it sees the agent as
the TCP peer. See the [Traefik wildcard example](../examples/docker-traefik/README.md)
for a complete Docker topology.

Wildcard Relay is TLS passthrough-only. A wildcard certificate such as
`*.example.com` does not cover `example.com`. If the optional base DNS record is
pointed to Blindport, the origin TLS listener and certificate must cover that base
in addition to all descendant hostnames it serves.

The relay accepts only bounded HTTP/1.1 `GET` requests with canonical domain Host
headers. It forwards `/.well-known/acme-challenge/<token>` to the dedicated
challenge upstream, processes one response, and closes the connection. Other valid
paths receive a bodyless same-host `308` redirect to HTTPS and are never forwarded.
HTTP ingress is rate limited, but Blindport cannot determine whether a CA issued a
certificate and does not enforce an issuance count. Operators must account for CA
limits across all managed names. Let's Encrypt currently documents a limit of 50
new certificates per registered domain per seven days; keep `RELAY_MANAGED_DOMAIN_CAP`
conservative and prefer customer-owned domains as usage grows.

The backend is not an authoritative DNS server. Give it access to a trustworthy
recursive resolver over the network, and monitor `502` or `503` verification
responses as resolver failures. For exact claims it queries the direct CNAME
record with resolver search disabled and a configured total lifetime. For wildcard
TXT proof, it uses that recursive resolver only to find the closest authoritative
zone, its NS targets, and their A/AAAA addresses. It then queries one vetted,
globally routable authoritative numeric address at a time with recursion disabled
and requires the AA response bit. Recursive TXT answers are never proof. One
matching authoritative server is sufficient while secondaries converge; private,
loopback, link-local, multicast, reserved, documentation, and other non-global
NS addresses are rejected before egress. NXDOMAIN, missing proof records,
nonmatching TXT values, nonmatching direct exact-name targets (including chains
and alternate pool names), and lookup timeouts are ordinary unsuccessful
verification results and do not create payments. A/AAAA flattening is not valid
proof for an exact-name CNAME. Wildcard routing records are not queried and may
be changed independently because the retained TXT challenge is the ownership proof.

For every `RELAY_POOL_DOMAINS` base, publish wildcard A/AAAA or CNAME ingress
records for its generated children. A pool base can contain at most 220 ASCII
characters so the generated 32-character label and separator remain a valid DNS
hostname. The allocator balances retained apex assignments and child targets by
their configured base.

Configure strict canonical `DNS_SUPERVISION_TARGETS` and at least two explicit public
`DNS_SUPERVISION_RESOLVERS` before setting `DNS_SUPERVISION_ENABLED=true`. Keep
`DNS_SUPERVISION_STALE_SECONDS` at or above the check interval. The admin view treats
missing or stale observations as unavailable. Observation does not perform health steering,
change authoritative records, or provide a fencing lease.

An active Blindport Relay subscription loses authorization exactly at
`current_period_end`. Its domain remains reserved to that subscription until
`RELAY_RENEWAL_GRACE_SECONDS` after the period end (seven days by default,
configurable from 136 seconds to 30 days). Creating a renewal invoice repeats
the claim's exact CNAME or wildcard TXT ownership check. The owner
must create and settle renewal payment before that deadline. Periodic and
request-time reaping reconcile open Lightning, stablecoin swap, and NWC payments
before cancellation, then clear the domain, verification state, and relay-pool
metadata only when no open payment remains. Provider-check failures and
`PROCESSING` payments retain the claim for operator reconciliation. Any later
claimant starts the managed or customer-owned verification flow from the beginning.

For DNS active-active Blindport Relay ingress, publish multiple healthy relay targets
with low TTLs and include every advertised edge in
`RELAY_CONTROL_URLS`. The agent opens an independent claim tunnel to each
provisioned edge. Static DNS round robin is not health-aware. The bundled
PowerDNS deployment uses Relay readiness to withdraw failed A/AAAA candidates,
but it cannot preserve existing TCP sessions. Advertising an edge that is absent
from provisioning can still direct traffic to a node without the tunnel. Dedicated
Blindport IP failover still needs routing or address movement outside Blindport.

### Blindport authoritative DNS

`deploy/dns` runs PowerDNS Authoritative with a SQLite primary on Servers.Guru
and a SQLite secondary on mynymbox. The API and web server are disabled, query
logging and caches are disabled, AXFR requires the shared HMAC-SHA256 TSIG key,
and both nodes import the same ECDSAP256SHA256 DNSSEC private key. Lua A records
return every Relay whose public `GET /readyz` assertion succeeds. The assertion
listener exposes only that path on TCP 9080; metrics and the Relay admin listener
remain private.

Before bootstrap, audit `deploy/dns/blindport.com.zone` against a complete export
of the current zone and increment its SOA serial for every change. In particular,
preserve mail, verification, CAA, and service records that are not discoverable
from application configuration. Do not delegate the zone or publish a DS record
until that audit and direct-server tests are complete.

Generate one transfer secret and one DNSSEC key in the operator secret store:

```sh
openssl rand -base64 -out secrets/dns-transfer-tsig 32
docker run --rm powerdns/pdns-auth-50:5.0.7@sha256:4d6cc4fc42a28f2df7fb55f6f36d8323f96e0da66135ccdad057ca7349b223b4 pdnsutil zone generate-key ksk ecdsa256 > secrets/blindport.com.private
chmod 0400 secrets/dns-transfer-tsig secrets/blindport.com.private
```

Place identical secret files on both hosts. Set `DNS_ROLE=secondary` with
`pdns-secondary.conf` on mynymbox, initialize it, and start `authoritative`.
Then set `DNS_ROLE=primary` with `pdns-primary.conf` on Servers.Guru and repeat:

```sh
docker compose --profile tools run --rm init
docker compose up -d authoritative
```

Allow inbound UDP/TCP 53 publicly. Allow TCP 9080 and primary-to-secondary
NOTIFY/AXFR only between the two provider addresses. Verify SOA, NS, A, Lua A,
DNSKEY, and RRSIG answers directly over UDP and TCP from an external network.
Verify unsigned AXFR fails, signed AXFR succeeds, the secondary receives a serial
increase, and each Lua pool removes one edge when its Relay assertion fails.

Keep ingress AAAA records absent until application traffic succeeds externally
through both provider IPv6 paths. The Servers.Guru IPv6 route must be repaired
before its address is published. After both authorities pass independent tests,
create registrar glue for `ns1.blindport.com` and `ns2.blindport.com`, update the
NS delegation, wait through the old TTL, and only then publish the tested DS.
Rollback removes the DS first, restores the previous NS delegation, and waits for
parent and resolver caches before stopping either PowerDNS node.

When introducing base routing for existing wildcard subscriptions, deploy every
Relay first and verify base, exact-precedence, and descendant lookup behavior.
Only then deploy backend and dashboard wording that advertises the included base.
Rollback reverses that order: restore the backend wording before reverting Relays.

## Firewall

| Surface | Protocol | Required access |
| --- | --- | --- |
| backend API (8000 or reverse-proxied 443) | TCP | users and relays |
| Blindport Relay HTTP redirect and HTTP-01 listener | TCP 80 | public HTTP clients and ACME validators |
| relay control (default 5443) | TCP with mutual TLS | blindportd clients |
| historical framed Blindport IP listener ports | TCP | public clients with unexpired service |
| shared Blindport Port TCP range | TCP | public clients |
| shared Blindport Port UDP range | UDP | public clients |
| Blindport Relay SNI listener | TCP/TLS passthrough | public clients |
| routed WireGuard endpoint (default 51820) | UDP | blindportd clients |
| routed Blindport IP inventory | IPv4, any transport | public clients |
| authoritative DNS | UDP and TCP 53 | public resolvers |
| Relay DNS assertion (9080) | HTTP | provider DNS peers only |
| relay admin (default 127.0.0.1:9090) | HTTP | private probes and Prometheus only |

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
traffic through historical framed Blindport IP, TCP Blindport Port, or Blindport
Relay is raw TCP; any user-facing TLS certificate belongs on the user's upstream. UDP Blindport Port
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
explicitly trusted. The image trusts forwarded headers from loopback only. The
immediate proxy must replace client-supplied forwarded headers; alternate topologies
must trust only exact proxy addresses and must never use wildcard trust. The
application never parses arbitrary forwarded headers itself. Payment creation,
domain verification, and client certificate enrollment
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
compared only with Python 3.14.

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

Optional stablecoin checkout uses its own invoice expiry,
`STABLECOIN_SWAP_INVOICE_EXPIRY_SECONDS` (1,200 seconds by default), which plus
the safety interval must remain shorter than the resource reservation. Apply
migrations through `0030`, then deploy the new code to every API and reconciler replica
with the kill switch still false. If stablecoin checkout was previously enabled,
first let every open stablecoin invoice settle or expire. Migration `0026` marks
legacy rows as Boltz payments but cannot safely reconstruct a historical custom
origin or asset, so those rows do not expose a checkout link after migration. Only
after old replicas are drained should a
separate configuration rollout add `stablecoin_swap` to
`PAYMENT_ENABLED_METHODS` and set `STABLECOIN_PAYMENTS_ENABLED=true`.
`STABLECOIN_SWAP_MARKUP_BPS=1000` charges a 10 percent satoshi markup, rounded
up. New installs use `STABLECOIN_CHECKOUT_PROVIDER=lightning_swap` and must keep
`LIGHTNING_SWAP_WEB_URL` on an HTTPS origin. Megalithic's guide recommends this
provider. Blindport opens a new tab at the snapshotted provider origin with
`/?invoice=<percent-encoded BOLT11>`, which prefills the invoice in the provider UI
before the customer selects `LIGHTNING_SWAP_DEFAULT_ASSET=USDCSOL` (USDC on Solana).
The final invoice is the maximum of service price plus markup and
`STABLECOIN_SWAP_MIN_INVOICE_SATS=5000`, a conservative static floor. The configured
markup remains a surcharge; any floor top-up earns proportional service time rounded
up to a whole day. Set
`STABLECOIN_CHECKOUT_PROVIDER=boltz` to retain the prefilled Boltz checkout; its
`BOLTZ_WEB_URL` must also be an HTTPS origin and `STABLECOIN_SWAP_DEFAULT_ASSET`
selects the initial USDC or USDT0 asset. Blindport consumes no provider callback, and
LND settlement remains the only authority. For rollback, disable the kill switch first.
Migration `0026` cannot be removed while stablecoin payment rows remain. Migrations
`0027` and `0030`, including their API-order and deposit columns, are inert historical
compatibility because deployed data prevents a lossy downgrade; runtime no longer
creates or reads orders or returns deposit fields. Migration `0028` cannot be removed
while bonus-day payments remain, and migration `0029` cannot be removed while linked
Relay upgrades or discounted payments remain.

When `BTC_USD_PRICE_ENABLED=true`, each backend process requests
`https://mempool.space/api/v1/prices` every five minutes. The cache accepts only
a bounded, valid JSON response and retains the last good USD rate for 30 minutes.
This requires outbound HTTPS but no credential. Feed failures do not affect
readiness or payment creation; the UI simply omits approximate USD values. Treat
those values as orientation only because all configured prices, invoices, and
settlement checks remain denominated in satoshis.

The timeout bound assumes LND stops or completes `AddInvoice` within the client
request timeout. An intermediary or provider operation that continues after the
client has timed out remains ambiguous until lookup by payment hash finds it.
Alert on repeatedly unbound outbox rows and investigate LND or proxy latency
before their local deadlines elapse.

Each backend replica promptly runs a background scan, then runs at the fixed
`PAYMENT_RECONCILIATION_INTERVAL_SECONDS` rate. A cycle selects at most
`PAYMENT_RECONCILIATION_BATCH_SIZE` pending Lightning, stablecoin swap, or NWC
payments in payment ID order. Provider state is checked before local expiry, and failures are logged
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
query fields. Before validation, payment, lookup, or budget discovery, it requires
`pay_invoice` and `lookup_invoice` and always prefers `nip44_v2`. Wallets that
advertise only legacy `nip04` are rejected by default. Set
`NWC_ALLOW_LEGACY_NIP04=true` only when compatibility is required; the selected
mode is retained as connection metadata and shown in the dashboard. NIP-04 uses
an unauthenticated legacy payload format, leaks message length, and is deprecated
by NIP-47. Upgrade or replace legacy wallets when possible.

To enable NWC, retain `lightning` in `PAYMENT_ENABLED_METHODS`, set
`PAYMENT_NWC_ADAPTER=nwc`, add `nwc` to the allowlist, and install
`CREDENTIAL_ENCRYPTION_KEY` as a file-backed secret. The value is one or more
comma-separated, distinct 32-byte keys encoded as 64 lowercase hexadecimal
characters. The first key encrypts; key fingerprints select older keys for
decryption. Keep old keys until all credentials have been rewritten under the
new primary. Never reuse the invoice HMAC key or another application secret.
Choose exactly one relay egress policy. `NWC_ALLOW_PUBLIC_RELAYS=true` accepts the
relay URLs embedded in account-provided connection URIs only on standard `wss`
port 443. Both Python and the helper resolve every hostname before SDK use and
reject empty answers or any private, loopback, link-local, reserved, or otherwise
non-global unicast address. These are preflight checks: the SDK performs its own DNS
resolution when connecting, so network-level egress controls remain necessary where
DNS rebinding is in scope. For a narrower deployment, leave public mode false and set
`NWC_ALLOWED_RELAY_HOSTS` to an exact comma-separated list of trusted hostnames;
wildcards are not accepted. Configuring both policies is rejected.

NWC credentials are AES-256-GCM encrypted with a random 96-bit nonce. The public
account UUID and credential purpose are authenticated as AAD. Migration `0010`
revokes all pre-production plaintext values, retains the legacy `nwc_uri` column
only for rolling old-backend reads, and prevents old replicas from restoring a
non-null value. API responses expose only connection status, capabilities, and
last validation time and are marked `Cache-Control: no-store`. Inline setup may
atomically enable automatic renewal for one subscription owned by the account;
the checkbox is never implicit and revoking the credential disables every renewal.
Credential replacement and deletion are blocked while an NWC payment is open, because
safe lookup must retain the same wallet connection generation used for the attempt.
The authenticated budget endpoint also uses `Cache-Control: no-store`. It calls
the nonstandard `get_budget` extension only when the wallet advertises it and
strictly validates millisatoshi amounts, renewal periods, and renewal timestamps.
Unsupported or temporarily unavailable budget discovery does not block a valid
NIP-47 payment. The dashboard blocks an attempt only when a reported finite
remaining budget is below the invoice amount. Budget treatment of Lightning
routing fees is wallet-specific, so users should leave margin above the service
price; Alby Hub includes fees and pending fee reserves in its budget accounting.

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
Automatic renewal of a customer-owned Relay hostname repeats its exact CNAME or
wildcard TXT ownership check before creating the NWC invoice.

CLINK Debits uses the compiled `/usr/local/bin/blindport-clink-helper` to send an
existing LND BOLT11 invoice to an account's static `ndebit1...` pointer. Enable it
only after migration `0032`: retain `lightning` in `PAYMENT_ENABLED_METHODS`, add
`clink`, set `PAYMENT_CLINK_ADAPTER=clink`, install the same file-backed
`CREDENTIAL_ENCRYPTION_KEY` required by NWC, and install a separate stable
32-byte lowercase hexadecimal `CLINK_NOSTR_PRIVATE_KEY`. Every API and reconciler
replica must use the same two keyrings. Never reuse the invoice HMAC key,
credential encryption key, or another application secret as the Nostr key.

Choose exactly one CLINK relay egress policy. `CLINK_ALLOW_PUBLIC_RELAYS=true`
accepts pointer relays only on `wss` port 443 when every resolved address is
globally routable. For a narrower deployment, leave public mode false and set
`CLINK_ALLOWED_RELAY_HOSTS` to exact trusted hostnames. The same DNS-rebinding
caveat and requirement for network-level egress controls described for NWC apply.
Static pointers are AES-256-GCM encrypted with CLINK-specific authenticated data
and responses expose no pointer material.

CLINK is preferred when an account has both wallet methods. A signed CLINK `GFY`
rejection may start one NWC attempt against the same invoice. A timeout, transport
failure, malformed response, invalid preimage, or any other ambiguous result
remains pending for LND settlement and never retries CLINK or falls back to NWC.
CLINK v1 provides no lookup operation or mandatory idempotency key, so an operator
must resolve a long-lived `unknown` state with the wallet owner and LND before
changing it manually. Revoking either wallet preserves automatic renewal while
the other remains connected. Credential replacement is blocked while that
credential generation may still be needed by an open payment.

Cashu runtime support has been removed. The legacy database enum value and token
column remain read-only so historical rows can be inspected. Before upgrading,
count all legacy Cashu rows and manually resolve every `PENDING` or `PROCESSING`
row against the former provider; the application does not settle, expire, or
release reservations for those ambiguous rows.

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
`LND_INVOICE_HMAC_KEY`, `CLINK_NOSTR_PRIVATE_KEY`, and every active
`CREDENTIAL_ENCRYPTION_KEY` keyring entry with the matching backup. Store encrypted copies offsite
and test restoration into an isolated environment.

Application rollback requires the database revision expected by the old image.
Stop all API replicas, then either restore the matching pre-migration database
and `CA_DIR` backup or run a downgrade that has been verified for that exact
application revision. Before `blindport-migrate downgrade <revision>`, take a
fresh backup and confirm that both the downgrade and target application support
the resulting schema. A forward schema with an old application is unsupported,
not a normal rollback state, and exact-head startup verification rejects it.

## Production manifests

The checked-in production and split-host Compose manifests are documented in
[`deploy/OPERATIONS.md`](../deploy/OPERATIONS.md). The one-host production stack uses an
SNI multiplexer and is intended for manual and invited testing. Move relay
ingress to the split relay host before unrestricted public signup.
