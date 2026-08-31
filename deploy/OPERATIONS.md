# Production deployment artifacts

These Compose stacks are intentionally single-instance deployments. The production stack runs on
one dedicated host. The split stack separates control and relay
failure domains, but neither stack provides database, proxy, relay, or API high
availability.

Provider-edge Relay deployments may use `deploy/split/relay` independently of the
control stack. Keep one provider-specific control hostname per edge. Before enabling
backend mappings, deploy and verify every relay with only that site's shared and
historical framed addresses bound. Keep `PORT_HA_EDGES`, `PORT_HOSTNAME_SUFFIX`,
and `FRAMED_IP_ENDPOINTS` only on the control backend. Roll out the current agent before
representing Port service as redundant, and treat `PORT_HOSTNAME_SUFFIX` as immutable
after publishing customer hostnames.

An additional Relay edge does not make the website or control plane highly
available. Publishing a second website A or AAAA record requires a backend replica,
one fenced PostgreSQL writer endpoint, shared signer and secrets, redundant payment
connectivity, and readiness-based DNS steering. Do not use two writable databases or
automatic two-node promotion without an external quorum and fencing mechanism.

The disposable [HA lab](../docs/ha.md) exercises application-level failure behavior
on one Docker host. It is not a production manifest and does not change the availability
claims of the production or split stacks.

The hosted beta is best effort and has no uptime or high-availability guarantee.
High availability is planned after beta, but future topology is not part of the
current service commitment.

Start with the [self-hosting guide](../docs/self-hosting.md). Report deployment
problems through the [public issue tracker](https://github.com/blindport/blindport/issues),
but report vulnerabilities through the process in [SECURITY.md](../SECURITY.md).

## Required host preparation

If GitHub Actions and GHCR are inside your trust boundary, use an immutable
release reference for every Blindport image, for example
`ghcr.io/blindport/blindport-relay:v0.3.0@sha256:<manifest-digest>`. Download the
`blindport-images.env` asset from the matching
[GitHub release](https://github.com/blindport/blindport/releases). Otherwise,
follow the self-hosting guide to verify the signed source and build local images.
Then copy the relevant `.env.example` to `.env`, replace all example addresses
and names, and create a separate `secrets/` directory. The `.env.example` image
tags are convenient discovery aliases only; replace them with digest-pinned
release references or verified local image tags before going live. Do not modify
or use the checked-in placeholder files.

Production containers send stdout and stderr to journald. Install the repository's
30-day maximum retention policy before starting any service, then rotate and remove
older records left by previous deployments. Run these commands from the repository
root:

```sh
sudo install -d -m 0755 /etc/systemd/journald.conf.d
sudo install -m 0644 deploy/journald-blindport.conf \
  /etc/systemd/journald.conf.d/99-blindport-retention.conf
sudo systemctl restart systemd-journald
sudo journalctl --rotate
sudo journalctl --vacuum-time=30d
```

Relay containers run as UID 10001 and bind TCP 80 and 443. Persist the minimum
unprivileged port at 80 on every Relay host before starting the stack:

```sh
sudo install -m 0644 deploy/sysctl-blindport-relay.conf \
  /etc/sysctl.d/99-blindport-relay.conf
sudo sysctl --system
```

This host policy applies to Blindport container output and other journal records.
It also disables journal forwarding to syslog so a second host-local copy cannot
bypass the limit. Keep proxy and Uvicorn access logging disabled. Configure firewall,
kernel, Tor, database, backup, monitoring, and external log collectors so request or
visitor source addresses are not retained and all operational logs expire within 30 days.
The checked-in policy cannot control independent hosting, DNS, payment, email, or
customer systems; review those providers separately.
Set the yearly IP price and every monthly and yearly Port and Relay price to positive
satoshi amounts. The checked-in defaults are 75,000 yearly for IP, 1,500/15,000 for
Port, and 3,000/30,000 for Relay. Historical monthly or framed IP subscription price
snapshots remain in the database; new IP subscriptions use the yearly price only.
Keep `BILLING_YEARLY_ENABLED=false` until migration `0009` is applied and all old
backend and reconciliation replicas are drained, then enable it on every replica.
Blindport IP has no sellable capacity while yearly billing is disabled.
Keep NWC disabled until migration `0010` is applied, all old replicas are drained,
a dedicated credential keyring is mounted, and each user has validated a wallet
connection. The checked-in Compose environments remain Lightning-only.
Keep reminder email disabled until migration `0013` is applied and SMTP plus
recipient-encryption settings are installed. Reminder delivery does not require
customer NWC enablement.
Keep service announcements disabled until migration `0018` is applied, every old
writer is drained, and the same SMTP and recipient-encryption settings are installed.
Apply migration `0023` before deploying browser-session code. Keep
`PASSKEYS_ENABLED=false` until every old API replica is drained, then verify the Compose
derived `WEBAUTHN_RP_ID=${API_DOMAIN}` and `WEBAUTHN_ORIGIN=https://${API_DOMAIN}` before
enabling the flag on all replicas. Every API replica must share PostgreSQL and
`SECRET_KEY`; rotating that key revokes customer browser sessions and pending ceremonies.
Passkeys are public-origin only. Bearer tokens remain required for agents and recovery.
Stop every old API and notification worker before applying migration `0024`. The migration
replaces the separate reminder and service-announcement recipient columns with one explicit
notification preference, resets consent instead of inferring it, and cancels queued email.
Old application code is incompatible with the new schema. Rollback to pre-`0024` code should
restore the matching database backup rather than rely on reconstructed empty consent columns.
Apply migration `0025` with the new backend, then deploy the backend before either new Relay.
Old Relays may continue heartbeat reporting but omit connection attribution. A new Relay sends
strict bounded subscription-presence fields that an old backend rejects. Roll back Relays before
the backend. Truncated snapshots never infer disconnection for omitted subscriptions.
For routed-IP rollout, replace and verify every relay before deploying the new
backend. The new relay safely falls back to the old v1 desired state with no
TCP/25 exceptions. An old relay has no routed nftables policy, so never leave one
serving routed traffic after the new backend or SMTP approvals are enabled.
Drain every old API and reconciliation replica before applying migration `0017`,
then deploy the annual routed-IP backend. The migration backfills one imported
lease episode for each currently assigned dedicated IP. Do not run mixed old/new
writers after the migration because old code does not write the lease audit table.
The `0017` downgrade drops all lease and SMTP review history. For rollback to a
pre-`0017` image, stop every writer and restore the matching pre-migration
database backup instead of treating a downgrade as history-preserving.
Migration `0013` permanently scrubs the retired paid-delivery fields. A rollback to
an image built for the deployed pre-`0013` schema requires restoring the matching
pre-migration database backup; the `0013` downgrade cannot reconstruct those fields.
Apply migration `0012` before deploying agents that create orders from Docker
labels. Existing agents and explicit subscription labels remain compatible.
The public `/admin*` browser path is protected by the `ADMIN_TOKEN` sign-in flow, not source
CIDRs. Browser sessions are short-lived, signed, `HttpOnly`, `Secure`, `SameSite=Strict`, and
scoped to `/admin`; `POST /admin/login` has the dedicated stricter direct-client rate limit.
Rotating `ADMIN_TOKEN` immediately invalidates both browser sessions and bearer access.
Set `ADMIN_PRIVATE_CIDRS` to an operator VPN or fixed management source. Only bearer admin APIs
at `/api/v1/admin/*` and `/api/v2/admin/*` are allowed from those sources; every other source
receives `404`. The onion route continues to return `404` for all admin browser and API paths.

The admin operations summary reports active subscriptions, customers with an active
subscription, lifetime settled gross sats (not revenue), open pending or processing payments,
catalog capacity, counts derived from the rate-limited `last_seen_at` account activity field,
current paying-customer lifecycle counts, and latest Relay/DNS observations. Relay reports
contain fixed-cardinality aggregate counters plus a bounded, sorted set of active public
subscription IDs for connection-state attribution. They contain no source addresses, upstream
addresses, domains, or traffic content. Treat stale or missing observations as unavailable; the
database is not a metrics store, and DNS observation does not perform authoritative record changes.

Create secrets with restrictive permissions. Compose file-backed secret `uid`, `gid`,
and `mode` are not implemented by every Compose runtime, so ownership on the host is
authoritative. Backend and relay secret files must be owned by numeric UID/GID 10001;
the PostgreSQL password may remain root-owned because its entrypoint reads it before
dropping privileges.

```sh
install -d -m 0700 secrets
install -d -o 1000 -g 1000 -m 0700 state state/caddy-data state/caddy-config
install -o 10001 -g 10001 -m 0400 /dev/null secrets/database-url
install -o 10001 -g 10001 -m 0400 /dev/null secrets/secret-key
install -o 10001 -g 10001 -m 0400 /dev/null secrets/token-hash-key
install -o 10001 -g 10001 -m 0400 /dev/null secrets/relay-secret
install -o 10001 -g 10001 -m 0400 /dev/null secrets/relay-heartbeat-keys
install -o 10001 -g 10001 -m 0400 /dev/null secrets/relay-heartbeat-token
install -o 10001 -g 10001 -m 0400 /dev/null secrets/admin-token
install -o 10001 -g 10001 -m 0400 /dev/null secrets/lnd-invoice-hmac-key
install -o 10001 -g 10001 -m 0400 /path/to/tls.cert secrets/lnd-tls-cert
install -o 10001 -g 10001 -m 0400 /path/to/invoice.macaroon secrets/lnd-invoice-macaroon
install -o 10001 -g 10001 -m 0400 /dev/null secrets/credential-encryption-key
install -o 10001 -g 10001 -m 0400 /dev/null secrets/smtp-password
install -o 10001 -g 10001 -m 0400 /path/to/offline-entitlement-private-key.pem secrets/offline-entitlement-private-key
install -o 10001 -g 10001 -m 0400 /dev/null secrets/wireguard-key
install -o root -g root -m 0400 /dev/null secrets/postgres-password
```

When routed WireGuard is enabled, generate its key separately instead of leaving
an empty placeholder:

```sh
temporary=$(mktemp)
wg genkey > "$temporary"
install -o 10001 -g 10001 -m 0400 "$temporary" secrets/wireguard-key
rm -f "$temporary"
wg pubkey < secrets/wireguard-key
```

Put the final command's output in `WIREGUARD_RELAY_PUBLIC_KEY`. Never copy the
private key to the control host.

Generate independent random values for the application secret, token-hash key, relay
secret, admin token, database password, and 32-byte invoice HMAC key. The five Blindport
security credentials must be distinct. The non-hex credentials must each contain at least
32 characters, and the invoice HMAC key must contain 64 lowercase hexadecimal characters.
The password in `database-url` must
be URL encoded and exactly match `postgres-password`. The relay host receives only
`relay-secret`; use the exact same value as the control host. An LND invoice macaroon
restricted to `GetInfo`, `AddInvoice`, and `LookupInvoice` is the expected
least-privilege credential. Do not mount an admin macaroon. Keep LND external and route
its HTTPS name over a private network or VPN.

Optional NWC enablement requires another owner-only secret file containing exactly
64 lowercase hexadecimal characters (or a comma-separated rotation keyring). Add
`CREDENTIAL_ENCRYPTION_KEY_FILE=/run/secrets/credential-encryption-key` and mount
that file on backend and migration services, set `PAYMENT_NWC_ADAPTER=nwc`, then
set `PAYMENT_ENABLED_METHODS=lightning,nwc`. Do this only after the `0010` rollout.
Choose exactly one NWC relay egress policy. Set `NWC_ALLOW_PUBLIC_RELAYS=true` to
accept the relay embedded in each user's connection URI only when it uses `wss`
port 443 and every DNS answer is globally routable. Alternatively, leave public
mode false and set `NWC_ALLOWED_RELAY_HOSTS` to exact trusted hostnames without
wildcards. The backend and helper perform independent policy prechecks. Public
mode does not pin the SDK connection to a checked DNS answer, so enforce network
egress rules outside the application if DNS rebinding must be excluded.
Legacy NIP-04 wallet providers remain rejected by default. Set
`NWC_ALLOW_LEGACY_NIP04=true` only when compatibility is required; NIP-44 remains
preferred when a wallet advertises both modes. NIP-04 does not authenticate its
ciphertext, so keep wallet budgets and expirations restrictive and migrate the
connection when the provider supports NIP-44 v2.
The backend image already contains the architecture-native compiled helper, so no
Node or Bun service runs in production. Each user should create a dedicated wallet
connection with a wallet-enforced budget and expiry that cover the selected renewal
term plus fees.

Optional CLINK Debits enablement requires migration `0032`, the credential
encryption key described above, and a separate owner-only file containing one
stable 32-byte Nostr private key as 64 lowercase hexadecimal characters. Generate
it with `openssl rand -hex 32`, mount it read-only into backend and migration
services, and set `CLINK_NOSTR_PRIVATE_KEY_FILE` to the mounted path. Then set
`CLINK_NOSTR_PRIVATE_KEY_SOURCE` to the host path, set
`PAYMENT_CLINK_ADAPTER=clink`, and add `clink` to `PAYMENT_ENABLED_METHODS` while
retaining `lightning`. Choose exactly one relay policy with
`CLINK_ALLOW_PUBLIC_RELAYS=true` or exact `CLINK_ALLOWED_RELAY_HOSTS`; the NWC
egress and DNS-rebinding guidance above applies equally to CLINK. The backend
image includes the architecture-native CLINK helper, so no Bun service runs in
production. Keep the signing key stable across replicas and backups. CLINK is
preferred when both wallet methods are connected; NWC fallback occurs only after
a definitive signed rejection because CLINK v1 cannot look up an ambiguous send.

Optional stablecoin checkout uses the external provider UI. Apply migrations through `0030`,
then roll out the new application code to every API and reconciler replica while
keeping `STABLECOIN_PAYMENTS_ENABLED=false` and the existing method allowlist.
Before migrating an installation that previously enabled stablecoin checkout, let
every open stablecoin invoice settle or expire. Legacy rows are identified as
Boltz payments, but their historical custom origin and asset cannot be reconstructed,
so the new UI does not offer a checkout link for them.
After every old replica is drained, set
`PAYMENT_ENABLED_METHODS=lightning,stablecoin_swap`, verify
`STABLECOIN_CHECKOUT_PROVIDER=lightning_swap` and
`LIGHTNING_SWAP_WEB_URL=https://lightning-swap.com`, and set
`STABLECOIN_PAYMENTS_ENABLED=true` in a separate configuration rollout. The
checked-in default remains false. The default `STABLECOIN_SWAP_MARKUP_BPS=1000`
adds 10 percent to the LND invoice and
`STABLECOIN_SWAP_INVOICE_EXPIRY_SECONDS=1200` leaves time for the external swap
within the 1,800-second reservation. `STABLECOIN_SWAP_MIN_INVOICE_SATS=5000` is a
conservative static floor. The configured surcharge remains a checkout cost. Any
additional amount required by that floor earns proportional service time rounded up to
a whole day. Disable the feature flag first during a
rollback. The flag blocks new checkout creation and removes the UI control;
reconciliation still settles or expires invoices issued before disablement so
customer payments and resource holds are not stranded. Do not deploy application code
from before migration `0030` during this rollout. Migration `0026` cannot be removed
while stablecoin payment rows remain. Migrations `0027` and `0030`, including their
API-order and deposit columns, are inert historical compatibility: deployed data
prevents a lossy downgrade, but runtime no longer creates or reads orders or returns
deposit fields. Migration `0028` cannot be removed while bonus-day payments remain.
Migration `0029` cannot be removed while linked Relay upgrades or discounted payments
remain.

Megalithic's guide recommends Lightning Swap. Blindport opens a new tab at the
snapshotted provider origin with `/?invoice=<percent-encoded BOLT11>`, so the provider
UI receives the LND invoice prefilled before the customer chooses USDC on Solana. Only
the LND payment hash settles service; provider callbacks cannot activate it.

Managed names have a 30-minute unpaid hold, customer-owned names have a one-hour
DNS and payment hold, and one account may retain at most two unpaid Relay claims.
Keep `RELAY_MANAGED_DOMAIN_CLAIM_TTL_SECONDS=1800`,
`RELAY_DOMAIN_CLAIM_TTL_SECONDS=3600`, and
`ACCOUNT_MAX_PENDING_RELAY_CLAIMS=2` unless capacity planning justifies a change.
The payment reconciler also reaps elapsed claims, so alert on reconciler readiness.

`BTC_USD_PRICE_ENABLED=true` permits outbound HTTPS to the fixed mempool.space
price endpoint. The display-only cache refreshes every five minutes and omits USD
estimates after 30 minutes without a successful response. It has no credential
and must not be used as invoice or accounting authority.

Optional reminder delivery uses generic SMTP. Configure `SMTP_HOST`, `SMTP_PORT`,
`SMTP_SECURITY=starttls|tls`, `SMTP_FROM_EMAIL`, and `SMTP_TIMEOUT_SECONDS`.
Production requires TLS. For authenticated SMTP, set `SMTP_USERNAME` and use
`SMTP_PASSWORD_FILE` as the file-backed operator input, for example the owner-only
`smtp-password` file at `/run/secrets/smtp-password`; username and password must be
present together. Omit both for a trusted relay. Set
`CREDENTIAL_ENCRYPTION_KEY_FILE=/run/secrets/credential-encryption-key` to protect
recipient addresses with a distinct encryption purpose, then set
`REMINDER_EMAIL_ENABLED=true`. Mount both secrets only on `backend`, never on
`migrate`, relay, proxy, or database services. The migration service forces reminders
off and needs neither runtime secret.

Service announcements use the same SMTP configuration but a separate encrypted recipient
purpose. After migration `0018` and a complete writer rollout, set
`ANNOUNCEMENT_EMAIL_ENABLED=true`. The customer dashboard exposes a separate opt-in.
The browser admin creates a draft, reviews the eligible count, then queues it with a
separate POST. The queue snapshot excludes suspended and admin accounts. Delivery rows
contain only campaign, account, and recipient-generation references; no addresses are
displayed or exported. Cancellation reaches queued rows only and cannot retract a
delivery that has entered `sending`.

After migration `0022`, set `NOTIFICATION_RECONCILIATION_ENABLED=true` on control-plane
backends and tune its interval, batch, startup grace, staleness, and delivery lease only
through the `NOTIFICATION_RECONCILIATION_*` and `NOTIFICATION_DELIVERY_LEASE_SECONDS`
settings. This worker is independent from payment reconciliation and reports the
`notifications` readiness component. It uses one privacy-preserving outbox for ACCOUNT
lifecycle mail (activation, renewal, seven-day, one-day, and actual expiry) and SERVICE
announcements. Queue-time announcement snapshots are expanded in bounded pages; legacy
reminder and announcement outboxes are retained only for draining. SMTP acceptance is
terminal, retryable pre-boundary failures back off, and interrupted or ambiguous sends
become terminal `delivery_ambiguous` records.

Offline entitlements remain disabled by default. Do not set
`OFFLINE_ENTITLEMENTS_ENABLED=true` until every serving relay and agent accepts the signed
v2 claim format. Mount the dedicated unencrypted Ed25519 PKCS#8 PEM only on `backend`, set
`OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE=/run/secrets/offline-entitlement-private-key`, choose
an immutable `OFFLINE_ENTITLEMENT_KEY_ID`, and map every configured control endpoint in
`RELAY_EDGES`. Before enabling the flag, set both
`RESOURCE_REUSE_QUARANTINE_SECONDS` and `RELAY_RENEWAL_GRACE_SECONDS` strictly above
`OFFLINE_ENTITLEMENT_GRACE_SECONDS + 120`; with the default seven-day grace, each must be at
least `604921`. The checked-in normal disabled defaults remain 180 seconds and seven days,
respectively. Roll out the code and configuration with the flag false first, drain old API
replicas, verify each edge mapping, then enable the flag in a separate rollout. Keep the key
stable with the database backups; no private material is returned to clients.

Relay stacks remain disabled by default. Before the separate enablement rollout, give
each relay its own stable `RELAY_EDGE_ID`, set `OFFLINE_ENTITLEMENT_MAX_GRACE_SECONDS`
to the approved backend grace limit, and set `OFFLINE_ENTITLEMENT_PUBLIC_KEYS` to the
canonical JSON public keyring. Mount no entitlement private key on a relay. A relay can
admit a newly connected v2 client during an infrastructure outage only when its exact
certificate identity and signed artifact both verify for that edge; token denials,
secret failures, and protocol failures remain fail-closed.

For the integrated production Relay, set `LOCAL_RELAY_EDGE_ID` and stage
`OFFLINE_ENTITLEMENT_PUBLIC_KEYS` plus `OFFLINE_ENTITLEMENT_MAX_GRACE_SECONDS` while
`LOCAL_RELAY_OFFLINE_ENTITLEMENTS_ENABLED=false`. Enable that local Relay flag only in
the relay-fallback rollout after backend issuance and normal online authorization pass.
Split Relay stacks use their own `OFFLINE_ENTITLEMENTS_ENABLED` flag.

The reconciler queues one notice seven days before expiry and one notice one day
before expiry. Each delivery gets a deterministic Message-ID derived from its outbox
identity. SMTP acceptance is `sent`; definitive transient rejection retries with
bounded backoff, permanent rejection is `failed`, and disconnect or timeout after the
send boundary is terminal `delivery_ambiguous` to prevent duplicate mail. A stale
`sending` lease is also recovered as ambiguous. Disabling reminders cancels queued
work but cannot retract an in-flight SMTP send. Review terminal and ambiguous states
in the admin UI.

Named volumes persist PostgreSQL and the Blindport CA. The owner-only `STATE_DIR`
directories persist Caddy account and certificate state while allowing Caddy to run as
UID/GID 1000. Back up all state sets and owner-only secret files together, encrypt the
backup offsite, and test restoration. Losing the CA breaks enrolled client identity
renewal; losing the invoice HMAC key can break pending invoice correlation. Changing
`TOKEN_HASH_KEY` invalidates every stored account and admin token.

Blindport application records do not persist request or visitor source addresses.
Direct-client signup and login rate limits use an ephemeral per-process HMAC key,
and their buckets expire with the fixed window. Account-derived rate limits remain
durable in PostgreSQL. Migration `0015` deletes direct-client buckets written by
older releases and recalculates the remaining bucket count. This makes direct-client
limits best effort across multiple backend processes; per-account product and payment
limits remain authoritative.

## Production

The production stack uses host networking for HAProxy, Caddy, and the relay. This is required so
the public IP configured for Blindport Port in the backend is also the actual address bound by
the relay. Ensure `PUBLIC_IP` is configured on the host. HAProxy owns `PUBLIC_IP:80`
and `PUBLIC_IP:443`; the relay binds active leases from the configured TCP/UDP
Blindport Port range and owns `PUBLIC_IP:5443`. Backend `:8000`, relay SNI `:4443`,
Caddy `:8080/:8443`, and relay admin `:9090` bind loopback only. Firewall all
loopback-only surfaces from the public interface.

Keep backend port `8000` bound to loopback. The backend image accepts forwarded
addresses only from loopback, and Caddy must replace client-supplied forwarded
headers before proxying. Never use wildcard Uvicorn forwarded-header trust. Any
alternate proxy topology must explicitly trust only its immediate proxy addresses.

HAProxy runs as UID/GID 99. Because host networking does not receive Docker's usual
low-port network-namespace setting, set `net.ipv4.ip_unprivileged_port_start=0` on this
single-purpose host so the non-root proxy can bind `:80` and `:443`. Do not use this
setting on a shared shell host with untrusted local users.

The Caddy image carries a `NET_BIND_SERVICE` file capability. Its service retains only
that capability so the non-root binary can execute under `no-new-privileges`; Caddy
still binds only the configured high loopback ports.

Before public DNS exists, set `CADDYFILE=./Caddyfile.internal` to issue the API
certificate from Caddy's local CA. Test clients must explicitly trust that CA or use a
one-off insecure client together with a manual host mapping. Return to
`CADDYFILE=./Caddyfile` before publishing DNS so Caddy obtains a publicly trusted
certificate.

For a bounded pre-LND forwarding test, the production stack also permits
`ENVIRONMENT=development` and `PAYMENT_LIGHTNING_ADAPTER=mock-auto`. Block public
`:80`, restrict `:443` to the operator's source address, and use explicit HTTPS while
this mode is active. Every mock invoice settles without payment, and development mode
does not set `Secure` on authentication cookies or emit HSTS. Because HAProxy shares
`:443` between the API and Blindport Relay SNI, the source restriction also limits relay
TLS testing. Restore `ENVIRONMENT=production` and `PAYMENT_LIGHTNING_ADAPTER=lnd`,
install the LND credentials, audit and revoke or explicitly retain every mock-issued
subscription, verify readiness, and restore the intended public firewall policy before
accepting users. Production remains the default.

The `*_CPU_LIMIT` and `*_MEMORY_LIMIT` variables set per-container ceilings. A
one-vCPU host must set every CPU limit to at most `1.0`; lower memory limits only after
measuring steady-state and migration usage.

For onion access, install Tor on the host, copy `deploy/production/torrc` to
`/etc/tor/torrc`, and persist `/var/lib/tor/blindport-production` as secret key material.
Set `ONION_HOST` to the generated hostname. Tor maps Web traffic to loopback Caddy and
relay control to the additional loopback mTLS listener; no public firewall port is
required. The onion Web route intentionally returns 404 for admin and internal APIs.

The production stack mounts `DOWNLOADS_DIR` read-only at `/srv/downloads`. Publish versioned
agent binaries and matching `.sha256` files there; never replace an existing
versioned artifact in place. Also publish `install.sh`, the current
`blindportd-linux-{amd64,arm64,armv7}` aliases, and their checksums. Stage and
verify all current-release aliases before renaming them into place together.

HAProxy sends PROXY v2 to both loopback TLS backends. Caddy and the relay require it
only on their explicit loopback listeners, so Caddy receives the API client address
in `X-Forwarded-For` and the relay passes the client address through the tunnel for
origin-side PROXY v2 mappings. Never enable the relay's SNI PROXY protocol mode on a
public or wildcard listener. HAProxy probes the relay's loopback `:9090/readyz`
endpoint directly, without a PROXY header, because synthetic health checks have no
client address. HTTP ingress rate limits still see HAProxy as one source and are
explicitly sized for redirects and multi-vantage ACME retries.

For independently hosted Relay edges, set `RELAY_PRIVATE_CIDRS` to their fixed source
addresses. Caddy permits those sources to reach `/internal/v1/*`, `/internal/v2/*`, and
`/internal/v3/*`;
the backend still requires the Relay shared secret on every request. Every other
source receives 404 for internal routes. Keep the onion route blocked.

The Caddy `servers` selector must remain the exact `127.0.0.1:8443` listener produced
by `default_bind`; a port-only selector silently omits the PROXY protocol wrapper.
HTTP/3 remains disabled on this listener because the HAProxy frontend proxies only
TCP and must not advertise the internal `:8443` UDP endpoint to public clients.

API HTTP traffic is routed to Caddy. For every other host, HAProxy sends HTTP to the
relay's loopback listener. That listener validates and bounds each request, redirects
non-ACME GETs to the same canonical host, path, and query over HTTPS, and forwards valid
`/.well-known/acme-challenge/` requests over a port-80 stream. The origin must configure
`BLINDPORT_HTTP_CHALLENGE_UPSTREAM=host:port`, the
`-http-challenge-upstream` flag, a static mapping's `http_challenge_upstream`, or the
equivalent Docker label. `blindportd` refuses port-80 streams when that separate
plaintext HTTP upstream is absent; normal Blindport Relay TLS remains on its usual upstream.

Run the migration as a one-shot job before starting or replacing the API:

```sh
./compose.sh pull
./compose.sh --profile tools run --rm migrate
./compose.sh up -d
./compose.sh ps
```

Use `compose.sh` for every production Compose operation. When
`WIREGUARD_PUBLIC_IPS` is nonempty, it refuses to invoke Docker unless the
operator selects `--wireguard` for the single-host routed topology or
`--wireguard-control` when production controls a separate routed Relay host.

## Split control host

Point `API_DOMAIN` at `CONTROL_BIND_IP`. PostgreSQL and backend have no published
ports. Caddy publishes only `:80/:443`. `RELAY_PRIVATE_CIDRS` is a space-separated
allowlist for `/internal/v1/*`, `/internal/v2/*`, and `/internal/v3/*`; all other clients receive 404
for internal routes.
Route `API_DOMAIN` to the control host's private IP from the relay host, while keeping
normal public DNS for users. TLS still authenticates the API hostname.

Run `pull`, the one-shot `migrate` command, and `up -d` as shown for production, from
`deploy/split/control`.

## Split relay host

Ensure `RELAY_PUBLIC_IP` is configured on the relay host. The relay binds that IP on
`:80` for HTTPS redirects and HTTP-01, `:443` for SNI, `:5443` for client control, and
each TCP/UDP Blindport Port with an active authenticated tunnel. Relay admin remains
on loopback `:9090`. Permit the relay host's private source address through the
control Caddy allowlist and verify `BACKEND_INTERNAL_URL` resolves over that private
route.

Framed `RELAY_PUBLIC_IPS` remains disabled in the checked-in split topology.
Routed `WIREGUARD_PUBLIC_IPS` is optional and wired through both production
topologies. Before applying the routed Compose overlay, arrange provider routes
for every `/32`, persist `net.ipv4.ip_forward=1`, create the owner-only
`secrets/wireguard-key`, set its public half and endpoint on the control host,
and allow `51820/udp`. The relay receives `NET_ADMIN` for WireGuard, routes, and
its dedicated nftables table. The routed overlay runs the process as UID 0 so
that capability is effective, while retaining `cap_drop: ALL`, explicit
capability additions, `no-new-privileges`, and a read-only root filesystem. Keep
every other host firewall rule in operator tables. Add host rules for `80/tcp`,
`443/tcp`, `5443/tcp`, `51820/udp`, and the
configured TCP and UDP Blindport Port ranges. Do not expose `9090/tcp`.
The base Compose files keep routed inventory hidden, keep WireGuard disabled,
do not grant `NET_ADMIN`, and do not mount the key. Apply
`compose.wireguard.yaml` on both the control and relay host. For production, the
single overlay configures both services:

```sh
./compose.sh --wireguard up -d
```

When the one-host production backend provisions routed inventory through a separate
split relay host, apply `compose.wireguard-control.yaml` on the production host and
`compose.wireguard.yaml` in `deploy/split/relay` on the relay host. The control-only
overlay does not grant `NET_ADMIN`, mount the relay private key, or enable WireGuard
on the production host's local Relay. Run production control operations through
`./compose.sh --wireguard-control` so configured inventory cannot be hidden by an
accidental base-only deployment.

Persist IPv4 forwarding only on each routed relay host before enabling its overlay:

```sh
sudo install -m 0644 deploy/sysctl-blindport-routed-relay.conf \
  /etc/sysctl.d/99-blindport-routed-relay.conf
sudo sysctl --system
```

The routed Relay runs as UID 0 with `NET_ADMIN` to create the WireGuard device and
`DAC_OVERRIDE` to access the existing owner-only Relay secret and certificate cache.
This is required because common Compose runtimes ignore file-secret `uid` and `gid`.
The overlay uses a separate `relay-wireguard-state` volume so its owner-only
certificate cache matches UID 0 without changing the base Relay's UID 10001 state
volume. The mount sets `volume.nocopy` so a new routed-state volume starts root-owned
instead of copying the base image's UID 10001 state. Back up both volumes after enabling
routed mode. The container root filesystem remains read-only and all other capabilities
remain dropped.

Run `nft list table inet blindport` after startup and verify the input, active
source, non-global destination, and TCP/25 rules before activating sales. Test
both directions from an external network and confirm the outbound observer sees
the leased `/32`, not the relay's primary address. Readiness fails when peer,
route, or nftables state cannot be reconciled.

```sh
docker compose --env-file .env -f compose.yaml -f compose.wireguard.yaml pull
docker compose --env-file .env -f compose.yaml -f compose.wireguard.yaml up -d
docker compose --env-file .env -f compose.yaml -f compose.wireguard.yaml ps
```

For a relay without routed inventory, omit `-f compose.wireguard.yaml`.

## Validation

The repository validator uses example values and does not start Blindport services, contact
LND, request certificates, or require usable secrets:

```sh
./deploy/validate.sh
```

After deployment, verify the backend and relay readiness through container health,
test API HTTPS from outside, test relay mTLS enrollment through `:5443`, and exercise
one TCP, one UDP, one Blindport Relay TLS, and one HTTP-01 path before accepting testers.
