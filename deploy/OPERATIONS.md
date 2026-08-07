# Production deployment artifacts

These Compose stacks are intentionally single-instance deployments. The canary runs on
one dedicated host. The split stack separates control and relay
failure domains, but neither stack provides database, proxy, relay, or API high
availability.

Provider-edge Relay deployments may use `deploy/split/relay` independently of the
control stack. Keep one provider-specific control hostname per edge. Before enabling
backend mappings, deploy and verify every relay with only that site's shared and framed
addresses bound. Keep `PORT_HA_EDGES`, `PORT_HOSTNAME_SUFFIX`, and
`FRAMED_IP_ENDPOINTS` only on the control backend. Roll out the current agent before
representing Port service as redundant, and treat `PORT_HOSTNAME_SUFFIX` as immutable
after publishing customer hostnames.

An additional Relay edge does not make the website or control plane highly
available. Publishing a second website A or AAAA record requires a backend replica,
one fenced PostgreSQL writer endpoint, shared signer and secrets, redundant payment
connectivity, and readiness-based DNS steering. Do not use two writable databases or
automatic two-node promotion without an external quorum and fencing mechanism.

The disposable [HA lab](../docs/ha.md) exercises application-level failure behavior
on one Docker host. It is not a production manifest and does not change the availability
claims of the canary or split stacks.

The hosted beta is best effort and has no uptime or high-availability guarantee.
High availability is planned after beta, but future topology is not part of the
current service commitment.

Start with the [self-hosting guide](../docs/self-hosting.md). Report deployment
problems through the [public issue tracker](https://github.com/blindport/blindport/issues),
but report vulnerabilities through the process in [SECURITY.md](../SECURITY.md).

## Required host preparation

If GitHub Actions and GHCR are inside your trust boundary, use an immutable
release reference for every Blindport image, for example
`ghcr.io/blindport/blindport-relay:v0.2.3@sha256:<manifest-digest>`. Download the
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

This host policy applies to Blindport container output and other journal records.
It also disables journal forwarding to syslog so a second host-local copy cannot
bypass the limit. Keep proxy and Uvicorn access logging disabled. Configure firewall,
kernel, Tor, database, backup, monitoring, and external log collectors so request or
visitor source addresses are not retained and all operational logs expire within 30 days.
The checked-in policy cannot control independent hosting, DNS, payment, email, or
customer systems; review those providers separately.
Set all monthly and yearly price variables to positive satoshi amounts; the checked-in
defaults are 7,500/75,000 for IP, 1,500/15,000 for Port, and 3,000/30,000 for Relay.
Keep `BILLING_YEARLY_ENABLED=false` until migration `0009` is applied and all old
backend and reconciliation replicas are drained, then enable it on every replica.
Keep NWC disabled until migration `0010` is applied, all old replicas are drained,
a dedicated credential keyring is mounted, and each user has validated a wallet
connection. The checked-in Compose environments remain Lightning-only.
Keep reminder email disabled until migration `0013` is applied and SMTP plus
recipient-encryption settings are installed. Reminder delivery does not require
customer NWC enablement.
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
Set `ADMIN_PRIVATE_CIDRS` to an operator VPN or fixed management source. Requests to
`/admin*`, `/api/v1/admin/*`, and `/api/v2/admin/*` from every other source receive `404`.
Admin browser sessions expire after `ADMIN_SESSION_MAX_AGE_SECONDS` (15 minutes by default),
and rotating `ADMIN_TOKEN` immediately invalidates both bearer access and existing sessions.

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
install -o 10001 -g 10001 -m 0400 /dev/null secrets/admin-token
install -o 10001 -g 10001 -m 0400 /dev/null secrets/lnd-invoice-hmac-key
install -o 10001 -g 10001 -m 0400 /path/to/tls.cert secrets/lnd-tls-cert
install -o 10001 -g 10001 -m 0400 /path/to/invoice.macaroon secrets/lnd-invoice-macaroon
install -o 10001 -g 10001 -m 0400 /dev/null secrets/credential-encryption-key
install -o 10001 -g 10001 -m 0400 /dev/null secrets/smtp-password
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
The backend image already contains the architecture-native compiled helper, so no
Node or Bun service runs in production. Each user should create a dedicated wallet
connection with a wallet-enforced budget and expiry that cover the selected renewal
term plus fees.

Optional stablecoin checkout requires no provider secret. Apply migration `0016`,
then roll out the new application code to every API and reconciler replica while
keeping `STABLECOIN_PAYMENTS_ENABLED=false` and the existing method allowlist.
After every old replica is drained, set
`PAYMENT_ENABLED_METHODS=lightning,stablecoin_swap`, verify
`BOLTZ_WEB_URL=https://boltz.exchange`, and set
`STABLECOIN_PAYMENTS_ENABLED=true` in a separate configuration rollout. The
checked-in default remains false. The default `STABLECOIN_SWAP_MARKUP_BPS=1000`
adds 10 percent to the LND invoice and
`STABLECOIN_SWAP_INVOICE_EXPIRY_SECONDS=1200` leaves time for the external swap
within the 1,800-second reservation. Disable the feature flag first during a
rollback. The flag blocks new checkout creation and removes the UI control;
reconciliation still settles or expires invoices issued before disablement so
customer payments and resource holds are not stranded. Do not deploy application code from before migration `0016` or
downgrade the migration while stablecoin payment rows remain; older code cannot
deserialize the new payment method.

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
Production requires TLS. For authenticated SMTP, set `SMTP_USERNAME`, create the
owner-only `smtp-password` file, and set
`SMTP_PASSWORD_FILE=/run/secrets/smtp-password`; username and password must be
present together. Omit both for a trusted relay. Set
`CREDENTIAL_ENCRYPTION_KEY_FILE=/run/secrets/credential-encryption-key` to protect
recipient addresses with a distinct encryption purpose, then set
`REMINDER_EMAIL_ENABLED=true`. Mount both secrets only on `backend`, never on
`migrate`, relay, proxy, or database services. The migration service forces reminders
off and needs neither runtime secret.

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

## Canary

The canary uses host networking for HAProxy, Caddy, and the relay. This is required so
the public IP configured for Blindport Port in the backend is also the actual address bound by
the relay. Ensure `PUBLIC_IP` is configured on the host. HAProxy owns `PUBLIC_IP:80`
and `PUBLIC_IP:443`; the relay owns the configured TCP/UDP Blindport Port range and
`PUBLIC_IP:5443`. Backend `:8000`, relay SNI `:4443`, Caddy `:8080/:8443`, and relay
admin `:9090` bind loopback only. Firewall all loopback-only surfaces from the public
interface.

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

For a bounded pre-LND forwarding test, the canary also permits
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

For onion access, install Tor on the host, copy `deploy/canary/torrc` to
`/etc/tor/torrc`, and persist `/var/lib/tor/blindport-canary` as secret key material.
Set `ONION_HOST` to the generated hostname. Tor maps Web traffic to loopback Caddy and
relay control to the additional loopback mTLS listener; no public firewall port is
required. The onion Web route intentionally returns 404 for admin and internal APIs.

The canary mounts `DOWNLOADS_DIR` read-only at `/srv/downloads`. Publish versioned
agent binaries and matching `.sha256` files there; never replace an existing
versioned artifact in place. Also publish `install.sh`, the current
`blindportd-linux-{amd64,arm64,armv7}` aliases, and their checksums. Stage and
verify all current-release aliases before renaming them into place together.

HAProxy sends PROXY v2 only on the API path, and Caddy accepts it only from loopback,
so Caddy and the backend receive the API client address in `X-Forwarded-For`. The
relay protocol does not accept PROXY headers. Every SNI connection therefore appears
to come from HAProxy; the Compose file deliberately sets relay per-source ingress to
the total ingress limit while retaining the total and SNI-peek bounds. HTTP ingress
rate limits also see HAProxy as one source and are explicitly sized for redirects and
multi-vantage ACME retries.

For independently hosted Relay edges, set `RELAY_PRIVATE_CIDRS` to their fixed source
addresses. Caddy permits those sources to reach `/internal/v1/*` and `/internal/v2/*`;
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
docker compose --env-file .env -f compose.yaml pull
docker compose --env-file .env -f compose.yaml --profile tools run --rm migrate
docker compose --env-file .env -f compose.yaml up -d
docker compose --env-file .env -f compose.yaml ps
```

## Split control host

Point `API_DOMAIN` at `CONTROL_BIND_IP`. PostgreSQL and backend have no published
ports. Caddy publishes only `:80/:443`. `RELAY_PRIVATE_CIDRS` is a space-separated
allowlist for `/internal/v1/*` and `/internal/v2/*`; all other clients receive 404
for internal routes.
Route `API_DOMAIN` to the control host's private IP from the relay host, while keeping
normal public DNS for users. TLS still authenticates the API hostname.

Run `pull`, the one-shot `migrate` command, and `up -d` as shown for the canary, from
`deploy/split/control`.

## Split relay host

Ensure `RELAY_PUBLIC_IP` is configured on the relay host. The relay binds that IP on
`:80` for HTTPS redirects and HTTP-01, `:443` for SNI, `:5443` for client control, and every
configured TCP/UDP Blindport Port. Relay admin remains on loopback
`:9090`. Permit the relay host's private source address through the control Caddy
allowlist and verify `BACKEND_INTERNAL_URL` resolves over that private route.

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
`compose.wireguard.yaml` on both the control and relay host. For the canary, the
single overlay configures both services:

```sh
docker compose --env-file .env -f compose.yaml -f compose.wireguard.yaml up -d
```

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
