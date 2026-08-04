# Production deployment artifacts

These Compose stacks are intentionally single-instance deployments. The canary runs on
one dedicated host. The split stack separates control and relay
failure domains, but neither stack provides database, proxy, relay, or API high
availability.

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
Keep proxy and Uvicorn access logging disabled. Configure firewall, kernel, Tor,
database, backup, monitoring, and external log collectors so request or visitor
source addresses are not retained and all operational logs expire within 30 days.
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
install -o root -g root -m 0400 /dev/null secrets/postgres-password
```

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
Set `NWC_ALLOWED_RELAY_HOSTS` to the exact trusted `wss` relay hostnames; this is
an egress boundary, uses only standard port 443, and must not contain wildcards.
The backend image already contains the architecture-native compiled helper, so no
Node or Bun service runs in production. Wallet-side budgets and connection expiry
remain operator/user policy and must cover the selected renewal term plus fees.

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
agent binaries and matching `.sha256` files there; never replace an existing versioned
artifact in place.

HAProxy sends PROXY v2 only on the API path, and Caddy accepts it only from loopback,
so Caddy and the backend receive the API client address in `X-Forwarded-For`. The
relay protocol does not accept PROXY headers. Every SNI connection therefore appears
to come from HAProxy; the Compose file deliberately sets relay per-source ingress to
the total ingress limit while retaining the total and SNI-peek bounds. HTTP ingress
rate limits also see HAProxy as one source and are explicitly sized for redirects and
multi-vantage ACME retries.

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
allowlist for `/internal/v1/*`; all other clients receive 404 for internal routes.
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

No deployment sets framed `RELAY_PUBLIC_IPS`, `WIREGUARD_PUBLIC_IPS`, or WireGuard
keys/endpoints. The relay has only `NET_BIND_SERVICE` for direct `:80/:443`; it never has
`NET_ADMIN`. Add host firewall rules for `80/tcp`, `443/tcp`, `5443/tcp`, and the
configured TCP and UDP Blindport Port ranges. Do not expose `9090/tcp`.

```sh
docker compose --env-file .env -f compose.yaml pull
docker compose --env-file .env -f compose.yaml up -d
docker compose --env-file .env -f compose.yaml ps
```

## Validation

The repository validator uses example values and does not start Blindport services, contact
LND, request certificates, or require usable secrets:

```sh
./deploy/validate.sh
```

After deployment, verify the backend and relay readiness through container health,
test API HTTPS from outside, test relay mTLS enrollment through `:5443`, and exercise
one TCP, one UDP, one Blindport Relay TLS, and one HTTP-01 path before accepting testers.
