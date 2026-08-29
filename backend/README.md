# Blindport backend

FastAPI + SQLModel control plane for Blindport IP, Blindport Port, and Blindport Relay.

See repo root README for project overview.

## Production settings

Production requires dedicated, distinct values for `SECRET_KEY`, `TOKEN_HASH_KEY`,
`RELAY_SECRET`, `ADMIN_TOKEN`, and `LND_INVOICE_HMAC_KEY`. The token and relay keys fall back
to `SECRET_KEY` only outside production for local compatibility. Product sales and account
limits are controlled explicitly:

```env
SECRET_KEY=<dedicated-application-secret>
PUBLIC_SITE_URL=https://api.example.com
TOKEN_HASH_KEY=<dedicated-token-hashing-secret>
RELAY_SECRET=<dedicated-relay-authentication-secret>
ADMIN_TOKEN=<dedicated-admin-bearer-token>
LND_INVOICE_HMAC_KEY=<dedicated-64-character-lowercase-hex-key>
IP_ENABLED=true
IP_SALES_PAUSED=false
PORT_ENABLED=true
PORT_SALES_PAUSED=false
RELAY_ENABLED=true
RELAY_SALES_PAUSED=false
RELAY_MANAGED_DOMAIN_CAP=1000
RELAY_CUSTOMER_DOMAINS_ENABLED=true
RELAY_MANAGED_DOMAIN_CLAIM_TTL_SECONDS=1800
RELAY_DOMAIN_CLAIM_TTL_SECONDS=3600
ACCOUNT_MAX_NON_CANCELLED_SUBSCRIPTIONS=20
ACCOUNT_MAX_OPEN_PAYMENTS=5
ACCOUNT_MAX_PENDING_RELAY_CLAIMS=2
BTC_USD_PRICE_ENABLED=true
BTC_USD_PRICE_REFRESH_SECONDS=300
BTC_USD_PRICE_MAX_STALE_SECONDS=1800
RATE_LIMIT_SIGNUP_REQUESTS=10
RATE_LIMIT_SIGNUP_WINDOW_SECONDS=60
RATE_LIMIT_ADMIN_LOGIN_REQUESTS=5
RATE_LIMIT_ADMIN_LOGIN_WINDOW_SECONDS=300
RATE_LIMIT_PAYMENT_CREATE_REQUESTS=60
RATE_LIMIT_PAYMENT_CREATE_WINDOW_SECONDS=60
RATE_LIMIT_DOMAIN_VERIFY_REQUESTS=20
RATE_LIMIT_DOMAIN_VERIFY_WINDOW_SECONDS=60
RATE_LIMIT_CLIENT_CERT_REQUESTS=20
RATE_LIMIT_CLIENT_CERT_WINDOW_SECONDS=300
RATE_LIMIT_BUCKET_RETENTION_SECONDS=3600
RATE_LIMIT_CLEANUP_INTERVAL_SECONDS=60
RATE_LIMIT_CLEANUP_BATCH_SIZE=500
RATE_LIMIT_MAX_BUCKETS=100000
```

The public `GET /api/v1/catalog` endpoint reports prices, sales state, and conservative current
capacity. Direct Lightning remains mandatory in production. NWC can be enabled alongside it only
with the compiled helper, the `nwc` adapter, payment reconciliation, and a dedicated credential
encryption key. Checked-in production manifests keep NWC disabled until those secrets and user
wallet connections are provisioned. Each account submits its complete connection URI. Operators
must choose either globally routable user-selected `wss:443` relays or a strict exact-host
allowlist; the URI is encrypted after live capability validation and is never returned.

Stablecoin checkout is separately gated by `STABLECOIN_PAYMENTS_ENABLED` and also requires
`stablecoin_swap` in `PAYMENT_ENABLED_METHODS`. New installs use
`STABLECOIN_CHECKOUT_PROVIDER=lightning_swap` and
`LIGHTNING_SWAP_WEB_URL=https://lightning-swap.com`; `boltz` remains available with
`BOLTZ_WEB_URL`. Megalithic's guide recommends Lightning Swap. Blindport opens a new
tab at the snapshotted Lightning Swap origin with
`/?invoice=<percent-encoded BOLT11>`, prefilled in the provider UI, before the customer
selects `LIGHTNING_SWAP_DEFAULT_ASSET=USDCSOL` (USDC on Solana).
`STABLECOIN_SWAP_MARKUP_BPS=1000` applies a 10 percent satoshi surcharge with round-up.
The final amount is at least `STABLECOIN_SWAP_MIN_INVOICE_SATS=5000`, a conservative
static floor. Any minimum top-up earns proportional service time rounded up to a whole
day. Blindport relies only on LND settlement for activation and never trusts provider
callbacks.

The optional Bitcoin/USD display cache reads the fixed mempool.space price endpoint in the
background. It never changes invoices or settlement amounts, retains a last-good value for 30
minutes, and omits USD estimates when no sufficiently fresh value exists.

ACCOUNT lifecycle mail is gated by `REMINDER_EMAIL_ENABLED`; SERVICE announcements
are separately gated by `ANNOUNCEMENT_EMAIL_ENABLED`. When enabled, recipient
addresses are encrypted with purpose-specific AES-GCM associated data and never
returned after submission. Configure `SMTP_HOST`, `SMTP_PORT`,
`SMTP_SECURITY=starttls|tls`, `SMTP_FROM_EMAIL`, and `SMTP_TIMEOUT_SECONDS`.
`SMTP_USERNAME` and the file-backed `SMTP_PASSWORD_FILE` input must be configured together, or
both omitted for a trusted local relay. Production requires TLS. The durable outbox
stores no recipient, subject, or body plaintext and uses a deterministic Message-ID.
The unified notification worker is independent of payment reconciliation, handles
activation, renewal, seven-day, one-day, and actual-expiry events, expands campaign
snapshots in bounded pages, and drains legacy outboxes. SMTP servers necessarily
receive each recipient and generated message in plaintext.

Direct-client limits use FastAPI's trusted `Request.client` value and never parse forwarded headers.
The production ASGI server and any serving proxy must therefore be configured with an explicit
trusted-proxy policy. The shipped image trusts forwarded headers only from loopback. Keep the
backend private, and require the immediate proxy to replace client-supplied forwarded headers.
Alternate proxy topologies must replace the image policy with only the exact proxy addresses,
never `*`. Source-derived identifiers are HMACed in process-local memory and expire at
the end of the fixed window using an ephemeral per-process key; they are never inserted into
PostgreSQL. Durable rate-limit rows use account-derived identifiers only. Both stores are capped by
`RATE_LIMIT_MAX_BUCKETS`.

Production relay listener inventories must contain only globally routable unicast addresses.
Relay control/WireGuard endpoints, relay pool domains, and managed suffixes must use public DNS
names rather than development names such as `.test`, `.localhost`, or `.local`. Empty inventory and
pool settings are valid and report unavailable capacity through the catalog. These checks do not
apply to private payment-provider endpoints such as an internal LND hostname.

Each `RELAY_POOL_DOMAINS` entry must leave room for a 32-character generated child label. Operators
must publish wildcard ingress records below each pool base. New exact customer-owned Relay claims
receive one stable, random child target at creation and must point the requested hostname directly to
it with a CNAME before payment. Wildcard claims instead retain a TXT ownership token at the claimed
base domain, which is the only proof required before payment. Publish it as an additional TXT value so
it coexists with SPF and site-verification records. Their wildcard CNAME to a selected pool base
controls routing and can be added later for a no-downtime cutover. The wildcard scope routes its base
plus all descendants; pointing the base is optional and is not checked before payment.
