# Blindport architecture

## Planes

Blindport has three components:

1. The FastAPI control plane owns accounts, subscriptions, payments, resource
   reservations, and authorization.
2. `blindport-relay` owns public TCP and UDP listeners for framed delivery. It
   also optionally reconciles provider-routed IPv4 `/32`s and WireGuard peers.
3. `blindportd` maps framed subscriptions to local TCP or UDP upstreams, or in
   routed mode owns assigned `/32`s on a Linux WireGuard interface.

Framed delivery is L4 forwarding, not routed L3. WireGuard Blindport IP is a distinct
routed plane and does not use the framed tunnel protocol.

## Products and inventory

| Product | Leased identity | Delivery |
| --- | --- | --- |
| Blindport IP | one dedicated public IP | annual routed WireGuard `/32` |
| Blindport Port | one shared public IP, one port, and TCP or UDP | exact destination socket |
| Blindport Relay | one exact hostname or customer-owned wildcard base | TLS ClientHello SNI on a shared listener |

`WIREGUARD_PUBLIC_IPS` is the current Blindport IP sale inventory and must not be
bound as relay listener addresses. `RELAY_PUBLIC_IPS` is retained only for
already-active historical framed IP records. `RELAY_SHARED_IPS` is shared
Blindport Port and SNI ingress inventory. All three lists must be disjoint. A
Blindport Port lease also comes from the inclusive `RELAY_SHARED_TCP_PORTS` or
`RELAY_SHARED_UDP_PORTS` range. TCP and UDP on the same numeric IP/port are
distinct lease identities and may belong to different subscriptions. Separate
transport capacity settings cap advertised leases, and each relay binds a leased
socket only while its authenticated agent tunnel is active.

## Reservation and payment lifecycle

Docker agents may declare a Relay or Port order through idempotent
`PUT /api/v1/client/orders/{order_key}`. Revision `0012` stores the immutable,
account-scoped declaration and its subscription. Replaying the same key returns
the original subscription; changing its product, term, transport, delivery, or
domain returns a conflict. An optional initial NWC payment carries a unique link
to that order before any wallet call, so daemon retries, concurrent requests, and
process failures cannot turn discovery into duplicate subscriptions or spending.
An active replay never creates a renewal. Terminal initial payments require an
explicit account action.

Creating a subscription records requested product state but does not allocate a
scarce IP or socket. Before an external invoice or wallet request is created,
the backend reserves capacity on the subscription for one payment ID. If no
capacity exists, the payment endpoint returns `409` without calling the payment
adapter.

Port and Relay subscriptions snapshot monthly and yearly prices at creation and
keep a preferred billing term. New IP subscriptions always select yearly
WireGuard delivery. A payment independently snapshots the selected term, charged
amount, markup, and period length (30 service days monthly or 365 service days yearly).
Lightning Swap provider minimum top-ups receive proportionally rounded-up bonus time;
the payment snapshot is authoritative at settlement, including after configuration,
price, or preference changes.
An exact customer-owned Relay upgrade creates a linked pending wildcard subscription
at the exact hostname's immediate parent. Remaining exact time is valued using the
source subscription's snapshotted monthly or yearly daily rate, rounded down to
satoshis, capped at the selected wildcard price, and snapshotted as a payment discount.
The exact claim remains authorized and cannot renew while the upgrade is pending.
Settlement activates the verified wildcard and releases the exact claim in the same
transaction. A fully credited upgrade uses a zero-amount paid record without creating
an external invoice.
Historical framed or monthly IP records cannot create new payments or automatic
renewals. Yearly issuance is feature-gated during rollout. The gate remains disabled while
old replicas are present because those replicas do not understand a payment's
snapshotted day count; already-issued payments remain settleable when the gate is
later disabled.

Reservations expire after `RESOURCE_RESERVATION_TTL_SECONDS`, and payment expiry
is capped at the reservation ownership deadline. Provider state is queried
before an elapsed Lightning, stablecoin swap, or NWC payment is expired locally. Release paths
compare the reservation payment ID, so an old payment cannot clear a newer
payment's hold. Lightning invoice expiry is also bounded before invoice creation
by the remaining resource or domain eligibility window, less a configured
safety interval. Windows shorter than the configured minimum payable duration
are rejected before the adapter is called.

Only one payment may own a subscription reservation at a time. A request for a
different method receives a structured conflict containing the existing payment,
allowing clients to restore that checkout. Blindly replacing an open BOLT11 is
not allowed because a late settlement of the replaced invoice could otherwise
grant an unintended second service period.

Settlement conditionally changes one open payment to paid and updates the
subscription in the same transaction. This makes repeated or concurrent polls
grant at most one snapshotted period and updates the preferred term to the term
that settled.

Every API replica also runs a bounded background reconciler after migrations and
admin bootstrap. It scans pending Lightning, stablecoin swap, and NWC rows in payment ID order,
excluding methods disabled in the current configuration so stale rows cannot
consume the enabled-method batch. It checks provider settlement before expiry
and isolates each row in its own session so malformed data or one provider
failure does not stop the batch. The same conditional settlement transaction
makes concurrent replica cycles and request polling idempotent; no distributed
worker lock is used.

Reconciler freshness is process-local and protected by a small lock because
cycles run in worker threads while readiness runs on request threads. Readiness
allows a bounded startup grace, then requires a recent completed cycle in
production and whenever reconciliation is enabled. This exposes a stuck worker
without disclosing provider errors.

Lightning issuance uses a durable outbox transition. The backend first commits
the payment row, capacity ownership, local deadline, unique invoice identity,
and expected payment hash. A dedicated HMAC key deterministically derives the
LND preimage from that identity without storing the preimage. It then looks up
the hash before calling `AddInvoice` with the preimage, and looks up again after
an ambiguous create failure. LND returns the original BOLT11 string for an
existing hash. Amount, memo, and hash must all match before the invoice is bound
to the payment row. A process failure at either external boundary is recovered
by request retry or background reconciliation without issuing a second invoice.
Concurrent replicas converge through the unique identity/hash indexes, a
PostgreSQL row lock around issuance and expiry, and a conditional invoice-binding
update.

Stablecoin checkout reuses this LND outbox. Each payment snapshots its selected
provider, checkout origin, and asset. Boltz receives a prefilled web URL from the
bound BOLT11 invoice. Lightning Swap opens a new tab at its snapshotted origin with
`/?invoice=<percent-encoded BOLT11>`, which prefills the invoice in the provider UI.
`STABLECOIN_SWAP_MIN_INVOICE_SATS` is a conservative static floor, and a floor top-up
receives proportionally rounded-up bonus service time. LND invoice settlement is the
only activation authority.
Migration `0026` marks legacy stablecoin rows as Boltz payments but leaves their
origin and asset unset because historical custom configuration is not recoverable;
those rows therefore cannot generate a new external checkout URL.
Migration `0027` retains historical API-order snapshots and encrypted-token storage as
inert compatibility columns. Deployed data prevents a lossy downgrade, but runtime no
longer creates or reads orders.
Migration `0028` separates the configured stablecoin surcharge from provider-minimum
top-ups so credited days can be validated at settlement. Migration `0029` adds linked
Relay upgrade and immutable service-price and discount snapshots.
Migration `0030` retains historical deposit instruction columns as inert compatibility
columns. Deployed data prevents a lossy downgrade, but runtime no longer returns those
fields.

NWC pays that same Blindport-owned LND invoice. Account connection URIs are
AES-256-GCM envelopes bound to the public account UUID and `nwc` purpose; payment
rows snapshot the credential generation. A single-shot compiled Bun helper owns
NIP-47 and NIP-44 handling and communicates with Python only through bounded JSON
stdin/stdout. It validates wallet service metadata before every operation, always
prefers NIP-44 v2, and rejects missing pay/lookup capabilities. Operators can
explicitly allow compatibility with providers that advertise only legacy NIP-04.
Each connection URI supplies its own relay URLs. Deployments either restrict those
URLs to exact configured hostnames or admit only `wss:443` hostnames whose complete
DNS result is globally routable; Python and the helper precheck the policy separately.
The SDK resolves again when connecting, so these checks do not eliminate DNS rebinding;
deployments requiring a hard boundary also enforce network-level egress policy.
Credential setup can atomically record explicit per-subscription renewal consent.

An NWC payment records its attempt before calling the wallet and claims a bounded
database lease around lookup/send decisions. LND is checked first. Any previous
attempt requires outgoing lookup before another send, and only an explicit failed
or not-found lookup can cross the retry boundary after bounded backoff. Pending or
inconclusive state never resends. Returned preimages must hash to the immutable
LND payment hash. The existing one-open-payment uniqueness index and conditional
settlement transaction prevent concurrent renewal creation and duplicate credit.
The reconciler also creates due automatic renewals, using the same payment service
as manual `method=nwc` requests.

Active expiration changes authorization to `EXPIRED` immediately but retains a
dedicated Blindport IP or Blindport Port tuple until `RESOURCE_REUSE_QUARANTINE_SECONDS` elapses.
The expired subscription cannot open a new payment during its quarantine. A
historical framed IP cannot open another payment at all. At
release, an open renewal payment is reconciled first; settlement reactivates the
same assignment, while pending or uncertain provider state retains it until the
payment can be resolved safely. For renewable products, a later payment after
release reserves current capacity and may receive a different assignment.

Database uniqueness constraints protect dedicated IPs, shared
`(IP, port, transport)` tuples, and one open (`PENDING` or `PROCESSING`) payment
per subscription.
Allocation retries candidates after a uniqueness conflict, so PostgreSQL can
coordinate concurrent workers through those constraints. SQLite serializes
writes and remains supported only for the single-process experimental stack.

The SQLModel metadata is the application schema contract, while explicit
Alembic revisions in the installed `blindport.migrations` package own schema
creation and upgrades. Application startup never calls `metadata.create_all()`.

Blindport Relay's unique domain row is its reservation. Provider-managed names are
immediately verified only when they are strictly below a configured managed
suffix. At creation, exact customer-owned names receive a unique CNAME target
whose lowercase child label contains 128 bits of cryptographic randomness. The
target is stored in the existing pool-domain field and remains stable for the
retained claim. Exact customer claims cannot create a payment until the requested
hostname has one direct CNAME answer exactly equal to that target. Pending exact
rows with a retained TXT token use the claimed hostname as the TXT owner name;
new exact rows never receive a token.

Customer-owned wildcard claims retain a TXT ownership token at the claimed base
and one selected Relay pool base. Payment requires only the TXT ownership proof.
The token is an additional TXT value, so it coexists with SPF and site-verification
records at that name. The displayed `*.<base>` CNAME and optional base record
control routing and are deliberately outside payment verification, allowing the
customer to move traffic after setup.
The same wildcard price and claim route the base plus all descendants. Exact SNI
routes take precedence, then a wildcard at the requested base, then the longest
matching wildcard suffix.

Unverified claims and verified-but-unpaid claims retain a one-hour eligibility
deadline; managed unpaid claims retain a 30-minute deadline. Successful
verification does not extend or remove that deadline. An account may hold at
most two unpaid Relay claims. When an active claim expires, authorization stops
immediately and a separate renewal deadline reserves the verified domain for its
existing owner. Creating a payment during that bounded grace repeats the exact
CNAME check or wildcard TXT ownership check before the same domain
can reactivate. The periodic payment reconciler and request-time reaper cancel
elapsed claims and clear the domain, verification fields, and pool-domain
assignment. Active rows and unelapsed renewal holds do not match the release
update. Before release, the reaper checks open Lightning, stablecoin swap, and
NWC payments against their providers so a boundary settlement wins. An uncertain
provider check or an irreversible `PROCESSING` payment retains the claim for
operator reconciliation. The final release is conditional on no open payment,
while payment settlement remains a one-time conditional transaction. Pool-domain
assignment is load-distribution metadata and is not scarce socket inventory.

An optional process-local Bitcoin/USD cache fetches the fixed mempool.space price
endpoint outside request handling. Strictly validated last-good values may be used
for approximate UI labels for 30 minutes. This advisory cache is not a readiness
dependency and never participates in pricing snapshots, invoices, or settlement.

## Data paths

Historical framed Blindport IP and current Blindport Port dispatch do not inspect
payloads:

```text
external TCP client -> relay dedicated IP or exact shared socket
                    -> tunnel stream keyed by authorized claim
                    -> blindportd -> mapping-specific local TCP upstream
```

For a UDP Blindport Port lease, the relay keeps one bounded, idle-expiring association
per direct external source address:

```text
external UDP datagram -> relay exact shared UDP socket
                      -> one tunnel datagram stream for that source
                      -> blindportd -> connected local UDP upstream
```

Each protocol datagram frame carries one complete UDP payload, up to 65,507
bytes. The control tunnel remains TCP, so datagrams are reliable and ordered
inside the tunnel and can experience head-of-line blocking. This preserves
packet boundaries and request/response source association, but not native UDP
loss or latency behavior.

Blindport Relay reads only enough TLS ClientHello bytes to obtain SNI, then replays
those bytes through the tunnel. User TLS remains end to end between the external
client and local upstream.

An opt-in mapping can prepend PROXY protocol v2 on the local TCP connection. The
Relay records the direct external peer and accepted listener address separately
from the authorization-sensitive logical destination. `blindportd` validates and
encodes those addresses before sending application bytes. This lets a narrowly
trusted local reverse proxy recover the client address without terminating TLS at
the provider edge. Without this option, the upstream observes the agent's local
address.

SNI dispatch checks an exact hostname tunnel first. It then checks a wildcard
tunnel whose base equals the requested hostname, followed by wildcard suffixes
from longest to shortest. This preserves exact-route precedence and label
boundaries while including the wildcard base itself.

When the optional HTTP listener is enabled, it accepts bounded HTTP/1.1 `GET`
requests with a canonical domain Host. Requests below
`/.well-known/acme-challenge/` use the same exact-first and longest-wildcard claim
selection as TLS ingress, but
the tunnel stream has destination port 80 so `blindportd` can dial a separate
plaintext challenge upstream. Other paths receive a bodyless `308 Permanent
Redirect` to the same host, path, and query over HTTPS without a tunnel lookup.
Other methods, request bodies, malformed hosts, and malformed ACME paths are
rejected.

One tunnel carries length-prefixed JSON control frames and multiplexed stream or
datagram frames. See `protocol.md` for framing limits and claim definitions.

Routed Blindport IP has a separate packet path:

```text
external IP packet -> provider route to relay -> authorized WireGuard peer
                    -> customer Linux interface owning the leased /32

customer packet sourced from leased /32 -> WireGuard peer -> relay policy
                                         -> external IPv4 destination
```

The relay installs each active `/32` as a link route to WireGuard and blackholes
inactive or unenrolled managed inventory. The agent installs the `/32` locally
and uses a source rule plus a dedicated default-route table for replies. It does
not replace the host default route. The relay performs no source or destination
NAT, so the application observes the external peer and uses the leased address
as its source. Applications can explicitly bind the leased address for new
outbound connections; those packets use the same source rule and public identity.
The route is layer 3 rather than a per-service tunnel, so it carries
TCP, native UDP, ICMP, arbitrary ports, and other IPv4 protocol numbers without
framed TCP head-of-line behavior. Current routed support is IPv4 `/32` only with
MTU 1420 and requires Linux network administration capability at both endpoints.

The relay reconciles an nftables policy in the dedicated `inet blindport` table
before activating routes. Customer packets cannot target the relay host or
non-global IPv4 ranges. New outbound TCP connections to port 25 are denied unless
the current active IP lease has an operator-reviewed paid exception. The policy,
peer set, and routes fail closed together when backend state becomes stale.

Revision `0017` records every dedicated IP assignment episode independently of
the compatibility assignment columns on `Subscription`. Reservation, activation,
quarantine, release, SMTP review, and revocation remain available after an address
is reassigned.

## Authentication and revocation

The account bearer token is stored as a keyed hash. Relays resolve it through
`POST /internal/v1/resolve`, authenticated with `X-Relay-Secret`. The tunnel is
also protected by backend-issued mutual TLS: the client certificate identity
must match the user resolved from the token, and the server certificate covers
configured relay hostnames plus dedicated and shared listener IPs.

Current clients generate a stable Ed25519 key locally and submit only a signed
CSR. The backend persists one instance UUID, public-key fingerprint, and current
certificate generation per account. Identical generation retries return the
same certificate; renewal requires the next generation and the same public key.
Production disables the legacy endpoint that generated and returned private
keys. Agent credentials are written atomically to owner-only local state and
renewed in-process before expiry. Lost-key replacement is deliberately an
operator reset, not a bearer-authenticated self-service action.

The routed agent generates a separate WireGuard private key in the same private
state directory. Enrollment binds its public key, instance UUID, and monotonic
generation with a signature from the stable Ed25519 client identity. The relay
fetches complete desired-state snapshots over its secret-authenticated backend
channel. It blackholes revoked prefixes before removing peers and fails the
whole routed plane closed when backend state exceeds configured staleness. A
peer is authorized only while its instance UUID still matches the account's
current client credential, so an operator identity reset also revokes its routed
access.

The relay authorizes the complete claim, including Blindport Port transport, IP, and
port. It periodically resolves established claims again. Successful resolution
that no longer contains the claim closes the tunnel. Temporary backend errors
retain the existing session only until the configured maximum authorization
staleness, after which the relay closes it.

The relay currently checks the certificate's account CN at connection time but
does not send its URI instance ID or serial through authorization resolution.
Consequently, replacing the database credential does not revoke an already
issued leaf; token rotation or CA-level action is still required for immediate
device revocation.

## DNS and high availability

The production topology, database fencing, address constraints, and limits of the
local fault lab are described in [High availability](ha.md).

Blindport Relay has three DNS operating models:

1. **Managed wildcard:** the provider configures suffixes such as
   `relay.example.net`, publishes wildcard ingress records, and leases only
   names strictly below each suffix. The suffix apex remains provider-owned.
2. **Customer-owned DNS:** an exact-name customer publishes one CNAME from the
   requested hostname to the unique target returned by the subscription API.
   The control plane makes a bounded direct CNAME query with resolver search
   disabled and requires the one returned absolute target to equal the assigned
   target after canonicalization. A wildcard customer publishes its TXT ownership
   value at the claimed base before payment, alongside any SPF or site-verification
   TXT values, and later points a wildcard CNAME to the selected Relay pool when
   ready to route traffic. TXT proof discovery uses the configured recursive resolver
   to find the closest zone, nameservers, and their addresses, then queries vetted
   globally routable authoritative addresses directly without recursion and requires
   the authoritative answer bit. Neither that CNAME nor the wildcard's optional base
   record is verified for payment. The wildcard record does not match the base itself,
   so base routing uses a separate record to the same pool target. Subdomain bases can
   use CNAME. Mandatory NS and SOA records prevent a conventional CNAME at a zone
   apex, which instead uses the authoritative DNS service's ALIAS, ANAME, or
   CNAME-flattening feature. Exact-name verification does not follow CNAME chains or
   accept failed lookups.
3. **Operator DNS supervision:** an opt-in worker checks exact configured public A-record
   sets through multiple explicit recursive resolvers and retains one latest sanitized
   observation per name. It does not mutate authoritative DNS. A future fenced registrar or
   authoritative-DNS adapter may create or withdraw records and invoke the same control-plane
   subscription and verification endpoints.

Blindport is not currently authoritative for customer DNS. Its backend uses an
external recursive resolver for authority discovery and directly queries the
discovered authoritative servers for TXT proof; operators remain responsible for
the wildcard, A, and AAAA records that direct traffic to relay ingress.
Operators must publish wildcard ingress records below every configured relay
pool base so generated customer targets resolve at the relay edges.

Blindport Relay DNS may publish multiple A/AAAA records for active-active relay nodes.
Every advertised node must be able to authorize the same claim, and every such
edge must appear in `RELAY_CONTROL_URLS` so provisioning causes `blindportd`
to maintain a tunnel there. Workers reconnect independently, so one unavailable
edge does not stop the other mappings or edges. DNS does not preserve, migrate,
or resume established TCP sessions when answers or edge health change.

Historical framed Blindport IP and current Blindport Port provisioning contains
only `RELAY_CONTROL_URL`. Their failover requires the leased IPs to be announced
or moved between relay nodes because DNS does not move those socket identities. Routed Blindport IP failover
likewise requires the provider route to move to a relay with the same backend
state and WireGuard key; BGP and multi-relay key rotation are not implemented.
