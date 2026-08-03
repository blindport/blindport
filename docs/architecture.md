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
| Blindport IP | one dedicated public IP | framed TCP listeners or routed WireGuard `/32` |
| Blindport Port | one shared public IP, one port, and TCP or UDP | exact destination socket |
| Blindport Relay | one hostname | TLS ClientHello SNI on a shared listener |

`RELAY_PUBLIC_IPS` is framed Blindport IP inventory. `WIREGUARD_PUBLIC_IPS` is
provider-routed IPv4 inventory that must not be bound as relay listener
addresses. `RELAY_SHARED_IPS` is shared Blindport Port and SNI ingress inventory. All
three lists must be disjoint. A Blindport Port lease
also comes from the bounded inclusive `RELAY_SHARED_TCP_PORTS` or
`RELAY_SHARED_UDP_PORTS` range. TCP and UDP on the same numeric IP/port are
distinct lease identities and may belong to different subscriptions.

## Reservation and payment lifecycle

Docker agents may declare an order through idempotent
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

Subscriptions snapshot monthly and yearly prices at creation and keep a preferred
billing term. A payment independently snapshots the selected term, amount, and
fixed period length (30 service days monthly or 365 service days yearly). The
payment snapshot is authoritative at settlement, including after configuration,
price, or preference changes.
Yearly issuance is feature-gated during rollout. The gate remains disabled while
old replicas are present because those replicas do not understand a payment's
snapshotted day count; already-issued payments remain settleable when the gate is
later disabled.

Reservations expire after `RESOURCE_RESERVATION_TTL_SECONDS`, and payment expiry
is capped at the reservation ownership deadline. Provider state is queried
before an elapsed Lightning or NWC payment is expired locally. Release paths
compare the reservation payment ID, so an old payment cannot clear a newer
payment's hold. Lightning invoice expiry is also bounded before invoice creation
by the remaining resource or domain eligibility window, less a configured
safety interval. Windows shorter than the configured minimum payable duration
are rejected before the adapter is called.

Settlement conditionally changes one open payment to paid and updates the
subscription in the same transaction. This makes repeated or concurrent polls
grant at most one snapshotted period and updates the preferred term to the term
that settled. Cashu first commits a `PENDING` to `PROCESSING` claim;
only that claimant may mint or swap. An uncertain external error becomes
`FAILED` and requires operator reconciliation because the proofs may already be
spent. Cashu remains experimental.

Every API replica also runs a bounded background reconciler after migrations and
admin bootstrap. It scans pending Lightning and NWC rows in payment ID order,
excluding methods disabled in the current configuration so stale rows cannot
consume the enabled-method batch. It checks provider settlement before expiry
and isolates each row in its own session so malformed data or one provider
failure does not stop the batch. The same conditional settlement transaction
makes concurrent replica cycles and request polling idempotent; no distributed
worker lock is used. `PROCESSING` Cashu is excluded and remains an operator-only
reconciliation state.

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

NWC pays that same Blindport-owned LND invoice. Account connection URIs are
AES-256-GCM envelopes bound to the public account UUID and `nwc` purpose; payment
rows snapshot the credential generation. A single-shot compiled Bun helper owns
NIP-47 and NIP-44 handling and communicates with Python only through bounded JSON
stdin/stdout. It validates wallet service metadata before every operation and
rejects NIP-04 or missing pay/lookup capabilities.

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
The expired subscription cannot open a new payment during its quarantine. At
release, an open renewal payment is reconciled first; settlement reactivates the
same assignment, while pending or uncertain provider state retains it until the
payment can be resolved safely. Once released, a later payment reserves current
capacity and may receive a different assignment.

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
suffix. At creation, customer-owned names receive a unique CNAME target whose
lowercase child label contains 128 bits of cryptographic randomness. The target
is stored in the existing pool-domain field and remains stable for the retained
claim. Customer claims cannot create a payment until the requested hostname has
one direct CNAME answer exactly equal to that target. Unverified
claims, verified-but-unpaid claims, and managed unpaid claims all retain the
same initial eligibility deadline and release their unique domain after it.
Successful verification does not extend or remove that deadline. Pending rows
with a pre-rollout TXT token retain the legacy TXT path until their existing
claim expires; new rows never receive a token. When an active claim expires,
authorization stops immediately and a
separate renewal deadline reserves the verified domain for its existing owner.
Creating a payment during that bounded grace requires another exact CNAME lookup
before the same domain can reactivate. After grace, a conditional lazy reaper cancels the subscription and
clears the domain, verification fields, and pool-domain assignment. Active
rows and unelapsed renewal holds do not match the release update. Before release,
the reaper checks open Lightning and NWC payments against their providers so a
boundary settlement wins. An uncertain provider check or an irreversible
`PROCESSING` payment retains the claim for operator reconciliation. The final
release is conditional on no open payment, while payment settlement remains a
one-time conditional transaction. Pool-domain assignment is load-distribution
metadata and is not scarce socket inventory.

## Data paths

Framed Blindport IP and Blindport Port dispatch do not inspect payloads:

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

When the optional HTTP-01 listener is enabled, it accepts only one bounded
HTTP/1.1 `GET` below `/.well-known/acme-challenge/`. The validated Host selects
the same active Blindport Relay claim, but the tunnel stream has destination port 80
so `blindportd` can dial a separate plaintext challenge upstream. Other methods,
paths, request bodies, malformed hosts, and general HTTP traffic are rejected.

One tunnel carries length-prefixed JSON control frames and multiplexed stream or
datagram frames. See `protocol.md` for framing limits and claim definitions.

Routed Blindport IP has a separate packet path:

```text
external IP packet -> provider route to relay -> authorized WireGuard peer
                   -> customer Linux interface owning the leased /32
```

The relay installs each active `/32` as a link route to WireGuard and blackholes
inactive or unenrolled managed inventory. The agent installs the `/32` locally
and uses a source rule plus a dedicated default-route table for replies. It does
not replace the host default route. The relay performs no source or destination
NAT, so the application observes the external peer and uses the leased address
as its source. Current routed support is IPv4 `/32` only with MTU 1420.

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

Blindport Relay has three DNS operating models:

1. **Managed wildcard:** the provider configures suffixes such as
   `relay.example.net`, publishes wildcard ingress records, and leases only
   names strictly below each suffix. The suffix apex remains provider-owned.
2. **Customer-owned DNS:** the customer requests an arbitrary hostname and
   publishes one CNAME from that hostname to the unique target returned by the
   subscription API. The control plane makes a bounded direct CNAME query with
   resolver search disabled and requires the one returned absolute target to
   equal the assigned target after canonicalization. It does not follow CNAME
   chains or accept A/AAAA flattening, another pool target, or failed lookups.
3. **Future DNS automation:** a registrar or authoritative-DNS integration may
   create records and invoke the same control-plane subscription and
   verification endpoints. No such automation is implemented yet.

Blindport is not currently authoritative for customer DNS. Its backend only
queries an external recursive resolver, and operators remain responsible for
the wildcard, A, and AAAA records that direct traffic to relay ingress.
Operators must publish wildcard ingress records below every configured relay
pool base so generated customer targets resolve at the relay edges.

Blindport Relay DNS may publish multiple A/AAAA records for active-active relay nodes.
Every advertised node must be able to authorize the same claim, and every such
edge must appear in `RELAY_CONTROL_URLS` so provisioning causes `blindportd`
to maintain a tunnel there. Workers reconnect independently, so one unavailable
edge does not stop the other mappings or edges. DNS does not preserve, migrate,
or resume established TCP sessions when answers or edge health change.

Framed Blindport IP and Blindport Port provisioning contains only `RELAY_CONTROL_URL`.
Their failover requires the leased IPs to be announced or moved between relay
nodes because DNS does not move those socket identities. Routed Blindport IP failover
likewise requires the provider route to move to a relay with the same backend
state and WireGuard key; BGP and multi-relay key rotation are not implemented.
