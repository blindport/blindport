# High availability

Blindport separates control-plane availability from Relay data-plane availability.
The local lab in `deploy/ha-lab` demonstrates two stateless FastAPI processes behind
a health-checking, round-robin HAProxy, one PostgreSQL writer endpoint, and two
independent Relay edges. Both API processes use the same application, token-hash,
Relay, admin, and invoice-HMAC secrets and the same CA filesystem. Relay authorization
goes through the API load balancer. Relay provisioning returns both edge control
addresses, so one agent maintains one tunnel to each edge without sticky HTTP sessions.

This is a development fault lab, not a production topology. It uses deterministic
non-production credentials and mock Lightning, builds application images from the
checked-out source, pins all third-party images by digest, publishes no host ports,
and uses internal Compose networks. Run it from the repository root:

```sh
./deploy/ha-lab/run.sh
```

The script starts with empty named volumes, migrates the database, and checks real TLS
passthrough for both Relay and Port claims through both edges. It stops one API replica,
stops one Relay edge, and checks new-connection continuity. It then stops the agent, one
Relay, and both API replicas; restarts the agent and Relay without their dependencies;
and proves new Relay and Port traffic from persisted client authorization, a persisted
Relay certificate, and edge-bound signed entitlements. After API recovery it applies an
authoritative denial, verifies empty provisioning and loss of every tunnel, restores the
claims, races twelve payments against the four remaining Port sockets, and tests a `0015`
to head migration round trip without losing subscriptions. HAProxy uses Docker's embedded
DNS at runtime so restarted backend containers can receive new addresses. A trap removes
all containers, networks, and volumes on success or failure.

The entitlement key initializer derives a deterministic key from an explicit public test
seed and writes only an owner-only runtime PEM. The lab never uses production credentials
or commits a private-key artifact. Each Relay has its own persistent certificate-cache
volume.

## What the lab cannot prove

One-host Compose cannot prove tolerance of a host, rack, provider, region, WAN, DNS,
or control-network failure. Its named volumes are one local storage failure domain.
It does not exercise PostgreSQL replication, leader election, fencing, quorum,
synchronous cross-site commit latency, provider route movement, BGP convergence,
authoritative DNS steering, public certificate issuance, real LND behavior, backup
restore, or point-in-time recovery. Docker bridge networks do not reproduce Internet
packet loss, asymmetric routing, MTU differences, or provider anti-spoofing policy.
The outage sequence does not wait through the seven-day entitlement grace period; focused
tests cover expiration, while production qualification still needs a configured soak or
time-controlled environment.

Stopping a container is a deterministic process failure, not a machine power loss.
The migration test verifies the current image and retained lab rows, not arbitrary
mixed-version compatibility. Production rolling compatibility still requires the
release-specific migration-first feature-gate sequence in the operations guide.

## Two-provider topology

Place one site in each provider. A future inventory model should explicitly represent
`provider`, `site`, `node`, `address`, and `socket assignment`. A node belongs to one
site; an address belongs to a provider/site routing domain; a TCP or UDP socket belongs
to one address and is assigned to one Relay node or a deliberately coordinated node
set. Health, drain state, assignment generation, and fencing ownership belong on those
records. This repository does not yet implement those production inventory models.

Run an API proxy and at least one API replica in each site. Publish the website/API
name through a health-steered DNS or global load-balancing service that probes a
readiness endpoint from multiple locations. Do not use cookie or source-IP affinity:
all replicas must share durable state and required secrets. Keep TTLs low enough for
the DNS provider's supported steering interval, commonly 30 to 60 seconds, but treat
that as an upper cache-control request rather than an instant failover guarantee.
Recursive resolvers and clients may cache longer, and existing TCP connections do not
move when DNS changes.

For managed Relay names, publish wildcard A/AAAA answers containing only healthy
Relay sites. Every advertised edge must authorize against the HA API endpoint, use a
certificate from the same trusted CA, and be returned in `RELAY_CONTROL_URLS`. The
agent then reconnects independently to each edge. Removing a failed answer helps only
future DNS resolutions and connections. Established TCP sessions on the failed Relay
are lost and must be retried by the application; Blindport has no session migration or
stream resumption.

Offline entitlement fallback does not make the control plane highly available. Every
edge must have the same canonical public keyring, its own stable edge ID, and matching
grace configuration before it is enabled. A restarted Relay can admit a new v2 client
during a typed API infrastructure outage only from that client certificate and its
edge-bound signed artifact. Token denials, bad relay secrets, and malformed API replies
remain fail-closed, and an online authorization result remains authoritative.
The feature gates are disabled by default, and this framed-tunnel fallback does
not apply to routed WireGuard. Routed WireGuard continues to require its normal
enrolled, fail-closed desired-state path.

## PostgreSQL authority

Expose exactly one authoritative PostgreSQL writer endpoint to every API and worker.
Use a managed multi-zone PostgreSQL service or Patroni with an external distributed
configuration store, quorum across failure domains, watchdog or infrastructure-level
fencing, and a proxy/service-discovery endpoint that targets only the current primary.
Failover without fencing risks two writable primaries and violates payment, unique
socket, and reservation invariants.

Choose synchronous durability deliberately. For acknowledged payments and allocation
transactions to survive site loss, require synchronous commit to a standby in the
other failure domain. Measure the resulting WAN latency and define what happens when
the synchronous standby is unavailable: reject writes, or use an explicitly approved
reduced-durability mode with an understood recovery-point objective. Never silently
route writes to two independent databases.

Logical multi-primary replication is rejected. Conflict resolution after two sites
allocate the same scarce IP/socket or settle the same payment cannot preserve the
database uniqueness and conditional-update invariants. Last-writer-wins would turn a
consistency violation into customer-visible double assignment or accounting loss.

## Signers and workers

All API replicas require identical application secrets, token-hash key, Relay secret,
invoice HMAC key, and credential-encryption key when enabled. CA issuance must also
have one authority. Use a highly available signer/HSM service, or a strongly consistent
shared encrypted CA store with single-writer semantics and tested locking. Replicating
an unencrypted CA private key through an eventually consistent filesystem is not an
acceptable production design. Preserve old trust during planned CA rotation and test
client and Relay certificate renewal before retiring it.

Current payment reconciliation can run on multiple API replicas because PostgreSQL
row locks, unique constraints, leases, and conditional settlement updates coordinate
the supported paths. Keep configuration and provider credentials identical. Future
non-idempotent workers should use database leases or a dedicated queue with explicit
ownership and fencing tokens; do not rely on process-local locks for cross-site work.

## Relay addresses

Relay hostnames can use two provider-specific endpoints, one at each edge. This is the
portable option for Relay SNI because DNS can advertise both and the agent opens both
control tunnels. A provider floating IP can move sockets only within that provider's
supported routing domain. Portable provider-independent address space with BGP can
move the same address between providers, but requires an ASN or sponsoring network,
ROAs/RPKI, routing policy, health-based announcement withdrawal, anti-spoofing support,
and operational expertise.

Blindport Port can map one logical allocation to provider-local claims when
`PORT_HA_EDGES` is configured. The agent opens the same allocated port through each
provider endpoint. Each Relay mirrors that claim over its local shared IPv4 and IPv6
addresses, and the customer receives one wildcard-backed hostname plus every explicit
provider IP. This is new-connection redundancy, not socket mobility: cached DNS may
continue returning a failed edge and established streams are not resumed. The backend
model intentionally supports one canonical shared address pool; multiple allocation
pools need a future site-aware inventory model to prevent mirrored socket collisions.

Current routed Blindport IP and historical framed IP remain address products
rather than portable DNS identities. Honest HA choices are two separately assigned provider-specific addresses,
a provider-local floating IP with only provider-local HA, or portable BGP space. One
provider-assigned `/32` routed to one VPS does not provide cross-provider HA, and this
documentation does not claim that it does. Routed WireGuard failover additionally
needs coordinated endpoint, key, route, and fencing ownership that is not implemented.

## Backup and recovery

Take encrypted PostgreSQL base backups and continuously archive WAL to storage outside
both serving sites. Set retention from the recovery-point objective, monitor archive
lag, and regularly restore to an isolated environment at a selected timestamp. Back
up CA/signer material, application secrets, LND invoice credentials, and deployment
configuration under separate access controls. A database PITR without the matching
CA and invoice HMAC key is not a complete Blindport recovery.

Before adding a second VPS, provision private inter-site networking, health-steered DNS,
a fenced PostgreSQL writer design, synchronous durability policy, shared secret/signer
delivery, offsite backup/WAL storage, monitoring, and one Relay address strategy. Then
repeat API and Relay failure tests from external vantage points and test a full site
loss, database promotion, DNS convergence, and restored customer reconnects.
