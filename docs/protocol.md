# Blindport tunnel protocol (open draft)

This document describes the current implementation, not a stable standard. It
is an open protocol draft intended to make independent review and experiments
possible. Implementations should expect draft changes until a stable protocol
version is declared.

This protocol applies only to `framed` delivery. Routed WireGuard Blindport IP uses
standard WireGuard transport and the HTTP enrollment and desired-state APIs; it
does not encapsulate packets in these JSON frames.

## Transport and framing

Each `blindportd` worker opens one TCP connection to one relay control listener.
Multi-mapping mode runs a worker for each mapping and provisioned endpoint;
these connections do not share protocol state. Production configuration wraps
each in mutual TLS. Every frame is a four-byte unsigned big-endian length
followed by one JSON object. Zero-length frames are invalid; the encoded frame
limit is 1 MiB. A `data` frame carries at most 16 KiB after JSON base64 encoding
rules are applied to its byte field.

Current clients send protocol version `1`:

```json
{"type":"hello","version":1,"token":"...","claim":{"kind":"port","ip":"203.0.113.20","port":10000,"transport":"udp"}}
```

The relay returns `hello_ok` or `hello_err`. After `hello_ok`, the relay sends
`open` frames and both sides exchange `data`, `datagram`, and `close`; `ping`
receives `pong`. TCP streams use `data` frames with at most 16 KiB. UDP
associations use one `datagram` frame per complete packet with at most 65,507
bytes, including a valid zero-length datagram. Stream IDs are nonzero unsigned
32-bit integers. One
tunnel permits a configured number of concurrent streams (256 by default, with
a hard maximum of 1024), and each stream has a 32-item, 512 KiB receive queue.
Serialized frame writes have a 10-second deadline; a peer that stops reading
loses that tunnel instead of holding its write mutex and ingress handlers
indefinitely.
The agent applies one 10-second deadline across the HELLO write and reply read,
then clears the connection deadline after receiving `hello_ok`. The relay gives
the incoming HELLO the same 10-second read deadline, caps its encoded frame at 8
KiB, and caps the bearer token at 512 bytes.

## Claims

Claims are strict tagged objects:

| `kind` | Required fields | Meaning |
| --- | --- | --- |
| `ip` | `ip` | Blindport IP, all configured TCP listeners on one dedicated IP |
| `port` | `ip`, `port`, `transport: "tcp"` or `"udp"` | Blindport Port, exactly one shared transport socket |
| `relay` | lowercase `domain` | Blindport Relay, one valid DNS hostname on the SNI listener |

Fields belonging to another claim type are rejected. Blindport IP and Blindport Relay
accept an omitted transport for legacy compatibility or explicit `tcp`;
Blindport Port requires it. TCP and UDP on the same numeric IP and port are distinct
claims.

An omitted frame version is legacy version `0` and remains valid for TCP claims.
UDP requires version `1`. Relays return their current version in `hello_ok` and
reject versions newer than they support. This marker provides safe UDP rollout,
but it is not general capability negotiation.

The backend resolution response contains dedicated IP strings, relay domain
strings, and structured Blindport Port leases. Authorization compares the complete
claim. A different shared port, IP, or transport is a different identity.

For each direct source address sending to a UDP Blindport Port listener, the relay
opens one `proto: "udp"` stream. Its `src` and `dst` OPEN metadata identify the
external source and leased destination. The agent uses one connected UDP socket
to the mapping's upstream, preserving response association. Relay associations
share global and per-source ingress limits, have a bounded 32-packet queue, and
expire after the configured idle timeout. Association and tunnel receive queues
each retain at most 512 KiB of payload. A saturated UDP queue drops that source's
packet without terminating the association or control tunnel.

Before a Blindport Relay claim can become active, the control plane classifies its
canonical hostname under one of three DNS models. Names strictly beneath a
configured provider-managed wildcard suffix bypass customer proof. Non-apex,
non-wildcard customer subdomains receive a stable, subscription-specific CNAME target under
one configured relay-pool base and require an exact direct CNAME response before
payment. The target's generated lowercase label contains 128 bits of randomness.
A verification lookup requests only the CNAME type at the canonical customer
hostname, disables resolver search expansion, accepts one absolute target, and
requires canonical exact equality. CNAME chains, A/AAAA flattening, other pool
targets, and resolver failures do not prove control.
A future registrar or authoritative-DNS integration may automate record changes
through the same control-plane API, but that facility is not part of v0.
Blindport itself is not currently an authoritative DNS server. DNS verification
changes subscription eligibility only; the relay does not authorize the claim
until payment activates the subscription. Every pending Blindport Relay name has one
bounded initial payment eligibility deadline, including managed and verified
custom names. Verification does not reset that deadline. Pending claims created
before the CNAME rollout retain their existing TXT challenge only until that
bounded claim expires.

At the end of an active Blindport Relay billing period, the backend removes the name
from resolution immediately. A bounded renewal grace reserves the name to the
same subscription but grants no tunnel authorization. Renewal during grace
requires a fresh exact-CNAME lookup and retains the assigned target; release after grace requires any new
claimant to pass the normal managed or customer-owned rules again with a newly
generated target. Activation, renewal, and renewal grace retain the assigned
CNAME target; final release clears it.
Before either initial or renewal release, open Lightning and NWC payments are
reconciled. Confirmed settlement activates the name, while uncertain provider
state or an irreversible `PROCESSING` payment blocks handoff for operator
reconciliation.

For NWC, confirmation means Blindport's own LND invoice is settled. Wallet-side
pay or lookup responses never replace that authority. A returned preimage is
accepted only when its SHA-256 digest equals the persisted LND payment hash.
Unknown outgoing state prevents another wallet send.

## Security properties and limits

The bearer token identifies the account and authorizes only active,
non-expired leases. Mutual TLS separately proves a backend-issued client
identity and authenticates the relay using configured hostname, dedicated-IP,
and shared-IP SANs. The relay requires the certificate user ID to equal the user
resolved from the token. Current agents generate an Ed25519 key locally and
enroll its CSR. Production disables legacy v1 server-generated private keys and
allows one stable public key per account, so a bearer token copied after initial
enrollment cannot mint a replacement client identity by itself.

The certificate also carries `urn:blindport:client:<instance UUID>` as a URI SAN.
The v0 relay continues to bind the account through `CN=user:<id>` for protocol
compatibility; device serial revocation is not yet part of HELLO or periodic
resolution. A compromised token plus enrolled private key remains sufficient,
and an established TLS connection is not terminated solely because its leaf
certificate later expires.

The provisioning response retains v0 `relay_endpoint` and also returns
`relay_endpoints`. The singular value is the first list entry. Blindport Relay receives
all configured edges. Framed Blindport IP and Blindport Port receive only their primary edge
because their leased socket identity is provider-specific. A multi-edge agent
derives TLS ServerName independently from each endpoint unless configured with
one explicit override.

The relay reauthorizes established tunnels periodically. A successful response
that removes the claim closes the tunnel. Temporary backend failures retain it
only until `BLINDPORT_RELAY_REAUTH_MAX_STALENESS`, measured from the last
successful authorization. The maximum must be at least one interval, and the
backend resource reuse quarantine must be greater than the maximum plus one
interval.
The relay can observe endpoints, timing, byte counts, and Blindport Relay SNI. It does
not terminate user TLS, but framed Blindport IP and Blindport Port can carry plaintext
protocols if the user chooses them. This protocol provides no traffic padding,
anonymity, end-to-end payload encryption of its own, routed packets, stream
priority, resume, or session migration between relays. UDP is carried over the
reliable, ordered TCP control tunnel, so it can experience head-of-line blocking
and does not retain native UDP loss or latency behavior.

There is a scalar version marker but no independent capability negotiation.
Extensions that change validation, framing, or authorization must increment the
version or add a negotiated capability before mixed deployment.
