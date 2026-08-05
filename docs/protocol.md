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

Current clients send protocol version `1` and advertise independently optional
capabilities:

```json
{"type":"hello","version":1,"token":"...","claim":{"kind":"port","ip":"203.0.113.20","port":10000,"transport":"udp"},"capabilities":["tcp_half_close","stream_flow_control"]}
```

The relay returns `hello_ok` or `hello_err`. A `hello_ok` echoes only capabilities
offered by the client and supported by the relay. An absent or empty capability
list selects no extensions. After `hello_ok`, the relay sends
`open` frames and both sides exchange `data`, `datagram`, and `close`; negotiated
peers also exchange `close_write` and `window_update`; `ping` receives `pong`.
TCP streams use `data` frames with at most 16 KiB. UDP
associations use one `datagram` frame per complete packet with at most 65,507
bytes, including a valid zero-length datagram. Stream IDs are nonzero unsigned
32-bit integers. One tunnel permits a configured number of concurrent streams
(256 by default, with a hard maximum of 1024). A flow-controlled TCP stream can
queue at most 4 MiB or 512 frames, while all streams on one tunnel share a strict
64 MiB and 4,096-frame receive budget. The frame caps also bound queue metadata when peers
send unusually small frames. Enqueue never waits for an application socket, so
one stalled data stream cannot block control or sibling frames in the multiplexed
reader. The final 4 MiB and 256 frame slots are unavailable to a stream already
holding more than 64 KiB or eight frames, reserving shared capacity for concurrent
control streams. A TCP stream exceeding either its own limit or the shared limit
is closed without closing the tunnel; queued payload for that offending stream
is discarded.
Payload ordered before a peer `close` or negotiated `close_write` remains readable
before EOF. Local abort, local full close, and tunnel shutdown release any unread
queue immediately. UDP retains the nonblocking drop policy described below.
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
reject versions newer than they support. This marker provides safe UDP rollout.
Independent extensions use the capability negotiation in HELLO and HELLO_OK.

When both peers select `tcp_half_close`, either side can send
`{"type":"close_write","stream":7}` after its final `data` frame. This propagates
TCP FIN in that direction only. The receiver drains all preceding data and then
observes EOF while retaining the ability to send reverse-direction data. A
`close` frame still tears down both directions and releases the stream. Without
the selected capability, peers never send `close_write` and preserve the legacy
behavior where the first completed copy closes the full stream. `close_write` is
invalid for UDP streams.

`stream_flow_control` is selected only when the client also offered
`tcp_half_close`. Each new TCP stream starts with 4 MiB of send credit; each UDP
stream starts with 512 KiB. Sending `data` or `datagram` consumes payload-sized
credit before taking the tunnel write mutex. A sender with no credit waits only
on that stream, and stream or tunnel close wakes it. When application reads fully
consume a queued frame, the receiver returns exactly those bytes with
`{"type":"window_update","stream":7,"credit":16384}`. Increments must be
positive and at most 4 MiB, and total available credit can never exceed the
stream's initial window. Invalid or inflationary updates close that stream;
updates for already removed streams are ignored as late control traffic. An
unnegotiated update or zero stream ID is a tunnel protocol error.

A peer that did not select `stream_flow_control` never receives or sends
`window_update`. New receivers give such legacy TCP streams a 32 MiB or 4,096-frame
compatibility backlog under the same 64 MiB tunnel budget. This larger bounded
fallback absorbs normal long reverse-test jitter without restoring an unbounded
queue, but sustained legacy senders can still have only their offending stream
closed when they exceed that limit. Negotiated flow control is therefore required
for indefinite backpressure without stream abort.

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
packet without terminating the association or control tunnel. Tunnel UDP queues
also count against the shared 64 MiB and 4,096-frame receive budget.

For a Relay stream, destination metadata is authorization-sensitive. It is
exactly `domain:<claimed-hostname>:443` for public TLS and
`domain:<claimed-hostname>:80` for a relay-validated HTTP-01 request. In legacy
and explicit passthrough mode, destination 443 remains opaque end-to-end TLS and
destination 80 is accepted only when a separate challenge upstream is
configured. In automatic mode, one per-hostname agent manager shared by every
edge worker answers destination 80 directly, terminates destination 443 TLS with
an ACME certificate authorized only for the exact claimed hostname, and forwards
plaintext to the configured local upstream. No new frame type, capability, or
protocol version is required; older agents retain passthrough behavior.
The automatic manager starts issuance only after one edge tunnel completes
HELLO. Agent-side TLS handshakes and HTTP-01 handling close their individual
stream after a bounded timeout; this does not close sibling streams or the
shared control tunnel.

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
until payment activates the subscription. Managed names have a 30-minute initial
payment deadline; customer-owned names have a one-hour DNS and payment deadline.
Verification does not reset that deadline. Pending claims created
before the CNAME rollout retain their existing TXT challenge only until that
bounded claim expires.

At the end of an active Blindport Relay billing period, the backend removes the name
from resolution immediately. A bounded renewal grace reserves the name to the
same subscription but grants no tunnel authorization. Renewal during grace
requires a fresh exact-CNAME lookup and retains the assigned target; release after grace requires any new
claimant to pass the normal managed or customer-owned rules again with a newly
generated target. Activation, renewal, and renewal grace retain the assigned
CNAME target; final release clears it.
Before either initial or renewal release, open Lightning, stablecoin swap, and NWC payments are
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
not terminate user TLS. An automatic-TLS agent terminates Relay TLS locally,
while passthrough remains end to end to the origin. Framed Blindport IP and
Blindport Port can carry plaintext protocols if the user chooses them. This protocol provides no traffic padding,
anonymity, end-to-end payload encryption of its own, routed packets, stream
priority, resume, or session migration between relays. UDP is carried over the
reliable, ordered TCP control tunnel, so it can experience head-of-line blocking
and does not retain native UDP loss or latency behavior.

There is a scalar version marker plus independent capability negotiation.
Extensions that change validation, framing, or authorization must increment the
version or be gated by a capability selected by both peers before mixed deployment.
