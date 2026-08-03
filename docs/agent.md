# Blindport agent

`blindportd` supports the original single-claim flags, versioned static mappings,
and continuously reconciled Docker mappings. Docker labels may refer to an
existing paid subscription or declare an idempotent order for the backend to
register. When the account has NWC configured, an eligible declared order starts
one initial wallet payment; otherwise it remains pending for dashboard payment.

## Client identity

The agent generates one Ed25519 key locally and enrolls only its signed CSR at
`POST /api/v2/client/certificate`. The backend never receives or returns the
private key. Set `--state-dir` or `BLINDPORT_STATE_DIR` to a persistent private
directory. The default is `$XDG_STATE_HOME/blindport` or
`$HOME/.local/state/blindport`.

The state directory must be absolute, canonical, owned by the effective UID,
and inaccessible to group and other users. `blindportd` stores a versioned
`credential.json` with mode `0600` using file and directory synchronization plus
an atomic rename. It rejects symlinks, nonregular files, unsafe ownership or
permissions, malformed credentials, certificate/key mismatches, and unknown
state fields. Before first enrollment it durably writes a pending identity, so a
crash after the backend accepts the CSR can resume with the same key and instance
ID. A nonblocking process-lifetime lock prevents two daemons from sharing one
identity directory.

Certificate renewal starts at the server-provided renewal time, approximately
two thirds through the validity period. Retries use bounded exponential backoff.
The stable private key and instance ID remain unchanged; each successful renewal
atomically persists the next generation, and new relay connections select the
latest certificate without restarting the daemon. Existing TLS tunnels are not
forced closed for routine renewal.

Production permits one enrolled instance per account. A copied bearer token
cannot replace that instance because renewal must use the enrolled public key.
Run all mappings for one account through one daemon. If the private state is
lost, stop the daemon and have an operator reset the account's
`clientcredential` database row before enrolling a new identity. Protect and
back up the state directory as a secret. A WireGuard peer whose instance no
longer matches that row is excluded from relay desired state; the replacement
identity can enroll a fresh generation-1 WireGuard key.

## Static configuration

Pass `--config /etc/blindport/config.json` or set
`BLINDPORT_CONFIG=/etc/blindport/config.json`:

```json
{
  "version": 1,
  "mappings": [
    {
      "subscription_id": 123,
      "upstream": "traefik:443",
      "http_challenge_upstream": "traefik:80"
    },
    {"subscription_id": 456, "upstream": "photos:8080"}
  ]
}
```

The top-level and mapping objects reject unknown fields. The version must be
`1`, mappings must be nonempty, subscription IDs must be positive and unique,
and each upstream must be a `host:port` with a port in `1-65535`. The paid
subscription transport determines whether the agent dials it with TCP or UDP.
IPv6 addresses use `[address]:port`. The config must be a regular file, not a
symlink, must be owned by the agent's effective UID, and must not be writable
by group or others. On Linux these properties are checked after opening with
`O_NOFOLLOW`. Config files larger than 1 MiB are rejected.

`http_challenge_upstream` is optional and valid only for Blindport Relay. It receives
relay-validated ACME HTTP-01 requests on destination port 80. Normal Blindport Relay
TLS continues to `upstream` on port 443. Legacy mode exposes the same setting
through `--http-challenge-upstream` or
`BLINDPORT_HTTP_CHALLENGE_UPSTREAM`.

Every configured subscription must appear in the backend's active provisioning
response. Blindport Relay mappings create one independent tunnel worker for every
provisioned relay endpoint. Framed Blindport IP and Blindport Port provisioning contains
only the primary relay because those products are tied to provider-specific
IP/socket inventory. `--relay` or `BLINDPORT_RELAY_CONTROL` replaces provisioning
with one endpoint and is primarily retained for the legacy single-claim mode.
TLS ServerName is derived independently from each endpoint. `--server-name` or
`BLINDPORT_SERVER_NAME` sets one explicit override for every endpoint.

## Docker discovery

Enable continuous discovery with `--docker` or `BLINDPORT_DOCKER=1`. The default
daemon endpoint is `unix:///var/run/docker.sock`; change it with
`--docker-host` or `BLINDPORT_DOCKER_HOST`. Only canonical absolute local
`unix://` socket URLs are accepted. TCP, HTTP, SSH, npipe, remote authorities,
relative paths, and path traversal are rejected before the client is created.
Docker API discovery and its HTTP client are limited to 10 seconds. The daemon
lists running containers and refreshes backend provisioning every 10 seconds by
default. Set `--docker-poll-interval` or `BLINDPORT_DOCKER_POLL_INTERVAL` to a
duration between `1s` and `5m`.

Declare a Relay order before it exists in the dashboard by using the mapping name
as its stable account-scoped order key:

```yaml
services:
  web:
    image: example/web:latest
    labels:
      tech.blindport.mapping.web.product: "relay"
      tech.blindport.mapping.web.domain: "web.relay.blindport.com"
      tech.blindport.mapping.web.billing_term: "monthly"
      tech.blindport.mapping.web.upstream: "web:443"
      tech.blindport.mapping.web.http_challenge_upstream: "web:80"

  blindportd:
    image: ghcr.io/OWNER/blindportd:v0.1.0
    command: ["--docker"]
    environment:
      BLINDPORT_BACKEND_URL: "https://api.blindport.example"
      BLINDPORT_TOKEN_FILE: /run/secrets/blindport_token
      BLINDPORT_STATE_DIR: /var/lib/blindportd
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc/blindport/token:/run/secrets/blindport_token:ro
      - blindportd-state:/var/lib/blindportd
```

Mapping names contain lowercase ASCII letters, digits, underscores, or hyphens,
start with a letter or digit, and are at most 63 characters. One container may
define several mappings. Containers without Blindport labels are ignored. New
orders use `.product` with `relay`, `port`, or `ip`, an optional
`.billing_term` of `monthly` or `yearly`, and a required `.upstream`. Relay also
requires `.domain`. Port accepts `.transport` as `tcp` (the default) or `udp`.
Docker IP orders always use framed delivery. Existing mappings keep using
`.subscription` and `.upstream`; `.subscription` and `.product` are mutually
exclusive.

The backend creates a pending subscription exactly once for each mapping name.
Changing that name's product, domain, transport, or billing term is rejected; use
a new name for a different order. Identical declarations from rolling replicas
are coalesced. If NWC is configured and the declaration is immediately eligible,
the backend creates and reconciles one linked initial payment. Managed Relay
names can proceed immediately; customer-owned names wait for DNS verification.
Without NWC, the order appears in the dashboard pending manual payment. Automatic
renewal remains a separate dashboard setting.

Successful snapshots add, update, and remove tunnel workers without restarting
the daemon. Removing a label stops its local forwarding but does not cancel or
refund the subscription. Transient Docker, label, order, or provisioning errors
retain the last valid workers and are retried. Static and Docker mappings can be
combined; duplicate active subscription IDs remain invalid.

One agent can serve containers from several Compose projects only when their
upstream names are reachable from the agent, typically through a shared external
Docker network. The agent does not attach itself to networks or modify containers.

Access to the Docker socket is root-equivalent. Listing containers is read-only
at the API level, but possession of broad Docker daemon credentials normally
allows host compromise. Protect the socket and prefer a narrowly authorized
socket proxy where practical. Anyone allowed to deploy labeled containers can
publish internal services and, for an NWC-enabled account, initiate bounded
subscription spending. Restrict deployment authority and enforce a wallet-side
NWC budget.

The token file must be a regular, owner-only file owned by the daemon's
effective UID. Linux opens it with `O_NOFOLLOW`; symlinks, oversized values,
embedded whitespace, and group or other access stop startup. Environment and
command-line token values remain available for development, but a mounted
secret file avoids exposing the bearer token through process arguments.

## Routed WireGuard mode

Run `blindportd --wireguard` or set `BLINDPORT_WIREGUARD=1` for active Blindport IP
subscriptions created with `delivery=wireguard`. This mode is separate from
static mappings, Docker discovery, and the legacy claim flags. The application
must listen on the assigned address or a wildcard socket itself; routed mode
does not dial an `--upstream`.

Routed mode requires Linux kernel WireGuard support and `CAP_NET_ADMIN` (or an
equivalent root deployment). It creates `bpwg0` by default, assigns every active
routed `/32`, and configures the backend-provided relay peer, endpoint, MTU, and
persistent keepalive. Change the interface with
`BLINDPORT_WIREGUARD_INTERFACE`. The interface uses `AllowedIPs=0.0.0.0/0`, but
the host main default route is unchanged. Only packets sourced from an assigned
`/32` use policy table `51820` and rule priorities starting at `51820`; override
these with `BLINDPORT_WIREGUARD_ROUTE_TABLE` and
`BLINDPORT_WIREGUARD_RULE_PRIORITY` when they conflict with local routing policy.

The agent generates a separate WireGuard key and atomically persists it as
owner-only `wireguard.json` under `BLINDPORT_STATE_DIR`. It signs public-key
enrollment with the stable Ed25519 client identity. Losing only the WireGuard
key causes the next startup to enroll a replacement at the next generation;
losing `credential.json` still requires the operator reset described above.
`BLINDPORT_INSECURE_SKIP_TLS` is incompatible with routed mode because enrollment
requires that identity.

## Current limitations

- Continuous discovery uses bounded polling rather than Docker events, so changes
  can take up to one configured poll interval to apply.
- Static configuration is still read once at startup. Docker and active framed
  provisioning are reconciled in-process; routed WireGuard changes still require
  a restart. Client certificates renew in-process and are used on reconnect.
- Backend bootstrap requests and the relay protocol HELLO exchange are limited
  to 10 seconds. Bootstrap response bodies are size-limited and strictly parsed.
- Declared Docker orders can register and make one initial NWC payment. Label
  removal does not cancel service, and renewal remains an explicit account policy.
- TCP sessions belong to one relay tunnel. DNS changes and worker reconnects do
  not migrate or resume existing sessions.
- UDP source associations are local to one relay tunnel and expire after relay
  inactivity. UDP datagrams traverse TCP/mTLS and can experience head-of-line
  blocking rather than native UDP loss behavior.
- Routed mode currently supports IPv4 `/32` leases on Linux only. It does not
  manage host firewalls, application listeners, IPv6, DNS, or key overlap during
  rotation.

Legacy mode remains available with `--kind`, `--ip`, `--port`, `--transport`,
`--domain`, and `--upstream`. It selects one active subscription as before.
