# Blindport agent

`blindportd` supports the original single-claim flags, versioned static mappings,
and continuously reconciled Docker mappings. Docker labels may refer to an
existing paid subscription or declare an idempotent order for the backend to
register. When the account has NWC configured, an eligible declared order starts
one initial wallet payment; otherwise it remains pending for dashboard payment.

## Quick start

For one active endpoint on hosted Blindport:

```sh
curl -fsSL https://blindport.com/downloads/install.sh | sh
blindportd -upstream=127.0.0.1:8080
```

The first interactive run asks for the account token without echo and stores it
at `$XDG_CONFIG_HOME/blindport/token` or `$HOME/.config/blindport/token` with
mode `0600`. The hosted backend is the default. Self-hosted deployments set
`--backend`. A legacy `/etc/blindport/token` remains supported.

The installer downloads hosted release assets by default. When run as a normal
user it installs to `$HOME/.local/bin` without using `sudo`; when run as root it
installs to `/usr/local/bin`. If the user-local directory is not in `PATH`, the
installer adds one export to `.profile`, `.bashrc`, or `.zshrc` as appropriate
and prints the export needed by the current shell. Repeated installs do not add
duplicate profile lines. Self-hosted downloads and test harnesses can override
`BLINDPORT_DOWNLOAD_BASE_URL` and `BLINDPORT_INSTALL_DIR` explicitly.

## User systemd service

On a host with user systemd, create the static config at
`$XDG_CONFIG_HOME/blindport/config.json` or
`$HOME/.config/blindport/config.json`, protect it with mode `0600`, and run:

```sh
blindportd -install-user-service
```

The command securely prompts for and stores the token first if it is absent. It
then validates owner and permission safety, installs an owner-only
`blindportd.service` under the standard user systemd directory, reloads user
systemd, and enables and starts the service. The unit uses absolute paths for
the executable, static config, token file, and existing default state directory,
so the enrolled client identity remains stable. The bearer token itself is not
placed in the unit or in systemctl command arguments. The command prints the
corresponding `systemctl --user status` and `journalctl --user` commands.
Backend, Relay override, server name, SOCKS5, insecure development TLS, and ACME
settings supplied by flags or environment are persisted as quoted unit arguments.
Rerun the installation command after changing one of those settings.
Enable systemd lingering if the service must start at boot and remain active
without an interactive login:

```sh
loginctl enable-linger "$USER"
```

The host may require administrator approval for that policy change.

Installation fails without a usable user systemd session, without the static
config, for Docker or routed WireGuard modes, or when the executable, config,
token, unit, or unit directory has unsafe type, ownership, or permissions.

## Update

Rerun the hosted installer to verify and replace the binary, confirm the
reported version, then restart a managed service so it begins using the new
executable:

```sh
curl -fsSL https://blindport.com/downloads/install.sh | sh
blindportd -version
systemctl --user restart blindportd.service
```

Foreground agents use the new binary on their next manual restart. Keep the
existing config, token, and state directories so the enrolled identity is not
replaced.

At startup, release builds ask the authenticated backend for its configured
agent revision. When it differs, the agent logs a warning with the exact
installer command. An unavailable or older backend silently skips this advisory
check and never blocks tunnel startup. Blindport does not replace or restart the
binary automatically.

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
  "version": 2,
  "mappings": [
    {
      "subscription_id": "12312312-3123-4123-8123-123123123123",
      "upstream": "web:8080",
      "tls_mode": "automatic",
      "acme_terms_accepted": true
    },
    {"subscription_id": "45645645-6456-4456-8456-456456456456", "upstream": "tls-proxy:443", "tls_mode": "passthrough", "http_challenge_upstream": "tls-proxy:80"}
  ]
}
```

The top-level and mapping objects reject unknown fields. The version must be
`1` or `2`, mappings must be nonempty, subscription IDs must be canonical UUIDv4 strings and unique,
and each upstream must be a `host:port` with a port in `1-65535`. The paid
subscription transport determines whether the agent dials it with TCP or UDP.
IPv6 addresses use `[address]:port`. The config must be a regular file, not a
symlink, must be owned by the agent's effective UID, and must not be writable
by group or others. On Linux these properties are checked after opening with
`O_NOFOLLOW`. Config files larger than 1 MiB are rejected.

Version 1 remains fully compatible and always selects TLS passthrough. Version 2
requires each mapping to set `tls_mode` explicitly to `passthrough` or
`automatic`. Automatic TLS is valid only for Relay mappings and requires the
operator's explicit `acme_terms_accepted: true`. It obtains one exact-hostname
certificate through the relay's destination-port-80 HTTP-01 path, terminates TLS
inside `blindportd`, and forwards decrypted plaintext to `upstream`. It does not
require a separate reverse proxy, root, or a local public port. Automatic mode rejects
`http_challenge_upstream`; use passthrough when an origin proxy or server should
continue owning TLS and ACME.

The ACME account and certificates are atomically persisted under the private
`BLINDPORT_STATE_DIR/acme` tree. Directories must use mode `0700`, files use mode
`0600`, and unsafe ownership, permissions, symlinks, malformed keys, or
certificates containing names other than the exact Relay hostname are rejected.
Issuance waits until at least one relay-edge tunnel has completed HELLO, then
allows a short settling interval. Failures use minute-scale bounded exponential
backoff, avoiding both a startup race, repeated ACME orders while no edge is
available, and rapid consumption of CA authorization-failure limits. Renewal uses
the ACME Renewal Information window when the CA advertises ARI, selecting a
deterministically spread point in the first half with an expiry safety margin.
CAs without ARI use a deterministic, conservatively jittered schedule around
two-thirds of certificate lifetime (or 30 days before expiry for longer-lived
certificates). Successful renewal hot-reloads certificates for new handshakes;
existing TLS sessions continue normally. The default directory is
Let's Encrypt production; use `--acme-directory` or
`BLINDPORT_ACME_DIRECTORY_URL` for a private or staging ACME server and
`--acme-email` or `BLINDPORT_ACME_EMAIL` for an optional account contact. Email
changes update the existing ACME account. Changing directories requires a
separate state directory because accounts are never reused across CAs. Back up
the state directory because it contains private ACME keys.

TLS handshakes and HTTP-01 stream handling are each bounded to 10 seconds. The
agent closes the individual tunnel stream when a bound expires because the
multiplexed stream API does not provide socket deadlines. Challenge requests
retain the relay's strict HTTP/1.1 GET, exact Host, bodyless request, token, and
16 KiB header constraints.

`http_challenge_upstream` is optional and valid only for Blindport Relay. It receives
relay-validated ACME HTTP-01 requests on destination port 80. Normal Blindport Relay
TLS continues to `upstream` on port 443. Other valid HTTP GET requests receive a
permanent same-host HTTPS redirect directly from the relay and never reach the
agent. Legacy mode exposes the same setting through `--http-challenge-upstream` or
`BLINDPORT_HTTP_CHALLENGE_UPSTREAM`.

Version 3 runs several named local accounts in one process. Each account has an
owner-only token file, a non-overlapping private state directory, and its own
mappings, credentials, authorization cache, ACME state, and tunnel workers:

```json
{
  "version": 3,
  "accounts": [
    {
      "name": "public",
      "token_file": "/run/secrets/blindport-public",
      "state_dir": "/var/lib/blindport/accounts/public",
      "mappings": [
        {
          "subscription_id": "12312312-3123-4123-8123-123123123123",
          "upstream": "public-web:8080",
          "tls_mode": "passthrough"
        }
      ]
    },
    {
      "name": "private",
      "token_file": "/run/secrets/blindport-private",
      "state_dir": "/var/lib/blindport/accounts/private",
      "mappings": [
        {
          "subscription_id": "45645645-6456-4456-8456-456456456456",
          "upstream": "private-api:8443",
          "tls_mode": "passthrough"
        }
      ]
    }
  ]
}
```

Run this supported multi-account configuration with:

```sh
blindportd --config /etc/blindport/accounts.json
```

Account names are lowercase stable IDs. Token and state paths must be absolute,
canonical, unique, and non-overlapping. Each account token file contains the
owner-only bearer token for that backend account. Use a distinct bearer token
for each distinct backend account. Without Docker discovery, every account must
contain at least one static mapping. Version 3 does not support routed WireGuard
or legacy single-subscription flags.

Every configured subscription must appear in the backend's active provisioning
response. Blindport Relay mappings create one independent tunnel worker for every
provisioned relay endpoint. Blindport Port and already-active historical framed
IP provisioning contains only the primary relay because those identities are
tied to provider-specific IP/socket inventory. New WireGuard IP subscriptions do
not appear in framed provisioning. `--relay` or `BLINDPORT_RELAY_CONTROL` replaces provisioning
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

GitHub Actions builds the agent image published through GHCR. If GitHub Actions
and GHCR are inside your trust boundary, stable aliases are convenient for
evaluation, but use the digest-pinned `BLINDPORTD_IMAGE` reference from the
matching release's `blindport-images.env` asset in production:

```sh
docker pull ghcr.io/blindport/blindportd:latest
export DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"
export BLINDPORT_TOKEN="replace-with-account-token"
```

If CI is outside your trust boundary, verify the pinned GPG fingerprint and
signed source tag and commit, check out that source, then build the agent image
locally from the repository root:

```sh
docker build -f docker/go.Dockerfile --target blindportd \
  -t blindportd:local .
export BLINDPORTD_IMAGE=blindportd:local
```

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
      tech.blindport.mapping.web.upstream: "web:8080"
      tech.blindport.mapping.web.tls_mode: "automatic"
      tech.blindport.mapping.web.acme_terms_accepted: "true"

  blindportd:
    image: ${BLINDPORTD_IMAGE:-ghcr.io/blindport/blindportd:latest}
    init: true
    restart: unless-stopped
    command: ["--docker"]
    group_add:
      - "${DOCKER_GID}"
    environment:
      BLINDPORT_BACKEND_URL: "https://api.blindport.example"
      BLINDPORT_TOKEN: "${BLINDPORT_TOKEN:?set BLINDPORT_TOKEN}"
      BLINDPORT_STATE_DIR: /var/lib/blindport
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - blindport-state:/var/lib/blindport
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp:size=16m,mode=1777

volumes:
  blindport-state:
```

Mapping names contain lowercase ASCII letters, digits, underscores, or hyphens,
start with a letter or digit, and are at most 63 characters. One container may
define several mappings. Containers without Blindport labels are ignored. New
orders use `.product` with `relay` or `port`, an optional
`.billing_term` of `monthly` or `yearly`, and a required `.upstream`. Relay also
requires `.domain`. Port accepts `.transport` as `tcp` (the default) or `udp`.
Blindport IP orders are rejected because routed mode has no upstream mapping.
Existing historical framed IP mappings keep using `.subscription` and
`.upstream`; `.subscription` and `.product` are mutually
exclusive. Relay mappings may add `.tls_mode` as `automatic` or `passthrough`.
Automatic mode also requires `.acme_terms_accepted: "true"`; omitted mode keeps
legacy Docker mappings in passthrough mode. All provisioned relay-edge workers
for one hostname share one in-process certificate and HTTP-01 challenge manager.

With a version 3 config, every Docker mapping must also select one configured
local account name. Arbitrary account UUIDs and names absent from the config are
rejected:

```yaml
labels:
  tech.blindport.mapping.web.account: "public"
  tech.blindport.mapping.web.product: "relay"
  tech.blindport.mapping.web.domain: "web.relay.blindport.com"
  tech.blindport.mapping.web.upstream: "web:8080"
```

The `.account` value is used only inside this `blindportd` process and is never
sent as backend authority. The selected account runtime makes order and
provisioning requests with its configured bearer token. Single-account version
1 and 2 Docker deployments omit `.account`; specifying it outside version 3 is
rejected. A missing or unknown selector invalidates the complete Docker snapshot,
so every account retains its last valid workers.

The backend creates a pending subscription exactly once for each mapping name.
Changing that name's product, domain, transport, or billing term is rejected; use
a new name for a different order. Identical declarations from rolling replicas
are coalesced. If NWC is configured and the declaration is immediately eligible,
the backend creates and reconciles one linked initial payment. Managed Relay
names can proceed immediately; customer-owned names wait for DNS verification.
Without NWC, the order appears in the dashboard pending manual payment. Automatic
renewal remains a separate dashboard setting.

In version 3, the pending subscription appears only in the dashboard belonging
to the selected account token. Existing NWC auto-payment settings for that
account are reused. Two local account names configured with the same bearer token
still identify one backend account, so incompatible declarations that reuse the
same order key are rejected by the backend. Product declarations and local order
caches otherwise remain isolated by configured account name.

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

The published image runs as UID/GID `10001`. Set `DOCKER_GID` to the numeric
group owner of the host socket so Compose grants only the required supplementary
group. A named volume inherits the image's private state ownership on first use.

Docker environment values are visible to users with Docker inspection access
and in rendered Compose output. Those users already control the container and
its mounted Docker socket. Secret-manager and explicit owner-only token files
remain supported for deployments with a different threat model.

## Routed WireGuard mode

Run `blindportd --wireguard` or set `BLINDPORT_WIREGUARD=1` for active Blindport IP
subscriptions. New IP subscriptions always use yearly WireGuard delivery. This mode is separate from
static mappings, Docker discovery, and the legacy claim flags. The application
must listen on the assigned address or a wildcard socket itself; routed mode
does not dial an `--upstream`.

Routed mode requires Linux kernel WireGuard support and `CAP_NET_ADMIN` (or an
equivalent root deployment). It creates `bpwg0` by default, assigns every active
routed `/32`, and configures the backend-provided relay peer, endpoint, MTU, and
persistent keepalive. Change the interface with
`BLINDPORT_WIREGUARD_INTERFACE`. The interface uses `AllowedIPs=0.0.0.0/0`, but
the host main default route is unchanged. Only packets sourced from an assigned
`/32` use policy table `51820` and rule priorities starting at `10000`, ahead of
Linux's main-table rule at `32766`; override
these with `BLINDPORT_WIREGUARD_ROUTE_TABLE` and
`BLINDPORT_WIREGUARD_RULE_PRIORITY` when they conflict with local routing policy.

The public `/32` is bidirectional. An application listening on that address or a
wildcard socket receives any protocol and port allowed by the customer firewall.
An application that binds the `/32` as its outbound source uses the WireGuard
policy table and appears to remote systems from the same static public address.
Unbound host traffic continues to use the normal host default route. A dedicated
container or network namespace may make `bpwg0` its default route when all of that
namespace's IPv4 traffic should use the leased address. Blindport does not change
the host-wide default route or configure DNS.

Outbound TCP port 25 is denied at the relay by default. A manually reviewed paid
exception is attached to one active lease and does not carry over if the address
is released or reassigned. Authenticated submission ports 465 and 587 are not
part of this default block.

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
  provisioning, including historical framed IP compatibility, are reconciled
  in-process; routed WireGuard changes still require a restart. Client and
  automatic Relay certificates renew in-process without a daemon restart.
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
`--domain`, and `--upstream`. It selects one active framed subscription as before;
new Blindport IP subscriptions use the separate routed mode.
