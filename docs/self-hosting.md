# Self-hosting Blindport

Blindport publishes CI-built backend and relay images at `ghcr.io/blindport`.
Operators who trust GitHub Actions and GHCR should pull those images by digest.
Other operators can build a verified source checkout locally. Both paths use the
checked-in Compose manifests.

Blindport is pre-1.0 software. Read [the architecture](architecture.md),
[operational reference](../deploy/OPERATIONS.md), and [security policy](../SECURITY.md)
before exposing a deployment to untrusted traffic.

## Choose a topology

- `deploy/production` runs PostgreSQL, backend, Caddy, HAProxy, and relay on one
  dedicated Linux host. It is the shortest path to a single-instance deployment.
- `deploy/split/control` and `deploy/split/relay` separate the database/control
  host from the public relay host. The private control route and shared relay
  secret become cross-host dependencies.

Neither topology provides high availability. The supplied manifests expose
Blindport Port and Relay inventory. `RELAY_PUBLIC_IPS` listener addresses are
needed only while serving historical framed IP records. Current Blindport IP
sales require provider-routed WireGuard `/32`
inventory, a persistent relay key, IPv4 forwarding, `NET_ADMIN`, and nftables as
described in the operational reference. It provides a bidirectional static public
interface without NAT. Disable IP sales until the corresponding inventory and
network policy are configured and tested.

## Prerequisites

- A dedicated Linux host for each selected role, Docker Engine with Compose v2,
  and enough CPU, memory, disk, and file descriptors for the configured limits.
- Public DNS names and globally routable addresses for the API and relay.
- Firewall access for the documented Web, relay control, SNI, and port ranges.
- An external LND REST endpoint with a TLS certificate and a least-privilege
  invoice macaroon restricted to `GetInfo`, `AddInvoice`, and `LookupInvoice`.
- Encrypted backups for PostgreSQL, the Blindport CA volume, proxy state, and
  every secret file.

## Install a release

1. Clone the source repository so the deployment manifests can be reviewed:

   ```sh
   git clone https://github.com/blindport/blindport.git
   cd blindport
   ```

2. Select a release from
   [GitHub Releases](https://github.com/blindport/blindport/releases). If GitHub
   Actions and GHCR are inside your trust boundary, download its
   `blindport-images.env` asset and use those digest-pinned image references.
   The digest prevents a later tag change from silently changing your deployment.

   If CI is outside your trust boundary, verify the release key fingerprint and
   signed source tag, then build the images from that exact source instead:

   ```sh
   curl -fsSLO https://blindport.com/release-key.asc
   gpg --show-keys --fingerprint release-key.asc
   gpg --import release-key.asc
   git fetch --tags origin
   git verify-tag v0.2.3
   git switch --detach v0.2.3
   git verify-commit HEAD

   docker build -f docker/backend.Dockerfile --target runtime \
     -t blindport-backend:local .
   docker build -f docker/go.Dockerfile --target relay \
     -t blindport-relay:local .
   ```

   The expected primary fingerprint is
   `18ED E472 6C14 1484 4923 D6FF 14EA BFF7 39C1 6205`. A successful signature
   check authenticates the source history, not GitHub-built artifacts.

3. From the repository root, copy `.env.example` to `.env` within each selected
   deployment directory. For CI-built images, replace its mutable image aliases
   with the matching digest-pinned `BACKEND_IMAGE` and `RELAY_IMAGE` values from
   `blindport-images.env`. For local builds, use the local tags created above.

4. Replace every example hostname, address, CIDR, range, price, and resource
   limit in `.env`. Keep unavailable products disabled or sales-paused.

5. Create owner-only secret files under `secrets/` using the commands and
   ownership requirements in [deploy/OPERATIONS.md](../deploy/OPERATIONS.md).
   Never use the checked-in `secrets/example` sentinel values.

6. From the repository root, validate the checked-in deployment files and the
   rendered configuration for the selected stack before contacting production
   services. For the single-host topology:

   ```sh
   ./deploy/validate.sh
   docker compose --env-file deploy/production/.env \
     -f deploy/production/compose.yaml config --quiet
   ```

7. For CI-built images, pull the digest-pinned references before starting the
   selected stack. Skip this command when using the locally built image tags:

   ```sh
   cd deploy/production
   docker compose --env-file .env -f compose.yaml pull
   ```

   Then run the one-shot migration and start the single-host topology:

   ```sh
   docker compose --env-file .env -f compose.yaml --profile tools run --rm migrate
   docker compose --env-file .env -f compose.yaml up -d
   docker compose --env-file .env -f compose.yaml ps
   ```

For split deployment, migrate and start `deploy/split/control` first, then start
`deploy/split/relay`. Verify readiness and exercise one real path for every
enabled product before opening sales.

## Upgrades and rollback

Back up database, CA, proxy state, and secrets together. Read the release notes,
pull the new digest-pinned images, run migrations once, then replace services.
An older application intentionally refuses to run against a newer schema, so a
rollback may require restoring the matching pre-upgrade database backup.

The single-host Compose project is named `blindport-production`. A project-name
change creates new project-scoped volumes; never start this manifest over an older
single-host installation until PostgreSQL, backend CA, and Relay state have been
copied while the old stack is stopped or restored from a verified backup.

Open general defects and deployment problems in the
[issue tracker](https://github.com/blindport/blindport/issues). Report security
problems privately according to [SECURITY.md](../SECURITY.md).
