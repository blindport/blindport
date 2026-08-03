# Self-hosting Blindport

Blindport publishes the backend and relay images at `ghcr.io/blindport`.
Production deployments should pull those images by digest and run the checked-in
Compose manifests. Building images on the production host is not required.

Blindport is pre-1.0 software. Read [the architecture](architecture.md),
[operational reference](../deploy/OPERATIONS.md), and [security policy](../SECURITY.md)
before exposing a deployment to untrusted traffic.

## Choose a topology

- `deploy/canary` runs PostgreSQL, backend, Caddy, HAProxy, and relay on one
  dedicated Linux host. It is the shortest path to a single-instance deployment.
- `deploy/split/control` and `deploy/split/relay` separate the database/control
  host from the public relay host. The private control route and shared relay
  secret become cross-host dependencies.

Neither topology provides high availability. The supplied manifests expose
Blindport Port and Relay inventory. Dedicated framed or WireGuard Blindport IP
requires additional routable address inventory and host networking described in
the operational reference; disable IP sales until that inventory is configured.

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

2. Select a signed release from
   [GitHub Releases](https://github.com/blindport/blindport/releases). Download
   its `blindport-images.env` asset and verify the image attestations:

   ```sh
   gh attestation verify \
     oci://ghcr.io/blindport/blindport-backend@sha256:<digest> \
     -R blindport/blindport \
     --signer-workflow blindport/blindport/.github/workflows/release.yaml
   gh attestation verify \
     oci://ghcr.io/blindport/blindport-relay@sha256:<digest> \
     -R blindport/blindport \
     --signer-workflow blindport/blindport/.github/workflows/release.yaml
   ```

3. From the repository root, copy `.env.example` to `.env` within each selected
   deployment directory. Replace its mutable image aliases with the matching
   digest-pinned `BACKEND_IMAGE` and `RELAY_IMAGE` values from
   `blindport-images.env`.

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
   docker compose --env-file deploy/canary/.env \
     -f deploy/canary/compose.yaml config --quiet
   ```

7. Pull images, run the one-shot migration, and start the selected stack. For
   the single-host topology:

   ```sh
   cd deploy/canary
   docker compose --env-file .env -f compose.yaml pull
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

Open general defects and deployment problems in the
[issue tracker](https://github.com/blindport/blindport/issues). Report security
problems privately according to [SECURITY.md](../SECURITY.md).
