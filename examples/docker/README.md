# Automatic HTTPS with Docker

This example publishes one Nginx container through an existing paid Blindport
Relay subscription. `blindportd` obtains and renews the exact-hostname Let's
Encrypt certificate, terminates HTTPS inside the agent container, and forwards
plaintext to `site:80` on the Compose network.

It does not publish host ports or install a reverse proxy. The host needs Linux,
Docker Engine with Compose, and outbound Internet access.

## 1. Prepare the account

Create and pay for a Relay endpoint at [blindport.com](https://blindport.com).
Store the account token in a local owner-only file, then copy the active
subscription UUID from **Endpoint details** in the dashboard. The account and
subscription must match.

## 2. Configure

Create the private environment file:

```sh
cp .env.example .env
chmod 600 .env
```

Install the example config and create bind-mounted state and token paths for the
image's unprivileged UID. Do not put the bearer token in `.env`, Compose
environment, or rendered Compose output:

```sh
sudo install -d -o 10001 -g 10001 -m 0700 \
  /opt/blindport/config /opt/blindport/secrets /opt/blindport/state
sudo install -o 10001 -g 10001 -m 0600 \
  config/config.json /opt/blindport/config/config.json
sudo install -o 10001 -g 10001 -m 0600 \
  /dev/null /opt/blindport/secrets/public-token
sudoedit /opt/blindport/secrets/public-token
```

The resulting host layout is:

```text
/opt/blindport/
├── config/
│   └── config.json
├── secrets/
│   └── public-token
└── state/
```

`/opt/blindport/config/config.json` selects the mounted token and keeps this
account's identity and ACME state under the bind-mounted `state/` directory. The
config and token files must both be owned by UID `10001` with mode `0600`; the
three directories must be owned by `10001:10001` with mode `0700`.

Set:

- `DOMAIN` to the active Relay hostname, for the verification command below.
- `BLINDPORT_SUBSCRIPTION_ID` to the active Relay subscription UUID.

Compose defaults the Docker socket group to `999`. If the host uses another
group, set `DOCKER_GID` to `stat -c '%g' /var/run/docker.sock`.

Read the current [Let's Encrypt agreements](https://letsencrypt.org/repository/).
Change `ACME_TERMS_ACCEPTED=false` to `true` only after accepting the Subscriber
Agreement. An optional `ACME_EMAIL` supplies the ACME account contact.

For rootless Docker, set `DOCKER_SOCKET_PATH` to its Unix socket and derive
`DOCKER_GID` from that socket. Use a digest-pinned `BLINDPORTD_IMAGE` from the
matching Blindport release for a durable deployment. Version 3 account configs
require `blindportd v0.3.0` or newer. An untagged image is not refreshed
automatically, so pull before recreating the service.

## 3. Start and verify

```sh
docker compose config --quiet
docker compose pull blindportd
docker compose up -d
docker compose exec blindportd blindportd -version
docker compose logs -f blindportd
```

After the log reports that the automatic TLS certificate is installed:

```sh
curl --fail --show-error --silent "https://${DOMAIN}/"
```

`/opt/blindport/state` contains the enrolled client identity, ACME account, and
certificate private keys. Back up `/opt/blindport` as a secret and reuse it
across image updates. Starting another empty state directory with the same
account can require an operator identity reset and can consume Let's Encrypt
issuance limits.

`site` selects the configured `public` account with
`tech.blindport.mapping.site.account`. Version 3 requires this `.account` label
on every Docker mapping, including existing subscriptions. To add an account,
mount another owner-only token file and add an account with a distinct state path
to `/opt/blindport/config/config.json`:

```json
{
  "name": "private",
  "token_file": "/run/secrets/blindport-private",
  "state_dir": "/var/lib/blindport/accounts/private",
  "mappings": []
}
```

Add `/opt/blindport/secrets/private-token:/run/secrets/blindport-private:ro` to
the agent volumes after creating it with the same `10001:10001`, `0600`
ownership and mode.
Mappings for that account use labels such as
`tech.blindport.mapping.api.account: "private"`. Each account needs its own
non-overlapping state directory and token file.

Access to the Docker socket is effectively root-equivalent even with a read-only
mount. Prefer a narrowly authorized socket proxy where practical. Removing the
container or labels stops local forwarding but does not cancel the paid service.

To stop the example without deleting private state:

```sh
docker compose down
```

For a consistent offline backup, stop only the agent, archive the bind-mounted
tree, then start it again:

```sh
docker compose stop blindportd
sudo tar -C /opt -czf /root/blindport-backup.tgz blindport
docker compose start blindportd
```

The fixed `172.30.0.2` address lets an upstream proxy trust PROXY protocol only
from `172.30.0.2/32`. Change the subnet and fixed address together if they
conflict with another Docker network. A host service is not reachable as
`127.0.0.1` from this container; put it on the `blindport` network or add
`host.docker.internal:host-gateway` and use `host.docker.internal:<port>`.

## Declarative orders

Replace `.subscription` with `.product` to create an idempotent Relay or Port
order. The mapping name is the stable account-scoped order key, and every v3
mapping selects `.account`:

```yaml
tech.blindport.mapping.web.account: "public"
tech.blindport.mapping.web.product: "relay"
tech.blindport.mapping.web.domain: "web.relay.blindport.com"
tech.blindport.mapping.web.billing_term: "monthly"
tech.blindport.mapping.web.upstream: "site:80"
tech.blindport.mapping.web.tls_mode: "automatic"
tech.blindport.mapping.web.acme_terms_accepted: "true"

tech.blindport.mapping.game.account: "public"
tech.blindport.mapping.game.product: "port"
tech.blindport.mapping.game.transport: "udp"
tech.blindport.mapping.game.billing_term: "yearly"
tech.blindport.mapping.game.upstream: "game:27015"
```

With NWC configured, `payment_pending` means the initial payment is settling or
being reconciled. Without NWC, `awaiting_payment` requires payment in the
dashboard. Customer-owned Relay domains remain `awaiting_domain` until their
exact DNS-only CNAME verifies. Removing labels stops forwarding but does not
cancel, refund, or end a paid subscription. Docker labels cannot order routed IP.

## Containerized routed WireGuard

Run an annual WireGuard IP subscription in a separate agent process from Docker
discovery. It uses the host network namespace so `bpwg0` and its source policy
rules apply to the host:

```yaml
services:
  blindport-wireguard:
    image: ${BLINDPORTD_IMAGE:-ghcr.io/blindport/blindportd:latest}
    user: "0:0"
    network_mode: host
    init: true
    restart: unless-stopped
    command: ["--wireguard", "--token-file=/run/blindport/token", "--state-dir=/var/lib/blindport"]
    volumes:
      - /opt/blindport-wireguard/secrets/token:/run/blindport/token:ro
      - /opt/blindport-wireguard/state:/var/lib/blindport
    read_only: true
    cap_drop: [ALL]
    cap_add: [NET_ADMIN]
    security_opt: ["no-new-privileges:true"]
    tmpfs: ["/tmp:size=16m,mode=1777"]

```

Create `/opt/blindport-wireguard/secrets/token` as a root-owned regular file with
mode `0600` and its `state/` directory with mode `0700`. Preserve both as
secrets. `NET_ADMIN` is the only added capability required. Do not give this
process the Docker socket or combine it with `--docker`.
