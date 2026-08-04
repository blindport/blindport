# HTTPS site with Blindport and Traefik

This example publishes one static Nginx page through Blindport Relay. Traefik
obtains and renews the Let's Encrypt certificate with HTTP-01, terminates TLS,
and routes the request to Nginx. `blindportd` runs in the same Compose project
and discovers its mapping from the site container's Docker labels.

No host ports, router changes, or inbound firewall rules are required. The host
needs Linux, Docker Engine with Compose, outbound Internet access, and a
Lightning wallet to pay for the Blindport Relay subscription.

## 1. Order the hostname

1. Open [blindport.com](https://blindport.com), choose **Blindport Relay**, and
   choose any available name under the managed `relay.blindport.com` suffix.
2. Create the pending order and store the one-time account token in a password
   manager. Blindport cannot recover it.
3. In the dashboard, create and pay the Lightning invoice. Wait until the Relay
   subscription is active.
4. Copy the active Relay subscription UUID from the dashboard-generated
   `blindportd` configuration. This is not the account UUID. The subscription
   UUID and token must belong to the same account.

Managed `*.relay.blindport.com` names need no DNS changes. For a domain you own,
follow the dashboard's direct, DNS-only CNAME instructions before paying, then
set `DOMAIN` to that exact subdomain below.

## 2. Configure the example

On the Docker host, copy this directory and create its local environment file:

```sh
cp .env.example .env
```

Edit `.env` and set these values:

- `DOMAIN`: the exact active Relay hostname.
- `ACME_EMAIL`: the contact address for the Let's Encrypt ACME account.
- `BLINDPORT_SUBSCRIPTION_ID`: the active Relay subscription UUID.
- `DOCKER_GID`: the numeric group owner of the Docker socket, from
  `stat -c '%g' /var/run/docker.sock`.

Install the account token as an owner-only file for the UID used by the
published `blindportd` image. Create its private state directory at the same
time:

```sh
sudo install -d -o 10001 -g 10001 -m 0700 /etc/blindport
sudo install -d -o 10001 -g 10001 -m 0700 /var/lib/blindport
sudo install -o 10001 -g 10001 -m 0600 /path/to/saved-token /etc/blindport/token
```

Set `BLINDPORT_TOKEN_PATH` or `BLINDPORT_STATE_PATH` in `.env` if you use
different absolute host paths. Both paths must be owned by UID/GID `10001`;
the token must have mode `0600` and the state directory mode `0700`.

The example uses `ghcr.io/blindport/blindportd:latest` for a short evaluation.
For a durable deployment, set `BLINDPORTD_IMAGE` to the digest-pinned reference
from the matching release's `blindport-images.env` asset.

Do not share or publish the account token. It is a bearer credential for the
whole account, and each user should deploy this example with their own account
and subscription.

## 3. Deploy and verify

Validate the rendered configuration, start the three containers, and watch the
initial certificate request:

```sh
docker compose config --quiet
docker compose up -d
docker compose logs -f traefik blindportd
```

After both services settle, open the site or check it from another machine:

```sh
curl --fail --show-error --silent "https://${DOMAIN}/"
```

Traefik stores its ACME account and certificates in the `letsencrypt` volume.
`blindportd` stores its stable client identity in `BLINDPORT_STATE_PATH`. Back
up both as secrets and do not run a second agent with the same account token.
Let's Encrypt renewal is automatic while the Relay subscription and stack stay
active. Monitor certificate expiry independently because Let's Encrypt no
longer sends expiry notification emails.

The public Relay accepts HTTPS on port 443. Its port 80 path forwards only valid
`/.well-known/acme-challenge/` requests, so normal public HTTP requests and HTTP
to HTTPS redirects are intentionally unavailable.

## Stop the demo

```sh
docker compose down
```

Do not add `--volumes` unless you intend to delete the TLS state. Removing the
containers or labels stops local forwarding but does not delete
`BLINDPORT_STATE_PATH`, cancel service, or refund the Blindport subscription.

Both Traefik and `blindportd` read the Docker socket. Even a read-only mount
provides root-equivalent Docker API access. Keep deployment access restricted
and use a narrowly authorized socket proxy for a production hardening pass.
