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
4. Copy the subscription UUID shown on the active Relay card. This is not the
   account UUID at the top of the dashboard. The subscription UUID and token
   must belong to the same account.

Managed `*.relay.blindport.com` names need no DNS changes. For a domain you own,
follow the dashboard's direct, DNS-only CNAME instructions before paying, then
set `DOMAIN` to that exact subdomain below.

## 2. Configure the example

On the Docker host, copy this directory and create its local environment file:

```sh
cp .env.example .env
chmod 600 .env
```

Edit `.env` and set these values:

- `DOMAIN`: the exact active Relay hostname.
- `BLINDPORT_SUBSCRIPTION_ID`: the active Relay subscription UUID.
- `BLINDPORT_TOKEN`: the account token shown during signup.
- `DOCKER_GID`: the output of `stat -c '%g' /var/run/docker.sock`.

The token is an environment variable only in the Docker workflow. Compose stores
the enrolled client identity in the private `blindport-state` volume, so host UID
and file mode differences do not affect startup. Back up that volume as a secret.
If an older deployment already enrolled from a host bind mount, copy its
`credential.json` into the named volume as UID/GID 10001 with mode `0600` before
switching. Starting with an empty volume creates a different identity and requires
an operator reset.

For rootless Docker, add its socket path to `.env` and set `DOCKER_GID` from that
socket (replace `1000` with the output of `id -u`):

```dotenv
DOCKER_SOCKET_PATH=/run/user/1000/docker.sock
DOCKER_GID=1000
```

For rootful Docker, the default `/var/run/docker.sock` is correct:

```sh
printf 'DOCKER_GID=%s\n' "$(stat -c '%g' /var/run/docker.sock)" >> .env
```

`ACME_EMAIL` is optional. Leave it unset to register with Let's Encrypt without
an email address, or add a real address to `.env`.

The example uses `ghcr.io/blindport/blindportd:latest` for a short evaluation.
For a durable deployment, set `BLINDPORTD_IMAGE` to the digest-pinned reference
from the matching release's `blindport-images.env` asset.

Do not share or publish the account token. It is a bearer credential for the
whole account, and each user should deploy this example with their own account
and subscription.

One `blindportd` container serves every framed subscription in the account. To
publish another container, add its Traefik labels and a second set of
`tech.blindport.mapping.<name>.*` labels with a unique mapping name and that
subscription's UUID. Keep the existing `blindportd` service; it discovers all
of the labeled containers and runs all mappings together.

## 3. Deploy and verify

Validate the rendered configuration, start the three containers, and watch the
initial certificate request. Traefik gives Blindport up to 30 seconds to
establish the tunnel before starting its first ACME challenge:

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
`blindportd` stores its stable client identity under
the `blindport-state` volume. Back up both volumes as secrets and do not run a
second agent with the same account token.
Let's Encrypt renewal is automatic while the Relay subscription and stack stay
active. Monitor certificate expiry independently because Let's Encrypt no
longer sends expiry notification emails.

The public Relay accepts HTTPS on port 443. On port 80 it forwards valid
`/.well-known/acme-challenge/` requests to Traefik and permanently redirects
other valid GET requests to the same HTTPS host, path, and query.

## Stop the demo

```sh
docker compose down
```

Do not add `--volumes` unless you intend to delete the TLS state. Removing the
containers or labels stops local forwarding but does not delete the Blindport
state directory, cancel service, or refund the Blindport subscription.

Both Traefik and `blindportd` read the Docker socket. Even a read-only mount
provides control of the selected Docker daemon. This example favors a short,
working setup; harden the containers and use a socket proxy as needed for a
long-lived deployment.

## Use an existing Traefik

Do not start the `traefik` service from this example when the host already runs
Traefik. Add the `tech.blindport.mapping.*` labels to the service handled by your
existing proxy, connect `blindportd` to that proxy's Docker network, and start
only the agent:

```sh
docker compose up -d blindportd
```

Set each mapping upstream to the existing proxy's service name and TLS port.
This avoids two Traefik Docker providers discovering the same labels.
