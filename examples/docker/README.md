# Automatic HTTPS with Docker

This example publishes one Nginx container through an existing paid Blindport
Relay subscription. `blindportd` obtains and renews the exact-hostname Let's
Encrypt certificate, terminates HTTPS inside the agent container, and forwards
plaintext to `site:80` on the Compose network.

It does not publish host ports or install a reverse proxy. The host needs Linux,
Docker Engine with Compose, and outbound Internet access.

## 1. Prepare the account

Create and pay for a Relay endpoint at [blindport.com](https://blindport.com).
Store the account token, then copy the active subscription UUID from **Endpoint
details** in the dashboard. The account and subscription must match.

## 2. Configure

Create the private environment file:

```sh
cp .env.example .env
chmod 600 .env
```

Set:

- `DOMAIN` to the active Relay hostname, for the verification command below.
- `BLINDPORT_SUBSCRIPTION_ID` to the active Relay subscription UUID.
- `BLINDPORT_TOKEN` to that account's bearer token.
- `DOCKER_GID` to `stat -c '%g' /var/run/docker.sock`.

Read the current [Let's Encrypt agreements](https://letsencrypt.org/repository/).
Change `ACME_TERMS_ACCEPTED=false` to `true` only after accepting the Subscriber
Agreement. An optional `ACME_EMAIL` supplies the ACME account contact.

For rootless Docker, set `DOCKER_SOCKET_PATH` to its Unix socket and derive
`DOCKER_GID` from that socket. Use a digest-pinned `BLINDPORTD_IMAGE` from the
matching Blindport release for a durable deployment.

## 3. Start and verify

```sh
docker compose config --quiet
docker compose up -d
docker compose logs -f blindportd
```

After the log reports that the automatic TLS certificate is installed:

```sh
curl --fail --show-error --silent "https://${DOMAIN}/"
```

The `blindport-state` volume contains the enrolled client identity, ACME account,
and certificate private keys. Back it up as a secret and reuse it across image
updates. Starting another empty state volume with the same account can require an
operator identity reset and can consume Let's Encrypt issuance limits.

Access to the Docker socket is effectively root-equivalent even with a read-only
mount. Prefer a narrowly authorized socket proxy where practical. Removing the
container or labels stops local forwarding but does not cancel the paid service.

To stop the example without deleting private state:

```sh
docker compose down
```
