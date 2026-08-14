# Wildcard Relay with Traefik

This example publishes one application through an active customer-owned wildcard
Blindport Relay. Blindport routes by SNI without terminating TLS. `blindportd`
prepends trusted PROXY protocol v2 metadata, Traefik terminates TLS on the customer
machine, and Traefik supplies `X-Forwarded-For` to the application.

No service publishes a host port. The fixed private `172.30.0.2` agent address is
trusted only on Traefik's private entrypoints.

## DNS

Complete the Blindport ownership and routing records shown by the dashboard:

```text
_blindport-challenge.example.com  TXT    <Blindport token>
*.example.com                     CNAME  <subscription pool target>
```

Point the base separately if it should also be reachable. A subdomain base can use
CNAME. A zone apex needs provider ALIAS, ANAME, or CNAME flattening.

The default Traefik router requests one certificate containing `example.com` and
`*.example.com`. ACME wildcard issuance requires DNS-01, so Traefik creates this
separate record through the Cloudflare API:

```text
_acme-challenge.example.com       TXT    <ACME proof>
```

Adapt the Traefik DNS provider and secret variable for another supported provider.
The Blindport ownership token and ACME proof are unrelated.

## Configure

Create the environment and owner-only secrets:

```sh
cp .env.example .env
chmod 600 .env
sudo chown 10001:10001 config/accounts.json
chmod 0600 config/accounts.json
sudo install -d -o 10001 -g 10001 -m 0700 secrets
sudo install -o 10001 -g 10001 -m 0600 /dev/null secrets/public-token
sudoedit secrets/public-token
sudo install -o root -g root -m 0600 /dev/null secrets/cloudflare-dns-api-token
sudoedit secrets/cloudflare-dns-api-token
```

Set `BASE_DOMAIN`, `APP_HOSTNAME`, `BLINDPORT_SUBSCRIPTION_ID`, `ACME_EMAIL`, and
`DOCKER_GID` in `.env`. The account token must own the active wildcard subscription.
Use a Cloudflare API token limited to DNS edits for the selected zone. Keep the
Blindport state and Traefik ACME volumes across upgrades and back them up as secrets.

The account config and public token must be owned by UID `10001`, with config mode
`0600`. A production deployment should use digest-pinned images and a narrowly
authorized Docker socket proxy.

If `172.30.0.0/24` conflicts with an existing network, change the Compose subnet,
the two fixed container addresses, and both Traefik `trustedips` values together.

## Start

```sh
docker compose config --quiet
docker compose up -d
docker compose logs -f blindportd traefik
```

After Traefik installs the certificate:

```sh
curl --fail --show-error --silent "https://${APP_HOSTNAME}/"
```

Traefik accepts PROXY protocol only from `172.30.0.2/32`. Do not replace this with
an unrestricted trust setting. The application should trust forwarding headers only
from Traefik. The reported address is the direct source observed by the Blindport
Relay; an additional provider-side TCP proxy or large NAT can still be that source.

## Exact HTTP-01 certificates

The mapping also forwards validated port 80 challenge requests to `traefik:80`.
To let Traefik obtain an exact certificate such as `app.example.com` without DNS
credentials:

1. Change the router's certificate resolver to `letsencrypt-http`.
2. Remove both `tls.domains[0]` labels so Traefik infers `APP_HOSTNAME` from the
   exact `Host` rule.
3. Remove the Cloudflare environment and secret mount when no DNS resolver uses it.

The public validation path is CA to Blindport Relay port 80, through the tunnel to
`blindportd`, then to Traefik. `blindportd` validates and transports the request but
does not own the ACME account or certificate. HTTP-01 cannot issue `*.example.com`.

## Plaintext local hop

For an exact Relay subscription, `blindportd` can own the certificate and send
decrypted HTTP plus PROXY v2 to an internal Traefik entrypoint:

```yaml
tech.blindport.mapping.edge.upstream: "traefik:8080"
tech.blindport.mapping.edge.tls_mode: "automatic"
tech.blindport.mapping.edge.acme_terms_accepted: "true"
tech.blindport.mapping.edge.proxy_protocol: "v2"
```

Configure Traefik entrypoint `:8080` to trust `172.30.0.2/32` for PROXY protocol and
route it without Traefik TLS:

```yaml
command:
  - --entrypoints.blindport-http.address=:8080
  - --entrypoints.blindport-http.proxyprotocol.trustedips=172.30.0.2/32
labels:
  traefik.http.routers.site.entrypoints: "blindport-http"
  traefik.http.routers.site.tls: "false"
```

Remove the router certificate resolver and TLS domain labels in this mode. Traefik
uses the PROXY source to create `X-Forwarded-For` before forwarding HTTP to the app.
`blindportd`, not Traefik, requests the exact-hostname certificate. Wildcard Relay
subscriptions reject automatic TLS, so their local hop to Traefik remains the
original encrypted TLS stream.
