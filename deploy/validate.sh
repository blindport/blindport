#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

compose_check() {
    directory="$1"
    docker compose \
        --env-file "$root/$directory/.env.example" \
        -f "$root/$directory/compose.yaml" \
        config --quiet
}

backend_healthcheck_policy_check() {
    directory="$1"
    docker compose \
        --env-file "$root/$directory/.env.example" \
        -f "$root/$directory/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

healthcheck = json.load(sys.stdin)["services"]["backend"]["healthcheck"]
assert healthcheck["timeout"] == "15s"
assert "timeout=12" in healthcheck["test"][-1]
'
}

smtp_secret_scope_check() {
    directory="$1"
    docker compose \
        --env-file "$root/$directory/.env.example" \
        -f "$root/$directory/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

services = json.load(sys.stdin)["services"]
for name, service in services.items():
    secret_names = {
        item if isinstance(item, str) else item.get("source")
        for item in service.get("secrets", [])
    }
    environment = service.get("environment", {})
    if name == "backend":
        assert "smtp-password" in secret_names
    else:
        assert "smtp-password" not in secret_names
        assert not environment.get("SMTP_PASSWORD_FILE")
'
}

caddy_check() {
    directory="$1"
    config="${2:-Caddyfile}"
    docker run --rm \
        --env-file "$root/$directory/.env.example" \
        -v "$root/$directory/$config:/etc/caddy/Caddyfile:ro" \
        caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d \
        caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
}

haproxy_check() {
    directory="$1"
    docker run --rm \
        --env-file "$root/$directory/.env.example" \
        -v "$root/$directory/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
        haproxy:3.2.1-alpine@sha256:ac79fe145f2bb6626ff26b584a2d0a34e791906c01015f2ae037aa3137b683d9 \
        haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg
}

caddy_runtime_policy_check() {
    docker run --rm \
        --user 1000:1000 \
        --cap-drop ALL \
        --cap-add NET_BIND_SERVICE \
        --security-opt no-new-privileges:true \
        caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d \
        caddy version >/dev/null
}

caddy_admin_policy_check() {
    directory="$1"
    config="${2:-Caddyfile}"
    docker run --rm \
        --env-file "$root/$directory/.env.example" \
        -v "$root/$directory/$config:/etc/caddy/Caddyfile:ro" \
        caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d \
        caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile \
        | python3 -c '
import json
import sys

config = json.dumps(json.load(sys.stdin), sort_keys=True)
for protected in ("/admin*", "/api/v1/admin/*", "/api/v2/admin/*"):
    assert protected in config
'
}

canary_proxy_protocol_check() {
    config="$1"
    docker run --rm \
        --env-file "$root/deploy/canary/.env.example" \
        -v "$root/deploy/canary/$config:/etc/caddy/Caddyfile:ro" \
        caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d \
        caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile \
        | python3 -c '
import json
import sys

servers = json.load(sys.stdin)["apps"]["http"]["servers"].values()
matches = [server for server in servers if server.get("listen") == ["127.0.0.1:8443"]]
assert len(matches) == 1
assert matches[0].get("protocols") == ["h1", "h2"]
wrappers = matches[0].get("listener_wrappers", [])
assert [wrapper.get("wrapper") for wrapper in wrappers] == ["proxy_protocol", "tls"]
proxy = wrappers[0]
assert set(proxy.get("allow", [])) == {"127.0.0.1/32", "::1/128"}
assert proxy.get("fallback_policy") == "REQUIRE"

onion_servers = [server for server in servers if "127.0.0.1:8080" in server.get("listen", [])]
assert len(onion_servers) == 1
onion_config = json.dumps(onion_servers[0], sort_keys=True)
assert "replace-with-v3-onion-host.onion" in onion_config
for protected in ("/internal/*", "/admin*", "/api/v1/admin/*", "/api/v2/admin/*"):
    assert protected in onion_config
assert "\"handler\": \"file_server\"" in onion_config
assert "\"status_code\": 404" in onion_config
'
}

compose_check deploy/canary
compose_check deploy/split/control
compose_check deploy/split/relay
backend_healthcheck_policy_check deploy/canary
backend_healthcheck_policy_check deploy/split/control
smtp_secret_scope_check deploy/canary
smtp_secret_scope_check deploy/split/control
caddy_check deploy/canary
caddy_check deploy/canary Caddyfile.internal
caddy_check deploy/split/control
haproxy_check deploy/canary
caddy_runtime_policy_check
caddy_admin_policy_check deploy/canary
caddy_admin_policy_check deploy/canary Caddyfile.internal
caddy_admin_policy_check deploy/split/control
canary_proxy_protocol_check Caddyfile
canary_proxy_protocol_check Caddyfile.internal

echo "deployment configuration validation passed"
