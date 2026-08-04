#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

compose_check() {
    directory="$1"
    docker compose \
        --profile tools \
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

logging_policy_check() {
    directory="$1"
    docker compose \
        --profile tools \
        --env-file "$root/$directory/.env.example" \
        -f "$root/$directory/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

services = json.load(sys.stdin)["services"]
for name, service in services.items():
    logging = service.get("logging", {})
    assert logging.get("driver") == "journald", (name, logging)
    assert logging.get("options", {}).get("tag", "").startswith("blindport-")
'
}

address_log_policy_check() {
    python3 - \
        "$root/deploy/journald-blindport.conf" \
        "$root/docker/backend.Dockerfile" \
        "$root/docker/docker-compose.yaml" \
        "$root/deploy/canary/Caddyfile" \
        "$root/deploy/canary/Caddyfile.internal" \
        "$root/deploy/split/control/Caddyfile" \
        "$root/deploy/canary/haproxy.cfg" <<'PY'
from pathlib import Path
import sys

journal, dockerfile, development_compose, *proxy_configs = (
    Path(path).read_text(encoding="utf-8") for path in sys.argv[1:]
)
assert "MaxRetentionSec=30day" in journal
assert "MaxFileSec=1day" in journal
assert "ForwardToSyslog=no" in journal
assert "--no-access-log" in dockerfile
assert "--no-access-log" in development_compose
for config in proxy_configs[:3]:
    assert "\n\tlog {" not in config
    assert "exclude http.log.error" in config
haproxy = proxy_configs[3]
assert "log stdout" not in haproxy
assert "option tcplog" not in haproxy
assert "option httplog" not in haproxy
PY
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

caddy_log_policy_check() {
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

config = json.load(sys.stdin)
logs = config.get("logging", {}).get("logs", {})
assert "http.log.error" in logs.get("default", {}).get("exclude", [])
servers = config["apps"]["http"]["servers"].values()
assert all(server.get("logs") is None for server in servers)
'
}

haproxy_check() {
    directory="$1"
    docker run --rm \
        --env-file "$root/$directory/.env.example" \
        -v "$root/$directory/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
        haproxy:3.2.1-alpine@sha256:ac79fe145f2bb6626ff26b584a2d0a34e791906c01015f2ae037aa3137b683d9 \
        haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg
}

canary_http_routing_check() {
    python3 - "$root/deploy/canary/haproxy.cfg" <<'PY'
from pathlib import Path
import sys

config = Path(sys.argv[1]).read_text(encoding="utf-8")
assert 'acl api_host hdr(host),field(1,:) -i "${API_DOMAIN}"' in config
assert "use_backend api_http if api_host" in config
assert "default_backend relay_http" in config
assert "backend relay_http" in config
assert "acl acme_path" not in config
assert "relay_acme" not in config
PY
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

traefik_example_check() {
    docker compose \
        --env-file "$root/examples/traefik/.env.example" \
        -f "$root/examples/traefik/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import os
import sys

services = json.load(sys.stdin)["services"]
assert set(services) == {"blindportd", "site", "traefik"}
assert all(not service.get("ports") for service in services.values())
assert all(set(service["networks"]) == {"ingress"} for service in services.values())
assert services["blindportd"]["user"] == "0:0"
assert services["blindportd"]["depends_on"]["site"]["condition"] == "service_started"
assert services["traefik"]["depends_on"]["blindportd"]["condition"] == "service_started"
assert services["traefik"]["entrypoint"] == [
    "/bin/sh",
    "-c",
    "sleep 30; exec /entrypoint.sh \"$$@\"",
    "--",
]
assert services["blindportd"]["environment"]["BLINDPORT_DOCKER_POLL_INTERVAL"] == "1s"

labels = services["site"]["labels"]
assert labels["tech.blindport.mapping.site.subscription"] == "12312312-3123-4123-8123-123123123123"
assert labels["tech.blindport.mapping.site.upstream"] == "traefik:443"
assert labels["tech.blindport.mapping.site.http_challenge_upstream"] == "traefik:80"
assert labels["traefik.http.routers.site.rule"] == "Host(`your-name.relay.blindport.com`)"
assert labels["traefik.http.routers.site.entrypoints"] == "websecure"
assert labels["traefik.http.routers.site.tls"] == "true"
assert labels["traefik.http.routers.site.tls.certresolver"] == "letsencrypt"

command = services["traefik"]["command"]
assert "--providers.docker.exposedbydefault=false" in command
assert "--entrypoints.web.address=:80" in command
assert "--entrypoints.websecure.address=:443" in command
assert "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web" in command
assert not any("acme.email" in item for item in command)
assert services["traefik"]["environment"]["TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_EMAIL"] == ""

for name in ("blindportd", "traefik"):
    socket = next(
        volume
        for volume in services[name]["volumes"]
        if volume["target"] == "/var/run/docker.sock"
    )
    assert socket["read_only"] is True

state = next(
    volume
    for volume in services["blindportd"]["volumes"]
    if volume["target"] == "/var/lib/blindport"
)
assert state["type"] == "bind"
assert state["source"] == os.path.expanduser("~/.local/state/blindport")
assert not state.get("read_only", False)

token = next(
    volume
    for volume in services["blindportd"]["volumes"]
    if volume["target"] == "/run/secrets/blindport_token"
)
assert token["source"] == os.path.expanduser("~/.config/blindport/token")
'

    DOCKER_SOCKET_PATH=/run/user/1234/docker.sock docker compose \
        --env-file "$root/examples/traefik/.env.example" \
        -f "$root/examples/traefik/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

services = json.load(sys.stdin)["services"]
for name in ("blindportd", "traefik"):
    socket = next(
        volume
        for volume in services[name]["volumes"]
        if volume["target"] == "/var/run/docker.sock"
    )
    assert socket["source"] == "/run/user/1234/docker.sock"
'

    BLINDPORTD_USER=1234:1234 DOCKER_GID=999 ACME_EMAIL=owner@example.com \
        docker compose \
        --env-file "$root/examples/traefik/.env.example" \
        -f "$root/examples/traefik/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

services = json.load(sys.stdin)["services"]
assert services["blindportd"]["user"] == "1234:1234"
assert services["blindportd"]["group_add"] == ["999"]
assert services["traefik"]["environment"]["TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_EMAIL"] == "owner@example.com"
'
}

compose_check deploy/canary
compose_check deploy/split/control
compose_check deploy/split/relay
compose_check examples/traefik
backend_healthcheck_policy_check deploy/canary
backend_healthcheck_policy_check deploy/split/control
smtp_secret_scope_check deploy/canary
smtp_secret_scope_check deploy/split/control
logging_policy_check deploy/canary
logging_policy_check deploy/split/control
logging_policy_check deploy/split/relay
address_log_policy_check
caddy_check deploy/canary
caddy_check deploy/canary Caddyfile.internal
caddy_check deploy/split/control
caddy_log_policy_check deploy/canary
caddy_log_policy_check deploy/canary Caddyfile.internal
caddy_log_policy_check deploy/split/control
haproxy_check deploy/canary
canary_http_routing_check
caddy_runtime_policy_check
caddy_admin_policy_check deploy/canary
caddy_admin_policy_check deploy/canary Caddyfile.internal
caddy_admin_policy_check deploy/split/control
canary_proxy_protocol_check Caddyfile
canary_proxy_protocol_check Caddyfile.internal
traefik_example_check

echo "deployment configuration validation passed"
