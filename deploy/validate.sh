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

migration_credential_scope_check() {
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
migrate = services["migrate"]
environment = migrate["environment"]
assert environment["CREDENTIAL_ENCRYPTION_KEY_FILE"] == services["backend"]["environment"]["CREDENTIAL_ENCRYPTION_KEY_FILE"]
secret_names = {
    item if isinstance(item, str) else item.get("source")
    for item in migrate.get("secrets", [])
}
assert "credential-encryption-key" in secret_names
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

wireguard_production_policy_check() {
    control_directory="$1"
    relay_directory="$2"
    docker compose \
        --env-file "$root/$control_directory/.env.example" \
        -f "$root/$control_directory/compose.yaml" \
        -f "$root/$control_directory/compose.wireguard.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

backend = json.load(sys.stdin)["services"]["backend"]
environment = backend["environment"]
assert "WIREGUARD_PUBLIC_IPS" in environment
assert "WIREGUARD_RELAY_PUBLIC_KEY" in environment
assert environment["WIREGUARD_ENDPOINT"].endswith(":51820")
assert int(environment["WIREGUARD_SMTP_EGRESS_FEE_SATS"]) > 0
'

    docker compose \
        --env-file "$root/$control_directory/.env.example" \
        -f "$root/$control_directory/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

environment = json.load(sys.stdin)["services"]["backend"]["environment"]
assert environment["WIREGUARD_PUBLIC_IPS"] == ""
assert environment["WIREGUARD_RELAY_PUBLIC_KEY"] == ""
assert environment["WIREGUARD_ENDPOINT"] == ""
'

    docker compose \
        --env-file "$root/$relay_directory/.env.example" \
        -f "$root/$relay_directory/compose.yaml" \
        -f "$root/$relay_directory/compose.wireguard.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

relay = json.load(sys.stdin)["services"]["relay"]
environment = relay["environment"]
assert relay["network_mode"] == "host"
assert "NET_ADMIN" in relay["cap_add"]
assert relay["user"] == "0:0"
assert relay["read_only"] is True
assert environment["BLINDPORT_RELAY_WIREGUARD"] == "1"
assert environment["BLINDPORT_RELAY_WIREGUARD_KEY_FILE"] == "/run/secrets/wireguard-key"
assert int(environment["BLINDPORT_RELAY_WIREGUARD_PORT"]) == 51820
assert "BLINDPORT_RELAY_WIREGUARD_ALLOW_PRIVATE_DESTINATIONS" not in environment
secret_names = {
    item if isinstance(item, str) else item.get("source")
    for item in relay["secrets"]
}
assert "wireguard-key" in secret_names
for name in ("relay-secret", "wireguard-key"):
    mounted = next(
        item for item in relay["secrets"]
        if isinstance(item, dict) and item.get("source") == name
    )
    assert mounted["uid"] == "0"
    assert mounted["gid"] == "0"
'

    docker compose \
        --env-file "$root/$relay_directory/.env.example" \
        -f "$root/$relay_directory/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

relay = json.load(sys.stdin)["services"]["relay"]
environment = relay["environment"]
assert environment["BLINDPORT_RELAY_WIREGUARD"] == "0"
assert "NET_ADMIN" not in relay.get("cap_add", [])
assert relay.get("user", "10001:10001") != "0:0"
assert "BLINDPORT_RELAY_WIREGUARD_KEY_FILE" not in environment
secret_names = {
    item if isinstance(item, str) else item.get("source")
    for item in relay.get("secrets", [])
}
assert "wireguard-key" not in secret_names
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

docker_example_check() {
    docker compose \
        --env-file "$root/examples/docker/.env.example" \
        -f "$root/examples/docker/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

services = json.load(sys.stdin)["services"]
assert set(services) == {"blindportd", "site"}
assert all(not service.get("ports") for service in services.values())
assert all(set(service["networks"]) == {"default"} for service in services.values())
assert "user" not in services["blindportd"]
assert services["blindportd"]["depends_on"]["site"]["condition"] == "service_started"
assert services["blindportd"]["command"] == ["--docker"]
assert services["blindportd"]["read_only"] is True
assert services["blindportd"]["cap_drop"] == ["ALL"]
assert services["blindportd"]["security_opt"] == ["no-new-privileges:true"]

labels = services["site"]["labels"]
assert labels["tech.blindport.mapping.site.subscription"] == "12312312-3123-4123-8123-123123123123"
assert labels["tech.blindport.mapping.site.upstream"] == "site:80"
assert labels["tech.blindport.mapping.site.tls_mode"] == "automatic"
assert labels["tech.blindport.mapping.site.acme_terms_accepted"] == "false"
assert not any(key.startswith("traefik.") for key in labels)

socket = next(
    volume
    for volume in services["blindportd"]["volumes"]
    if volume["target"] == "/var/run/docker.sock"
)
assert socket["read_only"] is True

state = next(
    volume
    for volume in services["blindportd"]["volumes"]
    if volume["target"] == "/var/lib/blindport"
)
assert state["type"] == "volume"
assert state["source"] == "blindport-state"
assert not state.get("read_only", False)
assert services["blindportd"]["environment"]["BLINDPORT_TOKEN"] == "replace-with-your-account-token"
assert services["blindportd"]["environment"]["BLINDPORT_ACME_EMAIL"] == ""
assert "BLINDPORT_TOKEN_FILE" not in services["blindportd"]["environment"]
'

    DOCKER_SOCKET_PATH=/run/user/1234/docker.sock docker compose \
        --env-file "$root/examples/docker/.env.example" \
        -f "$root/examples/docker/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

services = json.load(sys.stdin)["services"]
socket = next(
    volume
    for volume in services["blindportd"]["volumes"]
    if volume["target"] == "/var/run/docker.sock"
)
assert socket["source"] == "/run/user/1234/docker.sock"
'

    DOCKER_GID=1001 ACME_EMAIL=owner@example.com ACME_TERMS_ACCEPTED=true \
        docker compose \
        --env-file "$root/examples/docker/.env.example" \
        -f "$root/examples/docker/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

services = json.load(sys.stdin)["services"]
assert services["blindportd"]["group_add"] == ["1001"]
assert services["blindportd"]["environment"]["BLINDPORT_ACME_EMAIL"] == "owner@example.com"
assert services["site"]["labels"]["tech.blindport.mapping.site.acme_terms_accepted"] == "true"
'
}

ha_lab_policy_check() {
    docker compose \
        --profile tools \
        -f "$root/deploy/ha-lab/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys
from pathlib import Path

config = json.load(sys.stdin)
services = config["services"]
assert {"backend-a", "backend-b", "api-lb", "relay-a", "relay-b"} <= set(services)
assert all(not service.get("ports") for service in services.values())
assert all(network.get("internal") is True for network in config["networks"].values())

for name in ("backend-a", "backend-b", "api-lb", "relay-a", "relay-b", "postgres"):
    assert services[name].get("healthcheck"), name
for name in ("backend-a", "backend-b"):
    assert services[name]["environment"]["CA_DIR"] == "/var/lib/blindport/ca"
    assert any(volume["source"].endswith("backend-ca") for volume in services[name]["volumes"])
    assert services[name]["environment"]["RELAY_CONTROL_URLS"] == "relay-a:5443,relay-b:5443"

assert services["relay-a"]["environment"]["BLINDPORT_BACKEND_URL"] == "http://api-lb:8000"
assert services["relay-b"]["environment"]["BLINDPORT_BACKEND_URL"] == "http://api-lb:8000"
assert set(services["relay-a"]["networks"]) == {"control", "edge-a"}
assert set(services["relay-b"]["networks"]) == {"control", "edge-b"}
assert services["postgres"]["image"].startswith("postgres:17.5-alpine@sha256:")
assert services["api-lb"]["image"].startswith("haproxy:3.2.1-alpine@sha256:")

haproxy = Path(sys.argv[1]).read_text(encoding="utf-8")
assert "balance roundrobin" in haproxy
assert "option httpchk GET /api/v1/health/ready" in haproxy
assert "cookie" not in haproxy.lower()
assert "server backend-a backend-a:8000" in haproxy
assert "server backend-b backend-b:8000" in haproxy
' "$root/deploy/ha-lab/haproxy.cfg"
}

compose_check deploy/canary
compose_check deploy/split/control
compose_check deploy/split/relay
compose_check deploy/ha-lab
compose_check examples/docker
backend_healthcheck_policy_check deploy/canary
backend_healthcheck_policy_check deploy/split/control
smtp_secret_scope_check deploy/canary
smtp_secret_scope_check deploy/split/control
migration_credential_scope_check deploy/canary
migration_credential_scope_check deploy/split/control
logging_policy_check deploy/canary
logging_policy_check deploy/split/control
logging_policy_check deploy/split/relay
wireguard_production_policy_check deploy/canary deploy/canary
wireguard_production_policy_check deploy/split/control deploy/split/relay
address_log_policy_check
caddy_check deploy/canary
caddy_check deploy/canary Caddyfile.internal
caddy_check deploy/split/control
caddy_log_policy_check deploy/canary
caddy_log_policy_check deploy/canary Caddyfile.internal
caddy_log_policy_check deploy/split/control
haproxy_check deploy/canary
haproxy_check deploy/ha-lab
canary_http_routing_check
caddy_runtime_policy_check
caddy_admin_policy_check deploy/canary
caddy_admin_policy_check deploy/canary Caddyfile.internal
caddy_admin_policy_check deploy/split/control
canary_proxy_protocol_check Caddyfile
canary_proxy_protocol_check Caddyfile.internal
docker_example_check
ha_lab_policy_check

echo "deployment configuration validation passed"
