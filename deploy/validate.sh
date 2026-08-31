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

production_compose_guard_check() {
    guard="$root/deploy/production/compose.sh"
    guard_tmp="$(mktemp -d "${TMPDIR:-/tmp}/blindport-compose-guard.XXXXXX")"
    trap 'rm -rf "$guard_tmp"' 0 1 2 15

    fake_docker="$guard_tmp/docker"
    cat > "$fake_docker" <<'EOF'
#!/bin/sh
set -eu
: "${BLINDPORT_COMPOSE_CAPTURE:?}"
printf '%s\n' "$@" > "$BLINDPORT_COMPOSE_CAPTURE"
EOF
    chmod 0700 "$fake_docker"

    empty_env="$guard_tmp/empty.env"
    enabled_env="$guard_tmp/enabled.env"
    capture="$guard_tmp/args"
    error_output="$guard_tmp/error"
    printf 'WIREGUARD_PUBLIC_IPS=\n' > "$empty_env"
    printf 'WIREGUARD_PUBLIC_IPS=192.0.2.10\n' > "$enabled_env"

    BLINDPORT_DOCKER_BIN="$fake_docker" \
        BLINDPORT_ENV_FILE="$empty_env" \
        BLINDPORT_COMPOSE_CAPTURE="$capture" \
        "$guard" config --quiet
    python3 - "$capture" "$empty_env" "$root/deploy/production/compose.yaml" <<'PY'
import sys
from pathlib import Path

actual = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
assert actual == ["compose", "--env-file", sys.argv[2], "-f", sys.argv[3], "config", "--quiet"]
PY

    rm -f "$capture"
    if BLINDPORT_DOCKER_BIN="$fake_docker" \
        BLINDPORT_ENV_FILE="$enabled_env" \
        BLINDPORT_COMPOSE_CAPTURE="$capture" \
        "$guard" config --quiet 2> "$error_output"; then
        printf '%s\n' 'production Compose guard accepted routed inventory without an overlay' >&2
        exit 1
    fi
    test ! -e "$capture"
    python3 - "$error_output" <<'PY'
import sys
from pathlib import Path

error = Path(sys.argv[1]).read_text(encoding="utf-8")
assert "select --wireguard or --wireguard-control" in error
PY

    BLINDPORT_DOCKER_BIN="$fake_docker" \
        BLINDPORT_ENV_FILE="$enabled_env" \
        BLINDPORT_COMPOSE_CAPTURE="$capture" \
        "$guard" --wireguard-control up -d backend
    python3 - \
        "$capture" \
        "$enabled_env" \
        "$root/deploy/production/compose.yaml" \
        "$root/deploy/production/compose.wireguard-control.yaml" <<'PY'
import sys
from pathlib import Path

actual = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
assert actual == [
    "compose",
    "--env-file",
    sys.argv[2],
    "-f",
    sys.argv[3],
    "-f",
    sys.argv[4],
    "up",
    "-d",
    "backend",
]
PY

    BLINDPORT_DOCKER_BIN="$fake_docker" \
        BLINDPORT_ENV_FILE="$enabled_env" \
        BLINDPORT_COMPOSE_CAPTURE="$capture" \
        "$guard" --wireguard ps
    python3 - \
        "$capture" \
        "$enabled_env" \
        "$root/deploy/production/compose.yaml" \
        "$root/deploy/production/compose.wireguard.yaml" <<'PY'
import sys
from pathlib import Path

actual = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
assert actual == [
    "compose",
    "--env-file",
    sys.argv[2],
    "-f",
    sys.argv[3],
    "-f",
    sys.argv[4],
    "ps",
]
PY

    rm -rf "$guard_tmp"
    trap - 0 1 2 15
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

port_capacity_policy_check() {
    control_directory="$1"
    relay_directory="$2"
    docker compose \
        --env-file "$root/$control_directory/.env.example" \
        -f "$root/$control_directory/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

environment = json.load(sys.stdin)["services"]["backend"]["environment"]
assert environment["RELAY_SHARED_TCP_PORTS"] == "10000-65535"
assert environment["RELAY_SHARED_UDP_PORTS"] == "10000-65535"
assert environment["PORT_TCP_CAPACITY"] == "4096"
assert environment["PORT_UDP_CAPACITY"] == "4096"
'

    docker compose \
        --env-file "$root/$relay_directory/.env.example" \
        -f "$root/$relay_directory/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

environment = json.load(sys.stdin)["services"]["relay"]["environment"]
assert environment["BLINDPORT_RELAY_SHARED_TCP_PORTS"] == "10000-65535"
assert environment["BLINDPORT_RELAY_SHARED_UDP_PORTS"] == "10000-65535"
assert environment["BLINDPORT_RELAY_MAX_PORT_LISTENERS"] == "8192"
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

offline_entitlement_secret_scope_check() {
    directory="$1"
    docker compose \
        --env-file "$root/$directory/.env.example" \
        -f "$root/$directory/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

services = json.load(sys.stdin)["services"]
backend = services["backend"]
environment = backend["environment"]
assert environment["OFFLINE_ENTITLEMENTS_ENABLED"] == "false"
assert environment["OFFLINE_ENTITLEMENT_GRACE_SECONDS"] == "604800"
assert environment["OFFLINE_ENTITLEMENT_KEY_ID"] == ""
assert environment["OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE"] == ""
assert environment["RELAY_EDGES"] == ""
assert environment["RESOURCE_REUSE_QUARANTINE_SECONDS"] == "180"
assert environment["RELAY_RENEWAL_GRACE_SECONDS"] == "604800"
for name, service in services.items():
    secret_names = {
        item if isinstance(item, str) else item.get("source")
        for item in service.get("secrets", [])
    }
    if name == "backend":
        assert "offline-entitlement-private-key" in secret_names
    else:
        assert "offline-entitlement-private-key" not in secret_names
if "relay" in services:
    relay_environment = services["relay"]["environment"]
    assert relay_environment["OFFLINE_ENTITLEMENTS_ENABLED"] == "false"
    assert relay_environment["OFFLINE_ENTITLEMENT_PUBLIC_KEYS"] == ""
    assert relay_environment["OFFLINE_ENTITLEMENT_MAX_GRACE_SECONDS"] == "604800"
    assert "OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE" not in relay_environment
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
assert environment["SMTP_USERNAME"] == ""
assert environment["SMTP_PASSWORD_FILE"] == ""
secret_names = {
    item if isinstance(item, str) else item.get("source")
    for item in migrate.get("secrets", [])
}
assert "credential-encryption-key" in secret_names
assert "relay-heartbeat-keys" in secret_names
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
    control_overlay="${3:-compose.wireguard.yaml}"
    docker compose \
        --env-file "$root/$control_directory/.env.example" \
        -f "$root/$control_directory/compose.yaml" \
        -f "$root/$control_directory/$control_overlay" \
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
capabilities = set(relay["cap_add"])
assert {"DAC_OVERRIDE", "NET_ADMIN"} <= capabilities
assert capabilities <= {"DAC_OVERRIDE", "NET_ADMIN", "NET_BIND_SERVICE"}
assert relay["user"] == "0:0"
assert relay["read_only"] is True
relay_state = next(item for item in relay["volumes"] if item["target"] == "/var/lib/blindport")
assert relay_state["source"].endswith("relay-wireguard-state")
assert relay_state["volume"]["nocopy"] is True
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
        "$root/deploy/production/Caddyfile" \
        "$root/deploy/production/Caddyfile.internal" \
        "$root/deploy/split/control/Caddyfile" \
        "$root/deploy/production/haproxy.cfg" <<'PY'
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

relay_host_sysctl_check() {
    python3 - \
        "$root/deploy/sysctl-blindport-relay.conf" \
        "$root/deploy/sysctl-blindport-routed-relay.conf" <<'PY'
from pathlib import Path
import sys

def settings(path: str) -> list[str]:
    return [
        line.strip()
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

assert settings(sys.argv[1]) == ["net.ipv4.ip_unprivileged_port_start=80"]
assert settings(sys.argv[2]) == ["net.ipv4.ip_forward=1"]
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
    config="${2:-haproxy.cfg}"
    docker run --rm \
        --env-file "$root/$directory/.env.example" \
        -v "$root/$directory/$config:/usr/local/etc/haproxy/haproxy.cfg:ro" \
        haproxy:3.2.1-alpine@sha256:ac79fe145f2bb6626ff26b584a2d0a34e791906c01015f2ae037aa3137b683d9 \
        haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg
}

dual_stack_relay_policy_check() {
    docker compose \
        --env-file "$root/deploy/production/.env.example" \
        -f "$root/deploy/production/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

services = json.load(sys.stdin)["services"]
relay = services["relay"]["environment"]
proxy = services["sni-mux"]["environment"]
assert relay["BLINDPORT_RELAY_SHARED_IPS"] == "203.0.113.10,2001:db8:1::10"
assert proxy["PUBLIC_IPV6"] == "2001:db8:1::10"
'

    docker compose \
        --env-file "$root/deploy/split/relay/.env.example" \
        -f "$root/deploy/split/relay/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

services = json.load(sys.stdin)["services"]
relay = services["relay"]
environment = relay["environment"]
assert environment["BLINDPORT_RELAY_SHARED_IPS"] == "203.0.113.30,2001:db8:2::30"
assert environment["BLINDPORT_RELAY_SNI"] == "203.0.113.30:443,[2001:db8:2::30]:443"
assert environment["BLINDPORT_RELAY_HTTP_CHALLENGE"] == "203.0.113.30:80,[2001:db8:2::30]:80"
assert relay["command"][-1] == ""
health_proxy = services["health-proxy"]
assert health_proxy["network_mode"] == "host"
assert health_proxy["read_only"] is True
assert health_proxy["environment"]["RELAY_PUBLIC_IPV6"] == "2001:db8:2::30"
'

    python3 - \
        "$root/deploy/production/haproxy.cfg" \
        "$root/deploy/split/relay/health-proxy.cfg" <<'PY'
from pathlib import Path
import sys

production, split = (Path(path).read_text(encoding="utf-8") for path in sys.argv[1:])
assert 'bind "[${PUBLIC_IPV6}]:443"' in production
assert 'bind "[${PUBLIC_IPV6}]:80"' in production
assert 'bind "[${PUBLIC_IPV6}]:9080"' in production
assert 'bind "[${RELAY_PUBLIC_IPV6}]:9080"' in split
for config in (production, split):
    assert "http-request deny unless { method GET } { path /readyz }" in config
    assert "server relay 127.0.0.1:9090 check" in config
PY
}

dns_policy_check() {
    docker compose \
        --profile tools \
        --env-file "$root/deploy/dns/.env.example" \
        -f "$root/deploy/dns/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

config = json.load(sys.stdin)
services = config["services"]
authoritative = services["authoritative"]
initializer = services["init"]
assert authoritative["network_mode"] == "host"
assert authoritative["read_only"] is True
assert authoritative["cap_add"] == ["NET_BIND_SERVICE"]
assert authoritative["cap_drop"] == ["ALL"]
assert authoritative["healthcheck"]["test"][-1] == "rping"
assert initializer["profiles"] == ["tools"]
assert set(config["secrets"]) == {"dns_dnssec_private_key", "dns_transfer_tsig"}
assert {item["source"] for item in initializer["secrets"]} == {
    "dns_dnssec_private_key",
    "dns_transfer_tsig",
}
'

    python3 - \
        "$root/deploy/dns/pdns-common.conf" \
        "$root/deploy/dns/pdns-primary.conf" \
        "$root/deploy/dns/pdns-secondary.conf" \
        "$root/deploy/dns/init.sh" \
        "$root/deploy/dns/blindport.com.zone" <<'PY'
from pathlib import Path
import sys

common, primary, secondary, initializer, zone = (
    Path(path).read_text(encoding="utf-8") for path in sys.argv[1:]
)
assert "api=no" in common and "webserver=no" in common
assert "query-logging=no" in common and "log-dns-queries=no" in common
assert "enable-lua-records=yes" in common
assert "cache-ttl=0" in common and "query-cache-ttl=0" in common
assert "allow-axfr-ips=\n" in primary
assert "secondary=yes" in secondary
assert "pdnsutil tsigkey activate" in initializer
assert "pdnsutil zone import-key" in initializer
assert "pdnsutil zone rectify" in initializer
assert zone.count(" IN LUA A ") == 2
assert "http://78.17.212.128:9080/readyz" in zone
assert "http://89.125.35.70:9080/readyz" in zone
assert " IN AAAA " not in zone
PY
}

production_http_routing_check() {
    python3 - "$root/deploy/production/haproxy.cfg" <<'PY'
from pathlib import Path
import sys

config = Path(sys.argv[1]).read_text(encoding="utf-8")
assert 'acl api_host hdr(host),field(1,:) -i "${API_DOMAIN}"' in config
assert "use_backend api_http if api_host" in config
assert "default_backend relay_http" in config
assert "backend relay_http" in config
assert "option httpchk GET /readyz" in config
assert "http-check expect status 200" in config
assert "server relay 127.0.0.1:4443 send-proxy-v2 check port 9090" in config
assert "acl acme_path" not in config
assert "relay_acme" not in config
PY
}

production_relay_internal_policy_check() {
    python3 - \
        "$root/deploy/production/Caddyfile" \
        "$root/deploy/production/compose.yaml" \
        "$root/deploy/production/.env.example" <<'PY'
from pathlib import Path
import sys

caddy, compose, environment = (
    Path(path).read_text(encoding="utf-8") for path in sys.argv[1:]
)
assert "path /internal/v1/* /internal/v2/* /internal/v3/*" in caddy
assert "remote_ip {$RELAY_PRIVATE_CIDRS}" in caddy
assert caddy.index("handle @relay_internal") < caddy.index("handle @internal")
assert "RELAY_PRIVATE_CIDRS: ${RELAY_PRIVATE_CIDRS}" in compose
assert "BLINDPORT_RELAY_SNI: 127.0.0.1:4443" in compose
assert "BLINDPORT_RELAY_SNI_PROXY_PROTOCOL: v2" in compose
assert "BLINDPORT_RELAY_MAX_INGRESS_PER_SOURCE: ${RELAY_MAX_INGRESS_PER_SOURCE:-128}" in compose
assert "RELAY_PRIVATE_CIDRS=198.51.100.30/32" in environment
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

caddy_admin_routing_policy_check() {
    python3 - "$@" <<'PY'
from pathlib import Path
import sys

for path in sys.argv[1:]:
    config = Path(path).read_text(encoding="utf-8")
    public = config.split("http://{$ONION_HOST}", 1)[0]
    assert "@admin_browser path /admin*" in public
    assert "@admin_api_allowed {\n\t\tpath /api/v1/admin/* /api/v2/admin/*\n\t\tremote_ip {$ADMIN_PRIVATE_CIDRS}" in public
    assert "@admin_api path /api/v1/admin/* /api/v2/admin/*" in public
    assert public.index("handle @admin_browser") < public.index("handle @admin_api_allowed")
    assert public.index("handle @admin_api_allowed") < public.index("handle @admin_api {")
    assert public.index("handle @admin_api {") < public.index("handle {")
    if "http://{$ONION_HOST}" in config:
        onion = config.split("http://{$ONION_HOST}", 1)[1]
        assert "@private path /internal/* /admin* /api/v1/admin/* /api/v2/admin/*" in onion
        assert "handle @private {\n\t\trespond 404" in onion
PY
}

production_proxy_protocol_check() {
    config="$1"
    docker run --rm \
        --env-file "$root/deploy/production/.env.example" \
        -v "$root/deploy/production/$config:/etc/caddy/Caddyfile:ro" \
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
assert all(set(service["networks"]) == {"blindport"} for service in services.values())
assert "user" not in services["blindportd"]
assert services["blindportd"]["container_name"] == "blindportd"
assert services["blindportd"]["networks"]["blindport"]["ipv4_address"] == "172.30.0.2"
assert services["blindportd"]["depends_on"]["site"]["condition"] == "service_started"
assert services["blindportd"]["command"] == [
    "--docker",
    "--config=/etc/blindport/config.json",
]
assert services["blindportd"]["read_only"] is True
assert services["blindportd"]["cap_drop"] == ["ALL"]
assert services["blindportd"]["cap_add"] == ["NET_ADMIN"]
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
assert state["type"] == "bind"
assert state["source"] == "/opt/blindport/state"
assert not state.get("read_only", False)
assert services["blindportd"]["environment"]["BLINDPORT_ACME_EMAIL"] == ""
assert "BLINDPORT_TOKEN" not in services["blindportd"]["environment"]
assert "BLINDPORT_TOKEN_FILE" not in services["blindportd"]["environment"]

account_config = next(
    volume
    for volume in services["blindportd"]["volumes"]
    if volume["target"] == "/etc/blindport/config.json"
)
assert account_config["read_only"] is True
assert account_config["source"] == "/opt/blindport/config/config.json"

token = next(
    volume
    for volume in services["blindportd"]["volumes"]
    if volume["target"] == "/run/secrets/blindport-public"
)
assert token["read_only"] is True
assert token["source"] == "/opt/blindport/secrets/public-token"
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

docker_traefik_example_check() {
    docker compose \
        --env-file "$root/examples/docker-traefik/.env.example" \
        -f "$root/examples/docker-traefik/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

config = json.load(sys.stdin)
services = config["services"]
assert set(services) == {"blindportd", "site", "traefik"}
assert all(not service.get("ports") for service in services.values())
assert services["blindportd"]["networks"]["edge"]["ipv4_address"] == "172.30.0.2"
assert services["traefik"]["networks"]["edge"]["ipv4_address"] == "172.30.0.3"

labels = services["traefik"]["labels"]
assert labels["tech.blindport.mapping.edge.upstream"] == "traefik:443"
assert labels["tech.blindport.mapping.edge.http_challenge_upstream"] == "traefik:80"
assert labels["tech.blindport.mapping.edge.tls_mode"] == "passthrough"
assert labels["tech.blindport.mapping.edge.proxy_protocol"] == "v2"
assert "tech.blindport.mapping.edge.acme_terms_accepted" not in labels

commands = set(services["traefik"]["command"])
assert "--entrypoints.web.proxyprotocol.trustedips=172.30.0.2/32" in commands
assert "--entrypoints.websecure.proxyprotocol.trustedips=172.30.0.2/32" in commands
assert not any("proxyprotocol.insecure" in command for command in commands)
assert any("dnschallenge.provider=cloudflare" in command for command in commands)
assert any("httpchallenge.entrypoint=web" in command for command in commands)

site_labels = services["site"]["labels"]
assert site_labels["traefik.http.routers.site.tls.certresolver"] == "letsencrypt-dns"
assert site_labels["traefik.http.routers.site.tls.domains[0].main"] == "example.com"
assert site_labels["traefik.http.routers.site.tls.domains[0].sans"] == "*.example.com"

for name in ("blindportd", "traefik"):
    socket = next(
        volume
        for volume in services[name]["volumes"]
        if volume["target"] == "/var/run/docker.sock"
    )
    assert socket["read_only"] is True

assert services["blindportd"]["read_only"] is True
assert services["blindportd"]["cap_drop"] == ["ALL"]
assert services["blindportd"]["cap_add"] == ["NET_ADMIN"]
assert services["blindportd"]["security_opt"] == ["no-new-privileges:true"]

agent_volumes = {volume["target"]: volume for volume in services["blindportd"]["volumes"]}
assert agent_volumes["/etc/blindport/config.json"]["source"] == "/opt/blindport/config/config.json"
assert agent_volumes["/etc/blindport/config.json"]["read_only"] is True
assert agent_volumes["/run/secrets/blindport-public"]["source"] == "/opt/blindport/secrets/public-token"
assert agent_volumes["/run/secrets/blindport-public"]["read_only"] is True
assert agent_volumes["/var/lib/blindport"]["source"] == "/opt/blindport/state"
assert not agent_volumes["/var/lib/blindport"].get("read_only", False)

traefik_volumes = {volume["target"]: volume for volume in services["traefik"]["volumes"]}
assert traefik_volumes["/letsencrypt"]["source"] == "/opt/blindport/traefik-acme"
assert not traefik_volumes["/letsencrypt"].get("read_only", False)
assert traefik_volumes["/run/secrets/cloudflare-dns-api-token"]["source"] == "/opt/blindport/secrets/cloudflare-dns-api-token"
assert traefik_volumes["/run/secrets/cloudflare-dns-api-token"]["read_only"] is True
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
assert services["agent"]["cap_add"] == ["NET_ADMIN"]
assert services["postgres"]["image"].startswith("postgres:17.5-alpine@sha256:")
assert services["api-lb"]["image"].startswith("haproxy:3.2.1-alpine@sha256:")

haproxy = Path(sys.argv[1]).read_text(encoding="utf-8")
assert "balance roundrobin" in haproxy
assert "option httpchk GET /api/v1/health/ready" in haproxy
assert "resolvers docker" in haproxy
assert "resolvers docker resolve-prefer ipv4" in haproxy
assert "cookie" not in haproxy.lower()
assert "server backend-a backend-a:8000" in haproxy
assert "server backend-b backend-b:8000" in haproxy
' "$root/deploy/ha-lab/haproxy.cfg"
}

provider_edge_policy_check() {
    control_directory="$1"
    docker compose \
        --env-file "$root/$control_directory/.env.example" \
        -f "$root/$control_directory/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

services = json.load(sys.stdin)["services"]
environment = services["backend"]["environment"]
for name in (
    "FRAMED_IP_ENDPOINTS",
    "PORT_HA_EDGES",
    "PORT_HOSTNAME_SUFFIX",
    "RELAY_CONTROL_URLS",
    "RELAY_EDGES",
    "RELAY_HEARTBEAT_STALE_SECONDS",
    "RELAY_PUBLIC_IPS",
    "DNS_SUPERVISION_ENABLED",
    "DNS_SUPERVISION_TARGETS",
):
    assert name in environment
assert environment["RELAY_HEARTBEAT_KEYS_FILE"] == ""
secret_names = {
    item if isinstance(item, str) else item.get("source")
    for item in services["backend"].get("secrets", [])
}
assert "relay-heartbeat-keys" in secret_names
'

    docker compose \
        --env-file "$root/deploy/split/relay/.env.example" \
        -f "$root/deploy/split/relay/compose.yaml" \
        config --format json \
        | python3 -c '
import json
import sys

relay = json.load(sys.stdin)["services"]["relay"]
assert relay["environment"]["BLINDPORT_RELAY_IPS"] == ""
assert relay["environment"]["BLINDPORT_RELAY_PORTS"] == "443"
assert relay["environment"]["BLINDPORT_RELAY_CERTIFICATE_CACHE_DIR"] == "/var/lib/blindport"
assert relay["environment"]["BLINDPORT_RELAY_HEARTBEAT_INTERVAL"] == "30s"
assert relay["environment"]["BLINDPORT_RELAY_HEARTBEAT_TOKEN_FILE"] == ""
assert any(volume["target"] == "/var/lib/blindport" for volume in relay["volumes"])
assert relay["environment"]["OFFLINE_ENTITLEMENTS_ENABLED"] == "false"
assert relay["environment"]["OFFLINE_ENTITLEMENT_PUBLIC_KEYS"] == ""
assert relay["environment"]["OFFLINE_ENTITLEMENT_MAX_GRACE_SECONDS"] == "604800"
assert relay["environment"]["RELAY_EDGE_ID"] == ""
assert "OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE" not in relay["environment"]
assert "offline-entitlement-private-key" not in {
    item if isinstance(item, str) else item.get("source")
    for item in relay.get("secrets", [])
}
relay_secrets = {
    item if isinstance(item, str) else item.get("source")
    for item in relay.get("secrets", [])
}
assert "relay-heartbeat-token" in relay_secrets
assert "relay-heartbeat-keys" not in relay_secrets
assert relay["mem_limit"] == "402653184"
assert relay["cpus"] == 1.0
'
}

compose_check deploy/production
compose_check deploy/split/control
compose_check deploy/split/relay
compose_check deploy/dns
compose_check deploy/ha-lab
compose_check examples/docker
production_compose_guard_check
backend_healthcheck_policy_check deploy/production
backend_healthcheck_policy_check deploy/split/control
port_capacity_policy_check deploy/production deploy/production
port_capacity_policy_check deploy/split/control deploy/split/relay
smtp_secret_scope_check deploy/production
smtp_secret_scope_check deploy/split/control
offline_entitlement_secret_scope_check deploy/production
offline_entitlement_secret_scope_check deploy/split/control
migration_credential_scope_check deploy/production
migration_credential_scope_check deploy/split/control
logging_policy_check deploy/production
logging_policy_check deploy/split/control
logging_policy_check deploy/split/relay
logging_policy_check deploy/dns
provider_edge_policy_check deploy/production
provider_edge_policy_check deploy/split/control
wireguard_production_policy_check deploy/production deploy/production
wireguard_production_policy_check deploy/production deploy/split/relay compose.wireguard-control.yaml
wireguard_production_policy_check deploy/split/control deploy/split/relay
address_log_policy_check
relay_host_sysctl_check
caddy_check deploy/production
caddy_check deploy/production Caddyfile.internal
caddy_check deploy/split/control
caddy_log_policy_check deploy/production
caddy_log_policy_check deploy/production Caddyfile.internal
caddy_log_policy_check deploy/split/control
haproxy_check deploy/production
haproxy_check deploy/ha-lab
haproxy_check deploy/split/relay health-proxy.cfg
dual_stack_relay_policy_check
dns_policy_check
production_http_routing_check
production_relay_internal_policy_check
caddy_runtime_policy_check
caddy_admin_policy_check deploy/production
caddy_admin_policy_check deploy/production Caddyfile.internal
caddy_admin_policy_check deploy/split/control
caddy_admin_routing_policy_check \
    "$root/deploy/production/Caddyfile" \
    "$root/deploy/production/Caddyfile.internal" \
    "$root/deploy/split/control/Caddyfile"
production_proxy_protocol_check Caddyfile
production_proxy_protocol_check Caddyfile.internal
docker_example_check
docker_traefik_example_check
ha_lab_policy_check

echo "deployment configuration validation passed"
