#!/bin/sh
set -eu

directory="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
env_file="${BLINDPORT_ENV_FILE:-$directory/.env}"
docker_bin="${BLINDPORT_DOCKER_BIN:-docker}"
overlay_file=""

usage() {
    cat <<'EOF'
Usage: ./compose.sh [--wireguard | --wireguard-control] COMPOSE_ARGUMENT...

Use --wireguard for the single-host routed topology and --wireguard-control
when production controls a separate routed Relay host.
EOF
}

case "${1:-}" in
    --wireguard)
        overlay_file="$directory/compose.wireguard.yaml"
        shift
        ;;
    --wireguard-control)
        overlay_file="$directory/compose.wireguard-control.yaml"
        shift
        ;;
    -h | --help)
        usage
        exit 0
        ;;
esac

if [ "$#" -eq 0 ]; then
    usage >&2
    exit 64
fi

if [ ! -r "$env_file" ]; then
    printf 'error: environment file is not readable: %s\n' "$env_file" >&2
    exit 66
fi

read_env_value() {
    name="$1"
    result=""
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            "$name="*) result="${line#"$name="}" ;;
        esac
    done < "$env_file"
    printf '%s' "$result"
}

wireguard_public_ips="$(read_env_value WIREGUARD_PUBLIC_IPS)"
case "$wireguard_public_ips" in
    "" | "''" | '""') wireguard_inventory_configured=false ;;
    *) wireguard_inventory_configured=true ;;
esac

if [ "$wireguard_inventory_configured" = true ] && [ -z "$overlay_file" ]; then
    printf '%s\n' \
        'error: WIREGUARD_PUBLIC_IPS is configured; select --wireguard or --wireguard-control' \
        >&2
    exit 64
fi

if [ -n "$overlay_file" ]; then
    exec "$docker_bin" compose \
        --env-file "$env_file" \
        -f "$directory/compose.yaml" \
        -f "$overlay_file" \
        "$@"
fi

exec "$docker_bin" compose \
    --env-file "$env_file" \
    -f "$directory/compose.yaml" \
    "$@"
