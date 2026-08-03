#!/bin/sh
set -eu

if [ -n "${BLINDPORT_RELAY_SECRET_FILE:-}" ]; then
    [ -f "$BLINDPORT_RELAY_SECRET_FILE" ] || { echo "relay secret is not a regular file" >&2; exit 1; }
    BLINDPORT_RELAY_SECRET="$(cat "$BLINDPORT_RELAY_SECRET_FILE")"
    [ -n "$BLINDPORT_RELAY_SECRET" ] || { echo "relay secret is empty" >&2; exit 1; }
    export BLINDPORT_RELAY_SECRET
    unset BLINDPORT_RELAY_SECRET_FILE
fi

exec /usr/local/bin/blindport-relay "$@"
