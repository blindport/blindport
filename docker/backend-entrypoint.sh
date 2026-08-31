#!/bin/sh
set -eu

load_secret() {
    name="$1"
    eval "path=\${${name}_FILE:-}"
    [ -z "$path" ] && return
    [ -f "$path" ] || { echo "$name secret is not a regular file" >&2; exit 1; }
    value="$(cat "$path")"
    [ -n "$value" ] || { echo "$name secret is empty" >&2; exit 1; }
    export "$name=$value"
    unset "${name}_FILE"
}

load_secret DATABASE_URL
load_secret SECRET_KEY
load_secret TOKEN_HASH_KEY
load_secret RELAY_SECRET
load_secret RELAY_HEARTBEAT_KEYS
load_secret ADMIN_TOKEN
load_secret LND_INVOICE_HMAC_KEY
load_secret CREDENTIAL_ENCRYPTION_KEY
load_secret CLINK_NOSTR_PRIVATE_KEY
load_secret SMTP_PASSWORD
exec "$@"
