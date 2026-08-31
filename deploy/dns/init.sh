#!/bin/sh
set -eu

database=/var/lib/powerdns/pdns.sqlite3
zone=blindport.com
zone_file=/etc/powerdns/blindport.com.zone
tsig_name=blindport-transfer
tsig_file=/run/secrets/dns_transfer_tsig
dnssec_key_file=/run/secrets/dns_dnssec_private_key
initialized=false

case "${DNS_ROLE:?DNS_ROLE must be primary or secondary}" in
    primary|secondary) ;;
    *)
        printf '%s\n' 'DNS_ROLE must be primary or secondary' >&2
        exit 2
        ;;
esac

if [ ! -s "$database" ]; then
    sqlite3 "$database" < /usr/local/share/doc/pdns/schema.sqlite3.sql
    initialized=true
fi

if [ ! -s "$tsig_file" ] || [ ! -s "$dnssec_key_file" ]; then
    printf '%s\n' 'DNS TSIG and DNSSEC private key secrets must be nonempty' >&2
    exit 2
fi

if [ "$DNS_ROLE" = primary ]; then
    pdnsutil zone load "$zone" "$zone_file"
    pdnsutil zone set-kind "$zone" primary
elif [ "$initialized" = true ]; then
    pdnsutil zone load "$zone" "$zone_file"
    pdnsutil zone set-kind "$zone" secondary
    pdnsutil zone change-primary "$zone" 78.17.212.128
fi

if [ "$initialized" = true ]; then
    tsig_secret=$(tr -d '\r\n' < "$tsig_file")
    pdnsutil tsigkey import "$tsig_name" hmac-sha256 "$tsig_secret"
    pdnsutil zone import-key "$zone" "$dnssec_key_file" active ksk published
fi

pdnsutil tsigkey activate "$zone" "$tsig_name" "$DNS_ROLE"
pdnsutil zone rectify "$zone"

pdnsutil zone check "$zone"
pdnsutil zone list-keys "$zone"
