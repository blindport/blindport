#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
compose="docker compose -f $root/deploy/ha-lab/compose.yaml"

cleanup() {
    $compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

cleanup
$compose build --pull backend-a relay-a agent
$compose up -d postgres
$compose --profile tools run --rm migrate blindport-migrate upgrade
$compose up -d backend-a backend-b api-lb relay-a relay-b origin
$compose --profile tools run --rm state-init
$compose --profile tools run --rm tester setup
$compose up -d agent
$compose --profile tools run --rm tester forwarding relay-a relay-b

$compose stop backend-a
sleep 3
$compose --profile tools run --rm tester api-continuity
$compose up -d --wait backend-a

$compose stop relay-a
$compose --profile tools run --rm tester forwarding relay-b
$compose up -d --wait relay-a
$compose --profile tools run --rm tester forwarding relay-a relay-b
for _ in $(seq 1 30); do
    heartbeat_count="$($compose exec -T postgres psql -U blindport -d blindport -Atc 'select count(*) from relayheartbeat')"
    [ "$heartbeat_count" = "2" ] && break
    sleep 1
done
[ "$heartbeat_count" = "2" ] || { echo "FAIL Relay heartbeats were not persisted" >&2; exit 1; }
echo "PASS latest heartbeat persisted for both Relay edges"

$compose exec -T relay-a test -s /var/lib/blindport/certificate.json
$compose exec -T relay-b test -s /var/lib/blindport/certificate.json
$compose stop agent relay-a
$compose stop backend-a backend-b
$compose up -d --no-deps relay-a agent
[ -z "$($compose ps --status running -q backend-a backend-b)" ] || { echo "FAIL API replicas restarted during outage test" >&2; exit 1; }
$compose --profile tools run --rm tester forwarding relay-a relay-b
echo "PASS agent and Relay restarted with cached authorization during total API outage"

$compose up -d --wait backend-a backend-b api-lb
$compose exec -T postgres psql -U blindport -d blindport -c "update subscription set status = 'EXPIRED' where product in ('relay', 'port')"
$compose --profile tools run --rm tester revoked
$compose --profile tools run --rm tester unavailable relay-a relay-b
$compose exec -T postgres psql -U blindport -d blindport -c "update subscription set status = 'ACTIVE' where product in ('relay', 'port')"
$compose --profile tools run --rm tester forwarding relay-a relay-b

$compose --profile tools run --rm tester concurrency

before="$($compose exec -T postgres psql -U blindport -d blindport -Atc 'select count(*) from subscription')"
$compose stop agent relay-a relay-b api-lb backend-a backend-b
$compose --profile tools run --rm migrate blindport-migrate downgrade 0015
$compose --profile tools run --rm migrate blindport-migrate upgrade
after="$($compose exec -T postgres psql -U blindport -d blindport -Atc 'select count(*) from subscription')"
[ "$before" = "$after" ] || { echo "FAIL migration changed subscription count" >&2; exit 1; }
$compose up -d --wait backend-a backend-b api-lb
$compose --profile tools run --rm tester retained

echo "PASS schema 0015 to head round trip retained $after subscriptions"
echo "HA lab fault tests passed; disposable volumes will now be removed"
