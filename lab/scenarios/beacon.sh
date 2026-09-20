#!/bin/sh
# Scenario 3 - C2 beacon cadence (MITRE T1071, command and control).
#
# This does NOT stand up a command-and-control channel. It reproduces the one thing
# a beacon looks like on the wire that a flow model can learn: small, regular,
# long-lived callbacks to the same destination, with a little jitter. There is no
# implant, no listener, no commands - just curl to a lab sink on an interval.
#
# A real Sliver/Mythic exercise clones its own server on the VM; that is out of
# scope for a script whose job is to make the detector fire. What the detector reads
# is the rhythm, and the rhythm is all this generates.
#
#   docker compose --profile lab run --rm \
#     -v "$PWD/lab/scenarios:/scenarios" \
#     --network netsentinel_lab curlimages/curl:8.10.1 sh /scenarios/beacon.sh
set -eu

DIR=$(dirname "$0")
. "${DIR}/_guard.sh"

TARGET="${1:-$VICTIM_WEB}"
require_lab_target "$TARGET"

INTERVAL="${BEACON_INTERVAL:-30}"   # seconds between callbacks
JITTER="${BEACON_JITTER:-5}"        # +/- this many seconds, as a real beacon has
COUNT="${BEACON_COUNT:-40}"         # bounded: a demo, not a daemon

echo "[beacon] ${COUNT} callbacks to ${TARGET} every ~${INTERVAL}s"
i=0
while [ "$i" -lt "$COUNT" ]; do
    i=$((i + 1))
    # A tiny GET carrying an opaque id in a header, which is what a check-in is:
    # regularity and a small constant size, not the content.
    curl -s -o /dev/null \
        -H "X-Session-Id: $(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
        "http://${TARGET}/" || true

    sleep_for=$((INTERVAL + (RANDOM % (2 * JITTER + 1)) - JITTER))
    [ "$sleep_for" -lt 1 ] && sleep_for=1
    echo "[beacon] callback ${i}/${COUNT}, next in ${sleep_for}s"
    sleep "$sleep_for"
done

echo "[beacon] done"
