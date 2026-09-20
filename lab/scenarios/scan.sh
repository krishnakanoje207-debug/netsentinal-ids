#!/bin/sh
# Scenario 1 - reconnaissance (MITRE T1046, service/port discovery).
#
# A port and service scan is the least ambiguous thing an IDS should catch: one
# source touching many ports on one host in a short window. It is also the gentlest
# to run, which is why it is first - if this does not light up ClickHouse, nothing
# downstream is worth debugging yet.
#
#   docker compose --profile lab run --rm attacker sh /scenarios/scan.sh
#
# (mount this directory into the attacker container, or exec into it - see
# lab/README.md.)
set -eu

DIR=$(dirname "$0")
. "${DIR}/_guard.sh"

TARGET="${1:-$VICTIM_WEB}"
require_lab_target "$TARGET"

echo "[scan] SYN scan of the top 1000 ports on ${TARGET}"
# -sS SYN scan, -sV service/version probes: the version probes are what turn a bare
# port list into the fan-out of short connections the flow model is trained on.
nmap -sS -sV -T4 --top-ports 1000 "$TARGET"

echo "[scan] done"
