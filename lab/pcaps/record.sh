#!/bin/sh
# Record one packet capture per lab scenario, for the sensors to read offline.
#
# Suricata and Zeek are meant to watch the lab bridge live, which needs a Linux host
# (on Docker Desktop the bridge lives inside a VM the host cannot sniff). Both read
# capture files just as well, so this records what they would have seen. Each
# capture runs tcpdump inside the victim's network namespace, which sees every
# packet to and from that victim - including the benign-traffic container's
# requests, so no capture is attack-only.
#
#   sh lab/pcaps/record.sh              # from the repository root
#   OUT=D:/netsentinel-data/pcaps sh lab/pcaps/record.sh
#
# On Git Bash, set MSYS_NO_PATHCONV=1 so container paths are not rewritten.
set -eu

# pwd -W gives Git Bash a Windows path Docker Desktop can mount; elsewhere it fails.
ROOT=$(cd "$(dirname "$0")/../.." && { pwd -W 2>/dev/null || pwd; })
OUT="${OUT:-$ROOT/lab/pcaps/out}"
BENIGN_SECONDS="${BENIGN_SECONDS:-120}"
LAB="$ROOT/lab/scenarios"
NET=netsentinel_lab
compose() { docker compose -f "$ROOT/infra/docker-compose.yml" --profile lab "$@"; }

mkdir -p "$OUT"
# Pull the tool images before any capture starts: a first pull inside a capture
# window once stalled the run with tcpdump left running.
for image in nicolaka/netshoot instrumentisto/nmap:7.95 vanhauser/hydra curlimages/curl:8.10.1; do
    docker pull -q "$image" >/dev/null
done
compose up -d victim-web victim-ssh benign-traffic
# openssh-server takes a few seconds to generate host keys and listen.
sleep 15

start_capture() {
    # $1: capture name, $2: compose service whose traffic to record.
    docker run -d --rm --name "ns-capture-$1" \
        --network "container:$(compose ps -q "$2")" \
        -v "$OUT:/out" nicolaka/netshoot \
        tcpdump -i eth0 -U -w "/out/$1.pcap" >/dev/null
    sleep 3
}

stop_capture() {
    # Let the last packets of each connection land before cutting the file.
    sleep 5
    docker stop "ns-capture-$1" >/dev/null
}

start_capture benign victim-web
echo "[record] benign: ${BENIGN_SECONDS}s of benign-traffic requests only"
sleep "$BENIGN_SECONDS"
stop_capture benign

start_capture scan victim-web
docker run --rm --network "$NET" --cap-add NET_RAW -v "$LAB:/scenarios" \
    --entrypoint sh instrumentisto/nmap:7.95 /scenarios/scan.sh
stop_capture scan

start_capture brute_force victim-ssh
docker run --rm --network "$NET" -v "$LAB:/scenarios" \
    --entrypoint sh vanhauser/hydra /scenarios/brute_force.sh
stop_capture brute_force

start_capture web_attack victim-web
docker run --rm --network "$NET" -v "$LAB:/scenarios" \
    --entrypoint sh curlimages/curl:8.10.1 /scenarios/web_attack.sh
stop_capture web_attack

compose stop victim-web victim-ssh benign-traffic
ls -l "$OUT"
