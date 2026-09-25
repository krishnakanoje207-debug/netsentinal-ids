#!/bin/sh
# Replay a capture onto the lab bridge, so the live sensors see it as traffic (F21).
#
#   sudo sh lab/replay/tcpreplay.sh capture.pcap [extra tcpreplay options]
#   sudo sh lab/replay/tcpreplay.sh lab/pcaps/out/scan.pcap --mbps=10 --loop=3
#
# Runs on the VM, where the bridge exists (docker compose --profile lab up -d) and
# Suricata and Zeek sniff it. Needs tcpreplay on the host: sudo apt install tcpreplay.
#
# Guarded like the attack scenarios (../scenarios/_guard.sh): the interface is not a
# parameter. A replayed capture carries whatever addresses it was recorded with, and
# injected onto a real interface those packets would leave the box, so the only
# interface this writes to is the lab bridge - and if that is missing, it stops
# rather than looking for another.
set -eu

LAB_BRIDGE="netsentinel-lab"

require_lab_bridge() {
    if ! ip link show "$LAB_BRIDGE" >/dev/null 2>&1; then
        echo "refusing to replay: ${LAB_BRIDGE} does not exist; bring the lab up" \
             "first with docker compose --profile lab up -d" >&2
        exit 2
    fi
}

if [ $# -lt 1 ] || [ ! -f "$1" ]; then
    echo "usage: $0 capture.pcap [tcpreplay options]" >&2
    exit 2
fi
PCAP="$1"
shift

require_lab_bridge
command -v tcpreplay >/dev/null || { echo "tcpreplay not found: sudo apt install tcpreplay" >&2; exit 2; }

# At the recorded pace by default, so flow durations and inter-arrival times - the
# features the models read - match the capture. Pass --topspeed or --mbps to change it.
exec tcpreplay --intf1="$LAB_BRIDGE" "$@" "$PCAP"
