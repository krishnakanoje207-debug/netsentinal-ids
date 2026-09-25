#!/bin/sh
# Run Suricata and Zeek over the captures record.sh wrote, offline.
#
# Live sensing needs a Linux host (see record.sh); reading a capture exercises the
# same rules and scripts on the same packets, with the images and configuration the
# compose sensors run (infra/docker-compose.yml): Suricata 8.0.7 with
# infra/suricata/netsentinel.yaml, and Zeek built from infra/zeek with the JA4+
# scripts and its local.zeek. Suricata runs the ET Open ruleset, fetched once by
# suricata-update into $DATA/suricata.
#
#   OUT=D:/netsentinel-data/pcaps DATA=D:/netsentinel-data sh lab/pcaps/sensors.sh
#
# Logs land in $DATA/sensor-logs/{suricata,zeek}/<capture>/. On Git Bash, set
# MSYS_NO_PATHCONV=1 so container paths are not rewritten.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && { pwd -W 2>/dev/null || pwd; })
OUT="${OUT:-$ROOT/lab/pcaps/out}"
DATA="${DATA:-$OUT}"
LOGS="$DATA/sensor-logs"
CAPTURES="benign scan brute_force web_attack"

mkdir -p "$DATA/suricata"
for name in $CAPTURES; do mkdir -p "$LOGS/suricata/$name" "$LOGS/zeek/$name"; done

# Docker's veth leaves checksums to an offload that never happens, so every captured
# packet carries a wrong one. -k none stops Suricata acting on that; this stops the
# decoder rules alerting on it.
echo 're:invalid checksum' > "$DATA/suricata/disable.conf"
# Two ET brute-force/scan rules hard-code port 22; victim-ssh listens on 2222.
cat > "$DATA/suricata/modify.conf" <<'EOF'
2006546 "HOME_NET 22 " "HOME_NET $SSH_PORTS "
2001219 "HOME_NET 22 " "HOME_NET $SSH_PORTS "
EOF

# Rules are fetched rather than committed: ET Open changes daily and carries its own
# licence. The download is cached, so only the first run needs the network.
OFFLINE=""
[ -s "$DATA/suricata/rules/suricata.rules" ] && OFFLINE="--offline"
docker run --rm -v "$DATA/suricata:/var/lib/suricata" jasonish/suricata:8.0.7 \
    suricata-update $OFFLINE --no-test \
    --disable-conf /var/lib/suricata/disable.conf --modify-conf /var/lib/suricata/modify.conf

# The live sensor's overrides, from infra/suricata/netsentinel.yaml: HOME_NET is the
# lab subnet; EXTERNAL_NET is "any" because the attacker sits on the lab subnet too,
# and left at !$HOME_NET every $EXTERNAL_NET -> $HOME_NET rule would ignore the lab's
# own attacks; SSH_PORTS includes victim-ssh's 2222; JA4 for every client hello.
docker run --rm -m 1500m -v "$OUT:/pcaps:ro" -v "$LOGS/suricata:/logs" \
    -v "$DATA/suricata:/var/lib/suricata" \
    -v "$ROOT/infra/suricata/netsentinel.yaml:/etc/suricata/netsentinel.yaml:ro" \
    --entrypoint sh jasonish/suricata:8.0.7 -c "
    for name in $CAPTURES; do
        suricata -r /pcaps/\$name.pcap -k none -l /logs/\$name \
            --include /etc/suricata/netsentinel.yaml
    done"

# The compose sensor's image, built once from infra/zeek with the JA4+ scripts baked
# in, so only the first run needs the network. Its local.zeek writes JSON logs and
# loads the package.
ZEEK_IMAGE=netsentinel/zeek:8.0.10-ja4
docker image inspect "$ZEEK_IMAGE" >/dev/null 2>&1 ||
    docker build -t "$ZEEK_IMAGE" "$ROOT/infra/zeek"
docker run --rm -m 1g -v "$OUT:/pcaps:ro" -v "$LOGS/zeek:/logs" \
    -v "$ROOT/infra/zeek/local.zeek:/usr/local/zeek/share/zeek/site/local.zeek:ro" \
    "$ZEEK_IMAGE" sh -c "
    for name in $CAPTURES; do
        (cd /logs/\$name && zeek -C -r /pcaps/\$name.pcap local)
    done"

for name in $CAPTURES; do
    echo "[sensors] $name: $(grep -c '\"event_type\":\"alert\"' "$LOGS/suricata/$name/eve.json") Suricata alerts"
done
