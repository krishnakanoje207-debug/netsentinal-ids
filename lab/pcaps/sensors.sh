#!/bin/sh
# Run Suricata and Zeek over the captures record.sh wrote, offline.
#
# Live sensing needs a Linux host (see record.sh); reading a capture exercises the
# same rules and scripts on the same packets. Suricata runs the ET Open ruleset,
# fetched once by suricata-update into $DATA/suricata. Zeek loads FoxIO's JA4+
# package, installed once by zkg into $DATA/zeek.
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

mkdir -p "$DATA/suricata" "$DATA/zeek/zkg" "$DATA/zeek/packages"
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
docker run --rm -v "$DATA/suricata:/var/lib/suricata" jasonish/suricata:7.0 \
    suricata-update $OFFLINE --no-test \
    --disable-conf /var/lib/suricata/disable.conf --modify-conf /var/lib/suricata/modify.conf

# The attacker sits on the lab subnet too, so EXTERNAL_NET is "any": left at its
# default of !$HOME_NET, every rule written $EXTERNAL_NET -> $HOME_NET would ignore
# the lab's own attacks. victim-ssh listens on 2222, hence SSH_PORTS.
docker run --rm -m 1500m -v "$OUT:/pcaps:ro" -v "$LOGS/suricata:/logs" \
    -v "$DATA/suricata:/var/lib/suricata" --entrypoint sh jasonish/suricata:7.0 -c "
    for name in $CAPTURES; do
        suricata -r /pcaps/\$name.pcap -k none -l /logs/\$name \
            --set 'vars.address-groups.HOME_NET=[172.30.0.0/24]' \
            --set vars.address-groups.EXTERNAL_NET=any \
            --set 'vars.port-groups.SSH_PORTS=[22,2222]'
    done"

# JA4+ v0.18.8 is the last release that is plain Zeek script; later ones are a
# compiled plugin that needs Zeek 7 and a toolchain the zeek/zeek:6.0 image lacks.
docker run --rm -m 1g -v "$OUT:/pcaps:ro" -v "$LOGS/zeek:/logs" \
    -v "$DATA/zeek/zkg:/usr/local/zeek/var/lib/zkg" \
    -v "$DATA/zeek/packages:/usr/local/zeek/share/zeek/site/packages" \
    zeek/zeek:6.0 sh -c "
    [ -d /usr/local/zeek/share/zeek/site/packages/ja4 ] ||
        zkg install --force --version v0.18.8 foxio/ja4
    for name in $CAPTURES; do
        (cd /logs/\$name && zeek -C -r /pcaps/\$name.pcap local packages LogAscii::use_json=T)
    done"

for name in $CAPTURES; do
    echo "[sensors] $name: $(grep -c '\"event_type\":\"alert\"' "$LOGS/suricata/$name/eve.json") Suricata alerts"
done
