#!/bin/sh
# Enable MISP's warninglists, except the ones that describe rented hosting.
#
#   cd infra && sh misp/warninglists.sh
#
# The intel sync asks MISP to enforce warninglists, and MISP ships them loaded but
# disabled, so until this runs that request filters nothing: a feed carrying 8.8.8.8
# would make every DNS lookup an intelligence-backed alert.
#
# Enabling all of them fails the other way. The cloud and datacenter lists (AWS, GCP,
# Azure, OVH, "VPN providers and datacenters") say an address is rented compute, not
# that it is harmless, and rented compute is where command-and-control servers run:
# on 29 September they dropped every address in abuse.ch's Feodo Tracker list. Those
# are left off. Shared fronts (Cloudflare, Akamai, Fastly), public resolvers and the
# reserved ranges stay on, since an indicator there would match everyone's traffic.
# Run it after the first start of `intel`, and again after MISP updates its lists.
set -eu
cd "$(dirname "$0")/.."

docker compose --profile app exec -T api python - <<'EOF'
import re

import httpx

from netsentinel_api.config import get_settings

HOSTING = re.compile(
    r"Amazon AWS|GCP|Azure (China |Germany |US Government Cloud )?Datacenter|"
    r"Ovh Cluster|VPN providers and datacenters",
    re.IGNORECASE,
)

settings = get_settings()
headers = {
    "Authorization": settings.misp_api_key.get_secret_value(),
    "Accept": "application/json",
    "Content-Type": "application/json",
}
base = settings.misp_url.rstrip("/")
with httpx.Client(headers=headers, timeout=60) as client:
    lists = [w["Warninglist"] for w in client.get(f"{base}/warninglists/index").json()["Warninglists"]]
    hosting = [w for w in lists if HOSTING.search(w["name"])]
    keep = [w["id"] for w in lists if w not in hosting]
    client.post(f"{base}/warninglists/toggleEnable", json={"id": keep, "enabled": 1}).raise_for_status()
    if hosting:
        client.post(
            f"{base}/warninglists/toggleEnable",
            json={"id": [w["id"] for w in hosting], "enabled": 0},
        ).raise_for_status()
print(f"{len(keep)} warninglists enabled; left off as rented hosting:")
for w in hosting:
    print(f"  {w['name']}")
EOF
