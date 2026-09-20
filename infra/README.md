# infra

Deployment for the cloud VM. Nothing here runs on the laptop.

## Why profiles

The VM has 16 GB and Wazuh alone wants 4–5 GB of it, so the stack comes up in groups
rather than all at once. Every service has an explicit `mem_limit`: without them one
runaway container takes the whole box down, and on a single-VM deployment that means
losing the sensors at the same moment you needed them.

Rough budget:

| Profile | Services | Memory |
|---|---|---|
| `storage` | PostgreSQL, ClickHouse | 2.5 GB |
| `bus` | Redpanda | 1.2 GB |
| `ingest` | Vector | 0.25 GB |
| `sensors` | Suricata, Zeek | 2 GB |
| `lab` | victims, benign traffic, attacker | 0.4 GB |
| `dashboards` | Grafana | 0.25 GB |
| `response` | CrowdSec Local API | 0.25 GB |

About 6.6 GB, leaving room for Wazuh and the OS.

## First run

```bash
cp .env.example .env
# fill in every password; generate each with
#   python3 -c "import secrets; print(secrets.token_urlsafe(24))"

docker compose --profile storage up -d
docker compose --profile lab up -d
docker compose --profile sensors up -d
docker compose --profile ingest up -d
```

Bring `storage` up before `ingest` — Vector waits on ClickHouse being healthy, and the
schema is applied by ClickHouse's init directory on first start of an empty volume.

## Verifying each step

```bash
# ClickHouse has the schema
docker compose exec clickhouse clickhouse-client -q "SHOW TABLES FROM netsentinel"

# the lab bridge exists under a predictable name
ip -br link show netsentinel-lab

# Suricata is sniffing it
docker compose logs suricata | grep -i "netsentinel-lab"

# drive an attack and watch an alert appear
docker compose exec attacker nmap -sS -p 1-1000 172.30.0.10
docker compose exec clickhouse clickhouse-client -q \
  "SELECT ts, signature, src_ip FROM netsentinel.suricata_events ORDER BY ts DESC LIMIT 5"

# Vector config, after any edit
docker compose run --rm --entrypoint vector vector validate \
  --no-environment /etc/vector/vector.yaml
```

That nmap-to-ClickHouse round trip is the D3 exit criterion.

## Decisions worth knowing

**The lab bridge has a fixed name.** Docker names bridges `br-<hash>`, which changes
whenever the network is recreated — and Suricata pointed at a stale interface sniffs
nothing while looking perfectly healthy. `com.docker.network.bridge.name` pins it to
`netsentinel-lab`.

**Every published port binds to `127.0.0.1`.** Nothing is exposed to the internet; you
reach ClickHouse, Grafana and the API through the SSH tunnel. This VM is deliberately
full of attack traffic, and the NSG only permits port 22.

**Benign traffic is part of the lab, not an afterthought.** Without it the models learn
that "any traffic at all" means an attack, which is the classic way a lab-trained IDS
looks excellent in testing and is useless in production.

**Suricata and Zeek use host networking.** A container attached to the lab network would
only see traffic addressed to itself, not the conversations between the other containers.

**Vector writes to ClickHouse directly, not through Redpanda.** A bus earns its place
when a consumer can fall behind a producer. A log tail into a columnar store is not that.
The scored-flow stream from the extractor does go through Redpanda, where replay matters.

**ClickHouse is capped to roughly 12% of RAM.** It otherwise assumes it owns the machine,
and on a shared box that ends with the OOM killer choosing a victim.

## The schema is generated, not written

`clickhouse/init/01_schema.sql` comes from `netsentinel_core.features.clickhouse`, so the
`network_flows` table cannot drift from the feature contract. `core/tests/test_clickhouse_ddl.py`
fails if the committed file is stale. Regenerate with:

```bash
python -m netsentinel_core.features.clickhouse > infra/clickhouse/init/01_schema.sql
```

## Deviation from M2 §3.3

M2 lists a representative column set for `network_flows`. The generated table holds the
full 73-feature contract instead, because a table narrower than what the extractor
produces would silently discard features. Scalars are all `Float64` to match the
contract's own type rather than packed into narrower integers — the space saving is not
worth a conversion on every write.

`risk_score` is nullable. An undecided flow must not be storable as `0`, which would read
as "confidently benign".

## Response: CrowdSec and the nftables bouncer

The `response` profile runs the CrowdSec **Local API only** — `DISABLE_AGENT` is set,
because CrowdSec's own parsers and scenarios are a second detection engine and this
system already has one. Decisions here arrive from an analyst approving an action, and
from nowhere else.

The enforcement is split in two on purpose. The LAPI holds the decisions; the
**firewall bouncer runs on the host**, not in a container, because it writes nftables
sets in the host's network namespace. A bouncer inside Docker would filter its own
namespace and block nothing.

```bash
# 1. the API needs a watcher account to write decisions with
docker compose --profile response up -d
docker compose exec crowdsec cscli machines add netsentinel-api --password '<generated>'

# 2. the bouncer needs its own key, and runs on the VM itself
docker compose exec crowdsec cscli bouncers add nftables-bouncer
sudo apt install crowdsec-firewall-bouncer-nftables
sudo sed -i 's|^api_url:.*|api_url: http://127.0.0.1:8080/|'   /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
# paste the key into api_key in the same file, then
sudo systemctl restart crowdsec-firewall-bouncer

# 3. point the responder at the LAPI (in the API's environment, not .env here)
export NETSENTINEL_CROWDSEC_URL="http://127.0.0.1:8080"
export NETSENTINEL_CROWDSEC_MACHINE_ID="netsentinel-api"
export NETSENTINEL_CROWDSEC_PASSWORD="<the password from step 1>"
uv run netsentinel-respond --once
```

Verifying the D11 exit gate, end to end:

```bash
# an approved block reached the edge
docker compose exec crowdsec cscli decisions list -o human
# and the bouncer wrote it into the kernel
sudo nft list set inet crowdsec crowdsec-blacklists | head
```

`cscli decisions list` shows the origin as `netsentinel` and the reason as
`netsentinel/block_ip`, so an address blocked by this system is distinguishable at a
glance from one blocked by a CrowdSec scenario.

## Wazuh

Wazuh is not in this compose file. It ships its own multi-container stack, and rewriting
it would mean maintaining a fork of somebody else's deployment for no gain. Clone
`wazuh/wazuh-docker` at the matching tag and run its single-node compose, then keep its
memory settings in mind against the budget above.

Its Active Response side needs two commands declared in the manager's `ossec.conf`,
because Wazuh ships no stock equivalent of either:

| Action type | Command | Script |
|---|---|---|
| `isolate_host` | `!netsentinel-isolate` | deployed with the agent |
| `kill_process` | `!netsentinel-kill-process` | deployed with the agent |
| `disable_account` | `!disable-account` | ships with Wazuh |

The map lives in `services/enforcement.py`, and `enforcers_from` offers Wazuh only the
action types it appears in — so an action type with no command waits in the queue
rather than being sent to an agent that would ignore it.
