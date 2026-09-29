# infra

Deployment for the cloud VM. Nothing here runs on the laptop.

## Why profiles

The VM has 16 GB and Wazuh alone wants 3 GB of it even with its heap tuned down, so
the stack comes up in groups rather than all at once. Every service has an explicit
`mem_limit`: without them one runaway container takes the whole box down, and on a
single-VM deployment that means losing the sensors at the same moment you needed them.

Budget, as the sum of each profile's memory caps:

| Profile | Services | Memory |
|---|---|---|
| `storage` | PostgreSQL, ClickHouse | 2.5 GB |
| `bus` | Redpanda (+ a one-shot topic creator) | 1.2 GB |
| `ingest` | Vector | 0.25 GB |
| `sensors` | Suricata 8, Zeek 8 (both with JA4) | 2 GB |
| `pipeline` | sensor, Tier C scorer, detection writer, flow and Tier C sinks, Suricata importer | 1.7 GB |
| `lab` | victims, benign traffic, attacker | 0.4 GB |
| `dashboards` | Grafana | 0.25 GB |
| `response` | CrowdSec Local API, responder | 0.45 GB |
| `app` | API, dashboard (PostgreSQL shared with `storage`) | 0.6 GB |
| `hids` | Wazuh manager, indexer, dashboard | 3 GB |
| **core** | everything above | **12.3 GB** |
| `intel` | MISP, MariaDB, Redis, Keep | 2.9 GB |
| `case` | DFIR-IRIS app, worker, PostgreSQL, RabbitMQ, nginx | 1.6 GB |
| `scan` | Greenbone gvmd, ospd-openvas, openvasd, Redis, PostgreSQL, feeds | 5.3 GB |

The `pipeline` profile moved the core from 10.4 GB to 12.1 GB, and the responder to
12.3 GB, and the rotation with them. Core plus `case` is 13.9 GB and fits. Core plus
`intel` is 15.2 GB, which leaves under 1 GB for the OS: too little to run unattended, so
for the demo stop `dashboards` or `hids` while `intel` is up. Core plus `scan` is 17.6 GB
and does not fit at all;
stop `hids` for the scan window. None of the three rotating profiles produces
detections, so the detection path never waits on them. `scan`'s 5.3 GB excludes three
one-shot containers that exit once their setup is done.

**On an 8 GB VM** (the only size the student subscription allowed) the caps no longer
fit, but real use does. Measured on the first day, with swap raised to 12 GB:

| Running | Host memory used | Available |
|---|---|---|
| detection path (`storage`, `bus`, `ingest`, `sensors`, `pipeline`, `lab`, `app`) | 3.3 GB | 4.4 GB |
| + `hids` | 4.8 GB | 2.9 GB |
| + `response`, `dashboards`, `case` | 5.2 GB | 2.5 GB |

The largest were the Wazuh indexer (1.3 GB of its 1.5 GB), ClickHouse (650 MB), Suricata
(570 MB) and Redpanda (410 MB). So everything but `intel` and `scan` runs together;
`intel` takes turns with `case`, and `scan` with `intel` and `hids`.

The pipeline's caps (384 MB for the sensor, the Tier C scorer and the writer, 192 MB
for each sink and the importer) were estimates from the libraries each process loads.
On the first day they held with room to spare: the sensor used 150 MB, the writer 104 MB,
each sink about 50 MB and the Tier C scorer 39 MB.

Two figures are above the plan (M1 §7.4): IRIS is capped at 1.6 GB against the plan's
~1.0 GB, because its app and worker are separate Python processes that each need
headroom; and the Wazuh indexer's 1.5 GB cap around a 1 GB heap is tight. Watch
`docker stats` on the first day and raise the indexer before anything else.

The attack traffic that drives these victims — scan, brute force, C2 beacon, exfil — and
the API load test live in [`../lab`](../lab), scoped to the `172.30.0.0/24` bridge by a
guard that refuses any other target.

## First run

On a fresh VM, do `docs/CLOUD_VM.md` first: machine size, Docker, the Wazuh kernel
setting, the deploy key, copying the models and the tunnel.

```bash
cp .env.example .env
# fill in every password; generate each with
#   python3 -c "import secrets; print(secrets.token_urlsafe(24))"

docker compose --profile storage up -d
docker compose --profile bus up -d            # also creates the Kafka topics, once
docker compose --profile lab up -d

# ET Open for Suricata, once (and again whenever you want fresher rules). The rules
# land in suricata/rules/, which is gitignored: ET Open changes daily and carries
# its own licence.
docker compose --profile sensors run --rm --entrypoint suricata-update suricata
docker compose --profile sensors up -d --build  # --build: Zeek bakes in JA4+

docker compose --profile storage --profile ingest up -d

# the API migrates PostgreSQL on start; the writer and importer need that schema,
# and the sensor reads which models are active from the API itself
docker compose --profile app up -d --build
docker compose --profile storage --profile bus --profile pipeline up -d --build
```

The pipeline's one-time setup, its model registration and sensor row, is under
[pipeline](#pipeline-the-detection-path) below. Until the models are registered the
sensor scores nothing.

`ingest` is named together with `storage` because Vector depends on ClickHouse, and
compose refuses a dependency on a service outside the selected profiles. Vector waits
on ClickHouse being healthy, and the schema is applied by ClickHouse's init directory on
first start of an empty volume.

The API reads ClickHouse too, for one thing: flows per minute from `network_flows` for
the dashboard's activity strip, with the same `CLICKHOUSE_USER` and `CLICKHOUSE_PASSWORD`.
It has no dependency on `clickhouse`, which is in `storage`, so `app` still starts
without it; the strip then shows alerts, and flow counts as unavailable rather than zero.

`redpanda-init` creates `netsentinel.flows` (sensor to writer),
`netsentinel.flows.tier_c` (Tier C's per-flow scores, a window behind the flow),
`netsentinel.flows.deadletter` (the writer's malformed flows),
`netsentinel.flows.tier_c.deadletter` (the Tier C sink's) and exits; it leaves an
existing topic alone, so it is safe on every `up`. Check with
`docker compose exec redpanda rpk topic list`.

## pipeline: the detection path

The `pipeline` profile runs the Python processes that turn packets into detections, all
from one image (`pipeline/Dockerfile`: core, scoring, sensors, writer and, for the ORM,
backend; no torch). The model artefacts are mounted read-only from `../artefacts`, so
they must be on the VM beside the checkout; they are gitignored, not in the image.

| Service | Process | From | To |
|---|---|---|---|
| `sensor` | `netsentinel-sensor` on `netsentinel-lab` (host network) | packets | `netsentinel.flows` |
| `tier-c-scorer` | `python -m netsentinel_scoring.window` | `netsentinel.flows` | `netsentinel.flows.tier_c` |
| `detection-writer` | `netsentinel-writer` (Tier A explainer, family labeller) | `netsentinel.flows` | PostgreSQL `detections`, `alerts` |
| `flow-sink` | `netsentinel-flow-sink` | `netsentinel.flows` | ClickHouse `network_flows` |
| `tier-c-sink` | `netsentinel-tier-c-sink` | `netsentinel.flows.tier_c` | ClickHouse `tier_c_scores` |
| `suricata-import` | `netsentinel-import-suricata`, every 300 s | `suricata-logs` volume | PostgreSQL `alerts` |

The sensor scores Tiers A, D and B in process, with both Tier D models loaded:
`tier_d_ae` (the autoencoder) and `tier_d` (the Isolation Forest). The cards do not
decide which of them counts; every card says `shadow`. The model registry does. At
start the sensor reads `GET /api/v1/models/modes` from the API, on the port the `app`
profile publishes (`API_PORT`, 8010 by default), and runs each model in the mode registered for
its name and version:

- **Registered active:** it decides. One active model per tier; with two, the sensor
  refuses to start.
- **Registered shadow, or retired:** it is scored and recorded, and raises nothing.
- **Not registered:** it runs in shadow, with a warning in the sensor's log. An
  unregistered model never decides.
- **API unreachable, or the token refused:** the sensor retries for about fifteen
  seconds, exits non-zero, and `restart: unless-stopped` starts it again. It never
  falls back to the cards' modes, so the `app` profile has to be up.

So nothing is scored until the models are registered and one per tier is active.
The sensor reads the registry once, at start: a promotion on the dashboard takes
effect when `sensor` restarts. Each model's resolved mode is logged as it loads
(`loaded tier D tier_d_autoencoder:1.1.0 in active mode, per the model registry`).

The sensor authenticates with `NETSENTINEL_SENSOR_TOKEN` from `.env`, which compose
gives both `api` and `sensor`. It opens that one list and nothing else, and no user
token opens the list in its place. Left blank, the API serves no list and the sensor
does not start.

The writer refuses to start until the Tier A card is registered and the sensor it
writes for has a row. Both are one-time, after the `app` profile has migrated, and
registration is also where each tier's active model is chosen: Tier A and the autoencoder
decide, and the forest and Tier B observe in shadow, as in the demo
(`lab/replay/build_demo.ps1`):

```bash
docker compose --profile storage --profile bus --profile pipeline run --rm   detection-writer netsentinel-register-model /artefacts/tier_a/model_card.json --mode active
docker compose --profile storage --profile bus --profile pipeline run --rm   detection-writer netsentinel-register-model /artefacts/tier_d_ae/model_card.json --mode active
docker compose --profile storage --profile bus --profile pipeline run --rm   detection-writer netsentinel-register-model /artefacts/tier_d/model_card.json
docker compose --profile storage --profile bus --profile pipeline run --rm   detection-writer netsentinel-register-model /artefacts/tier_b/model_card.json
docker compose exec postgres psql -U netsentinel -d netsentinel -c "
  WITH a AS (INSERT INTO assets (hostname, ip_address, os, criticality)
             VALUES ('netsentinel-vm', '10.0.0.4', 'linux', 'high') RETURNING asset_id)
  INSERT INTO sensors (type, host_asset_id, status)
  SELECT 'early_flow', asset_id, 'online' FROM a RETURNING sensor_id;"
# put that sensor_id in .env as WRITER_SENSOR_ID (default 1), then
docker compose --profile storage --profile bus --profile pipeline up -d
```

Registering without `--mode` puts a model in shadow. Registering it again updates its
row rather than adding one, so the four commands can be repeated, and doing so resets
each model to the mode they name. After a promotion, on the dashboard or with
`netsentinel-shadow-report --promote`, restart the sensor to apply it:

```bash
docker compose --profile storage --profile bus --profile pipeline restart sensor
```

Use the VM's own address for the asset. The Suricata importer re-reads the whole
`eve.json` on each pass and skips alerts it already holds, so the interval
(`SURICATA_IMPORT_SECONDS`) trades freshness against re-reading a growing file.

## Verifying each step

```bash
# ClickHouse has the schema
docker compose exec clickhouse clickhouse-client -q "SHOW TABLES FROM netsentinel"

# the lab bridge exists under a predictable name
ip -br link show netsentinel-lab

# Suricata is sniffing it, and computing JA4
docker compose logs suricata | grep -i "netsentinel-lab"
docker compose exec suricata sh -c 'grep -m1 "\"ja4\"" /var/log/suricata/eve.json'

# Zeek loaded the JA4+ scripts: ssl.log records carry a ja4 field
docker compose exec zeek sh -c 'grep -m1 "\"ja4\"" /var/log/zeek/ssl.log'

# drive an attack and watch an alert appear
docker compose exec attacker nmap -sS -p 1-1000 172.30.0.10
docker compose exec clickhouse clickhouse-client -q \
  "SELECT ts, signature, src_ip FROM netsentinel.suricata_events ORDER BY ts DESC LIMIT 5"

# Vector config, after any edit
docker compose run --rm --entrypoint vector vector validate \
  --no-environment /etc/vector/vector.yaml
```

That nmap-to-ClickHouse round trip is the D3 exit criterion.

If `SHOW TABLES` comes back empty, ClickHouse's very first start probably crashed: that
leaves its volume non-empty, and every later start skips the init schema. Start it from
an empty volume again:

```bash
docker compose rm -sf clickhouse && docker volume rm netsentinel_clickhouse-data
docker compose --profile storage up -d
```

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

**Suricata's configuration is an overlay, not a copy.** `suricata/netsentinel.yaml` is
loaded with `--include` after the image's stock `suricata.yaml` and sets only mapping
keys: the lab's address groups (`EXTERNAL_NET` is `any`, because the attacker is on the
lab subnet too) and `app-layer.protocols.tls.ja4-fingerprints: yes`. An included mapping
replaces the stock one whole rather than merging key by key, so the overlay restates
every stock address and port group, not only the ones it changes. The stock eve-log
already writes alert, flow, dns, http and extended tls records, and extended tls
includes `tls.ja4` once fingerprinting is on. Outputs are left alone on purpose:
Suricata merges an included list by position, so an `outputs:` list in the overlay would
be spliced into the stock one entry by entry.

**Zeek's JA4+ is the scripts package, baked into the image.** `zeek/Dockerfile` installs
`foxio/ja4-zeek-scripts` v1.0.0 at build time with `zkg`. The compiled plugin
(`foxio/ja4`) needs a C++20 toolchain the stock image lacks, and installing at container
start would make the sensor depend on GitHub to come up. `zeek/local.zeek` switches on
JSON logs and loads the package; JA4, JA4S and JA4H then appear in `ssl.log`,
`http.log` and `conn.log`, which Vector already ships into `zeek_logs.fields`. JA4 is
BSD-licensed; the other JA4+ methods are under FoxIO's licence, which permits this
academic use.

**Vector writes to ClickHouse directly, not through Redpanda.** A bus earns its place
when a consumer can fall behind a producer. A log tail into a columnar store is not that.
The scored-flow stream from the extractor does go through Redpanda, where replay matters.

**ClickHouse is capped to 80% of its container's 2 GB.** It reads the cgroup limit, not
the host's RAM, as "RAM"; the first version asked for 12%, meaning 12% of 16 GB, and got
245 MB, too little for a merge. It otherwise assumes it owns the machine,
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

## Dashboards: Grafana on ClickHouse

The `dashboards` profile provisions itself from `grafana/provisioning`: one datasource
(the `grafana-clickhouse-datasource` plugin, pinned to 4.14.0, the last release that
supports Grafana 11.2) and one dashboard, **NetSentinel telemetry**, over the real
tables — flow volume and scored share, risk-score mean and p95, the riskiest sources,
Suricata alerts by severity and signature, the top JA4 client fingerprints from Zeek,
and Zeek record volume by log. Credentials come from the same `CLICKHOUSE_USER` and
`CLICKHOUSE_PASSWORD` as Vector; nothing is typed into the UI.

```bash
docker compose --profile dashboards up -d
# http://127.0.0.1:3000 through the tunnel, admin / GRAFANA_PASSWORD
```

The dashboard is file-provisioned and not editable in the UI: change
`grafana/provisioning/dashboards/json/netsentinel-telemetry.json` and restart Grafana,
so the repository stays the source of truth.

## intel: MISP

The API reaches MISP as `http://misp` on the backplane. Its key is made in MISP, not
here: sign in at `http://localhost:8081` through the tunnel (`MISP_ADMIN_EMAIL` /
`MISP_ADMIN_PASSWORD`), create an automation key, and put it in `.env` as
`NETSENTINEL_MISP_API_KEY`. Blank, the sync refuses to run and nothing else notices.
Use `localhost`, not `127.0.0.1`: MISP's session cookie is marked secure and its
`baseurl` is `http://localhost:8081`, and browsers accept a secure cookie over plain
HTTP only on `localhost`, so on the address the login form fails its CSRF check.

```bash
docker compose --profile app up -d                       # recreate the API with the key
sh misp/warninglists.sh                                  # see below
docker compose exec api netsentinel-sync-intel --since 7d
```

**Warninglists.** The sync asks MISP to enforce them, and MISP ships them loaded but
disabled, so until `misp/warninglists.sh` runs that request filters nothing. The script
enables all of them except the lists of rented hosting (AWS, GCP, Azure, OVH, and the
"VPN providers and datacenters" pair), which mark where C2 servers are run, not what is
harmless: enabled, they dropped every address in abuse.ch's Feodo Tracker list.

**A feed to start with.** On the VM, MISP carries abuse.ch's Feodo Tracker botnet C2
list as a CSV feed (`https://feodotracker.abuse.ch/downloads/ipblocklist.csv`, value
column 2, published on fetch). The plain-text version of the same list is worse: MISP's
free-text parser turns its comment header into indicators for `abuse.ch` and the
tracker's own URL.

Keep needs no key of its own: it runs with `AUTH_TYPE=NO_AUTH` on the backplane, and the
detection writer posts every stored alert to its generic webhook (`/alerts/event`) with
`KEEP_API_KEY` as the header. Keep folds alerts with one fingerprint (source, addresses,
technique) into one. The writer reads the address only when it starts, so recreate it after
`intel` first comes up; while Keep is stopped each forward fails fast, is logged, and the
alert stays stored.

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
# 1. the responder needs a watcher account to write decisions with. Generate its
#    password into .env as NETSENTINEL_CROWDSEC_PASSWORD first:
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
docker compose --profile response up -d crowdsec       # the LAPI alone, for now
docker compose exec crowdsec cscli machines add netsentinel-api \
  --password '<NETSENTINEL_CROWDSEC_PASSWORD>'

# 2. the bouncer needs its own key, and runs on the VM itself
docker compose exec crowdsec cscli bouncers add nftables-bouncer
sudo apt install crowdsec-firewall-bouncer-nftables
sudo install -m 600 crowdsec/crowdsec-firewall-bouncer.yaml /etc/crowdsec/bouncers/
# paste the key into api_key in the installed copy (never the repository's), then
sudo systemctl restart crowdsec-firewall-bouncer

# 3. the responder, which executes approved actions every 10 seconds. It needs
#    PostgreSQL and the API's migrations from the app profile, so they come up together
docker compose --profile app --profile response up -d --build
docker compose logs responder | grep ready   # "responder ready for block_ip ..."
```

Compose points the API and the responder at `http://crowdsec:8080` as
`netsentinel-api`; only the password comes from `.env`. Until it is set the responder
exits at start ("no enforcement point configured") and keeps being restarted, while
approvals wait in the queue: the safe way to be unconfigured. Off the VM, the same worker runs by hand
against the tunnelled LAPI with `NETSENTINEL_CROWDSEC_URL=http://127.0.0.1:8080`,
`NETSENTINEL_CROWDSEC_MACHINE_ID` and `NETSENTINEL_CROWDSEC_PASSWORD` exported:
`uv run netsentinel-respond --once`.

Verifying the D11 exit gate, end to end:

```bash
# an approved block reached the edge
docker compose exec crowdsec cscli decisions list -o human
# and the bouncer wrote it into the kernel - one set per decision origin
sudo nft list set ip crowdsec crowdsec-blacklists-netsentinel | head

# after a rollback, the decision is gone and the address is reachable again
docker compose exec crowdsec cscli decisions list -o human | grep 203.0.113.9 || echo lifted
```

`cscli decisions list` shows the origin as `netsentinel` and the reason as
`netsentinel/block_ip`, so an address blocked by this system is distinguishable at a
glance from one blocked by a CrowdSec scenario.

`crowdsec/crowdsec-firewall-bouncer.yaml` is the bouncer's own default cut to nftables
mode, with the LAPI at `127.0.0.1:8080` and `ban` as the only decision type — the only
one `services/enforcement.py` posts. It hooks `forward` as well as `input`: traffic to
the lab containers is routed through the host rather than delivered to it, and an
input-only bouncer would never see it.

## hids: Wazuh and Sysmon

The `hids` profile is Wazuh 4.14.8 in the `wazuh/wazuh-docker` single-node layout:
the same service names (`wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`) and the
same config files, kept under `wazuh/config` and marked with where they came from.
The certificates are issued to those hostnames, which is why they are not renamed.
What differs is deliberate: every port binds to `127.0.0.1`, the indexer heap is the
plan's `-Xms1g -Xmx1g`, each service has a cap (3 GB together), and the indexer's user
file is kept out of git.

One-time setup, on the VM:

```bash
# 1. certificates, into wazuh/config/wazuh_indexer_ssl_certs/ (gitignored: *.pem)
docker compose --profile hids-certs run --rm wazuh-certs

# 2. the indexer's users. The example holds Wazuh's public demo hashes; replace the
#    admin and kibanaserver hashes with your own before the first start.
cp wazuh/config/wazuh_indexer/internal_users.example.yml \
   wazuh/config/wazuh_indexer/internal_users.yml            # gitignored
docker run --rm -it wazuh/wazuh-indexer:4.14.8 \
  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
#    run it twice - once for WAZUH_INDEXER_PASSWORD (admin), once for
#    WAZUH_DASHBOARD_PASSWORD (kibanaserver) - and paste each hash into the copy.
#    Without a terminal, `htpasswd -bnBC 12 "" '<password>'` (apache2-utils) makes the
#    same bcrypt hash; drop the leading ':'.

# 3. WAZUH_INDEXER_PASSWORD, WAZUH_DASHBOARD_PASSWORD and WAZUH_API_PASSWORD in .env
#    (the API password needs upper, lower, digit and symbol)

docker compose --profile hids up -d
# dashboard: https://127.0.0.1:5601 through the tunnel, admin / WAZUH_INDEXER_PASSWORD
```

The user file is read when the indexer first initialises its security index, which
then lives in `wazuh-indexer-data`. Changing a password later is Wazuh's documented
procedure (new hash in the file, then `securityadmin.sh` inside the container), not an
edit to `.env` alone.

Agents reach the manager on 1514 (events) and 1515 (enrolment), both on `127.0.0.1`.
The agent on the VM uses them directly; the laptop's agent comes through the SSH
tunnel like everything else (`ssh -L 1514:127.0.0.1:1514 -L 1515:127.0.0.1:1515 ...`).

**Sysmon on the laptop.** `../sensors/sysmon/sysmonconfig.xml` is a trimmed
SwiftOnSecurity baseline (credited in the file): process creation and network
connections only, every other event type off. Install it with
`Sysmon64.exe -accepteula -i sysmonconfig.xml`, then paste
`../sensors/sysmon/ossec-localfile.xml` into the Windows agent's `ossec.conf` so
Wazuh reads the `Microsoft-Windows-Sysmon/Operational` channel.

**auditd on the VM** (plan: "auditd on VM"). `auditd/netsentinel.rules` is a small
subset of Florian Roth's baseline (credited in the file): execs in user sessions,
writes to account, sudo, PAM and SSH files, and network-configuration changes. It
uses Wazuh's own audit keys, so the stock rules label the events without a custom
decoder.

```bash
sudo apt install auditd
sudo cp auditd/netsentinel.rules /etc/audit/rules.d/ && sudo augenrules --load
sudo auditctl -l | head                       # the rules are loaded
# paste auditd/ossec-localfile.xml into /var/ossec/etc/ossec.conf, then
sudo systemctl restart wazuh-agent
```

### Active Response

The responder (`services/enforcement.py`) calls `PUT /active-response` with a command
name prefixed `!`. In Wazuh's API that prefix means "a script by this name", not a
command declared in the manager's `ossec.conf`: the agent runs
`active-response/bin/<name>` directly, so the file name on the agent is the whole
contract and the manager needs no configuration for it.

| Action type | Command | Undo | Script on the agent |
|---|---|---|---|
| `isolate_host` | `!netsentinel-isolate` | `!netsentinel-unisolate` | `../sensors/wazuh/active-response/netsentinel-ar` |
| `kill_process` | `!netsentinel-kill-process` | none | the same file |
| `disable_account` | `!disable-account` | `!netsentinel-enable-account` | `disable-account` ships with Wazuh; undo is the same file |

`netsentinel-ar` is one Python script installed under each of the four names; it picks
its action from the name it runs as (installation is in its docstring). Isolation drops
everything except loopback and the manager's address, so the undo can still arrive.

`kill_process` has no undo and never will: a killed process cannot be un-killed, and a
command listed there that quietly did nothing would let an analyst believe a rollback
restored something. `enforcers_from` offers Wazuh only the action types in that map,
so an action type with no command waits in the queue rather than being sent to an
agent that would ignore it.

Compose points the API and the responder at `https://wazuh.manager:55000` as
`wazuh-wui` with `WAZUH_API_PASSWORD`. The manager's own API certificate is
self-signed and names only `localhost`, so the responder could only stop checking it
or fail. Reissue it once, after `hids` is up, and recreate the responder:

```bash
sh wazuh/api-cert.sh                               # names wazuh.manager; exports the public half
docker compose --profile response up -d responder  # "responder ready for block_ip, disable_account, isolate_host, kill_process"
```

The script writes `wazuh/api-tls/api-ca.crt` (gitignored, never the key), which
compose mounts as `NETSENTINEL_WAZUH_CA_FILE`; the responder trusts that certificate
for the manager and nothing else, and does not start while it is missing. Do not set
`NETSENTINEL_WAZUH_VERIFY_TLS=false` instead: this channel isolates hosts. Rerun the
script when the certificate expires (365 days).

## case: DFIR-IRIS

The `case` profile is iris-web v2.4.29's own compose — app, worker, PostgreSQL,
RabbitMQ, nginx — flattened into this file, because upstream's `extends` a base file
and reads a `.env` of its own. v2.4.29 is the release `services/cases.py` was written
against. Budget 1.6 GB, which means it and `intel` take turns.

One-time setup:

```bash
# the six IRIS_* values in .env; IRIS_ADM_API_KEY is 64 hex characters:
python3 -c "import secrets; print(secrets.token_hex(32))"

# a self-signed web certificate, named as docker-compose.yml expects (gitignored)
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout iris/certificates/iris.key -out iris/certificates/iris.pem \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:iris-nginx,IP:127.0.0.1"
# nginx in the image runs as www-data (33) and cannot read a key only you can
sudo chown 33:33 iris/certificates/iris.key

docker compose --profile case up -d
# https://127.0.0.1:8443 through the tunnel, administrator / IRIS_ADM_PASSWORD
```

`IRIS_ADM_*` seed the administrator on the first start of an empty database only.
The API and the responder are already pointed at it: compose gives them
`https://iris-nginx` and `IRIS_ADM_API_KEY`, and once that key is set it makes
`iris/certificates/iris.pem` their trust store (`SSL_CERT_FILE`) rather than turning
verification off, as the API's own settings insist. Recreate them after the first
start of `case` so they pick it up:

```bash
docker compose --profile app --profile response up -d
```

Off the VM, the same three settings by hand, through the tunnel:
`NETSENTINEL_IRIS_URL=https://127.0.0.1:8443`, `NETSENTINEL_IRIS_API_KEY` and
`SSL_CERT_FILE` pointing at a copy of `iris.pem`. `NETSENTINEL_IRIS_CUSTOMER_ID`
defaults to 1.

The customer id is worth checking before the demo: IRIS files every case against one,
rejects an id it does not know, and ships with exactly one. A wrong id surfaces as an
escalation that succeeds with no case attached rather than as an error.

## scan: Greenbone

The `scan` profile is Greenbone Community Edition's own compose cut to what the
importer needs. `services/vulns.py` reads a report that `gvm-cli` fetched over the gvmd
socket, so the web UI chain (`gsa`, `gsad`, `gvm-config`, `nginx`) is dropped and the
scanner, its feeds and `gvm-tools` stay. Greenbone publishes only moving tags, so each
image is pinned by digest; the feed images carry the NVT and SCAP data themselves, and
a fresher feed is a deliberate digest bump. The registry drops old digests of the
daily feed images, so when `up` fails with `not found` on a digest, bump it to what
`docker buildx imagetools inspect <image>:latest` reports. `ospd-openvas` also joins the lab bridge,
because Docker keeps bridges apart and a scanner outside it would find nothing.

It needs 5.3 GB (gvmd alone 2 GB while it loads the feed), so **stop `intel` first**:

```bash
docker compose --profile intel down
docker compose --profile scan up -d
# the first start loads the feed into gvmd, which takes a long while; it is done
# when gvmd logs that it has finished updating VTs
docker compose --profile scan logs -f gvmd

docker compose --profile scan exec -u gvmd gvmd gvmd --user=admin --new-password='<generated>'

gmp() { docker compose --profile scan run --rm -T gvm-tools \
          gvm-cli --gmp-username admin --gmp-password '<generated>' socket --xml "$1"; }

# the lab subnet, Greenbone's stock "All IANA assigned TCP" port list,
# "Full and fast" scan config and OpenVAS scanner
gmp '<create_target><name>lab</name><hosts>172.30.0.0/24</hosts><port_list id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"/></create_target>'
gmp '<create_task><name>lab</name><target id="TARGET-ID"/><config id="daba56c8-73ec-11df-a475-002264764cea"/><scanner id="08b69003-5fc2-4037-a479-93b440211c73"/></create_task>'
gmp '<start_task task_id="TASK-ID"/>'        # prints the report id
gmp '<get_tasks task_id="TASK-ID"/>'          # until status is Done
gmp '<get_reports report_id="REPORT-ID" details="1" ignore_pagination="1" filter="apply_overrides=0 min_qod=70 rows=-1"/>' > report.xml

python -m netsentinel_api.sync_vulns --report report.xml
docker compose --profile scan down            # and intel back up
```

The feed load is the slow part and it has to finish before a scan means anything — a
scanner with no NVTs finds nothing and says so cheerfully. Nothing in this system
talks to gvmd directly, so the profile can go down the moment the report is out.

## Replaying captures onto the lab bridge

`../lab/replay/tcpreplay.sh` replays a pcap onto `netsentinel-lab` at its recorded
pace, so the live sensors see it as traffic (F21). It writes to that bridge and nothing
else, and stops if the bridge is missing, for the same reason the attack scenarios
refuse any target outside the lab. It runs on the VM with `tcpreplay` from apt.

```bash
sudo sh ../lab/replay/tcpreplay.sh ../lab/pcaps/out/scan.pcap
```
