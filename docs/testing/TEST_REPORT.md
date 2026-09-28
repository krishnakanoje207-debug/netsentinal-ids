# Testing and validation report (Milestone 4)

Everything below was first run on 23 September 2026 on the development laptop (Windows 11,
8 GB RAM) against the offline demonstration: PostgreSQL in Docker, the API, the
dashboard, and flows replayed from the NF-UNSW-NB15-v3 test window. Raw outputs sit
beside this file. Section 7 records the first run on the cloud VM, on 27 September 2026.

## 1. Automated tests

| Suite | Tests | Result | Command |
|---|---|---|---|
| Python: unit + integration (7 packages) | 978 | all pass | `uv run pytest` |
| End-to-end chain (detected, explained, enriched, case, approved, blocked) | included above (`tests/e2e`) | all pass | `uv run pytest tests/e2e` |
| Dashboard (React components, API client, stream) | 133 | all pass | `cd frontend; npx vitest run` |

Test counts are from 27 September, after the Tier D re-baselining tool and its 11 tests
were added; coverage was last measured on 24 September.

**Live push, verified against the real stack on 26 September** (native PostgreSQL 16, the
API under uvicorn, the dashboard under Vite): a WebSocket client signed in as the analyst
received one frame per alert the writer stored - 8 of 8, then 12 of 12 after the demo
database was dropped and recreated under the running API, which logged the lost
connection, retried and listened again on its own.

**Coverage** (Python, `coverage.txt`): **82%** of 4,667 statements. The uncovered code is
concentrated in command-line entry points (intel sync, vulnerability import, the
Copilot and writer CLIs: 0%) and in the real-database repository and WebSocket stream
(about 50%), which the suite replaces with fakes. Those paths were exercised live in
section 4 instead.

One dashboard test failed intermittently on a busy machine. The cause: the alert page
lazy-loads the chart library, and the first test to render it paid the one-off load
inside a one-second wait. The test file now loads the chart before its tests; five
consecutive full runs passed afterwards.

## 2. Security testing

| Check | Tool | Result | Output |
|---|---|---|---|
| Static analysis, 8,722 lines of Python | bandit | 5 findings, all reviewed and accepted (1 real issue fixed before this run) | `bandit.json` |
| Known CVEs in Python dependencies | pip-audit | 84 packages, **0 vulnerabilities** (torch CPU build not on PyPI, training-only) | `pip-audit.json` |
| Known CVEs in dashboard dependencies | npm audit | 243 packages, **0 vulnerabilities** | `npm-audit.json` |
| SQL injection through search and login | manual, live API | refused with a 422 / 401; data intact | testing guide 2.5, 3.6 |
| CSV formula injection in the export | unit tests | cells beginning `= + - @` are prefixed | `backend/tests/test_export.py` |
| Prompt injection through alert fields | unit tests | untrusted text fenced, one line, bounded; replies schema-checked | `copilot/tests` |
| XML entity expansion in scan imports | unit test | refused before expansion | `test_vulns.py` |

Bandit findings: an earlier run flagged **B314** (XML parsed with the standard library in the Greenbone
importer). That was real, since the importer takes a file it cannot vouch for, and is **fixed** with
`defusedxml`; it no longer appears. **B405** remains only because the module still imports the
standard `ElementTree` for its `ParseError` and `Element` type names; nothing is parsed with it.
**B608** ("SQL injection" in `nf_mapping.py`) is an error message with no SQL; **B105** is the name
of an environment variable; **B404/B603** are the sensor starting `tcpdump` with an argument list
and no shell. All five are accepted.

## 3. Performance and load

| Requirement | Measured | Verdict |
|---|---|---|
| NFR-01: ML inference <= 5 ms per flow | Tier A 0.07 ms p50, 0.19 ms p99; Tier D 0.06 ms p50, 0.13 ms p99 (ONNX, one flow per call; `docs/evaluation/REPORT.md` §6) | Met |
| NFR-02: dashboard pages < 2 s | Locust, 25 concurrent analysts for 60 s, 683 requests, **0 failures**: feed median 20 ms (p95 47 ms), alert detail median 19 ms (p95 45 ms) | Met |
| Login under the same load | median 780 ms (bcrypt, deliberately slow against guessing; once per session) | By design |

Raw figures: `load/run_stats.csv`.

## 4. System testing (live, through the real stack)

| Scenario | Result |
|---|---|
| 535 flows from the unseen test window replayed through the real scorer and writer | 135/135 attacks alerted, 0/400 false alarms, every alert explained |
| Viewer tries to change an alert | 403 |
| Analyst tries to propose a block; administrator tries to approve | 403 and 403 |
| Rejection without a comment | 422 |
| Same action approved twice | 409 |
| Block aimed at one of the estate's own assets | 422, with the reason |
| Browser: admin proposes, analyst escalates and confirms | all succeed; escalation says honestly that the case system is not connected |
| Copilot on live alerts (llama3.2:3b, laptop GPU) | 12 of 12 replies passed the guards at the time; one was later found to reverse the flow direction, and a guard was added (section 5); earlier prompts were rejected by the guards below and fixed |
| Demo launcher (Docker deployment) | PostgreSQL, API and dashboard up and healthy in 34 s; `-Dev` mode also verified |

## 5. Bugs found and fixed while testing

| Found by | Defect | Fix |
|---|---|---|
| Training audit | Tier A learned TTL, a testbed artefact (TTL alone: PR-AUC 0.998) | TTL removed from the model contract |
| Benchmark | Tier D (Isolation Forest) caught 0.2% of attacks on raw features | log-scaled input in the ONNX graph: 39% recall at a 2% false-positive rate, PR-AUC 0.64 (full test split) |
| Live API check | An approval came back with `approval_id` and `decided_at` null | flush and refresh before responding; test added |
| Live API check | Alert feed answered 500 on real PostgreSQL (INET addresses) | addresses serialised as text; tests added |
| Screenshot review | Models page showed a 0.0047 threshold as "0.00" | small thresholds keep two significant figures |
| Screenshot review | Navigation ran off the screen on a phone | icon-only navigation below tablet width |
| Launcher run | Port 8000 taken by another project; stderr treated as failure | API on 8010; exit codes, not stderr, decide failure |
| Family model check | Fuzzers and Worms techniques were right only 61-79% of the time | a technique must be right 85% of the time on validation to be claimed |
| Live Copilot run | The model invented measurements ("8.67 times larger than average") | evidence gives directions not numbers; such replies rejected |
| Screenshot review | The Copilot called a 100%-risk alert "likely harmless" (9 of 12 replies) | such a verdict is rejected at >= 90% risk; the prompt now defines each verdict, after which 12 of 12 passed |
| Live demo run | The Copilot wrote "Destination address 149.171.126.13 connected to source address 175.45.176.0" for alert 130: right labels, direction reversed, stored as valid | the prompt now says the source connected to the destination; a reply naming the destination as the one connecting is rejected |
| bandit | Unsafe XML parsing of scan reports | `defusedxml` |

## 6. Validation against Milestone 1

Status: **Met**, or **Partial** (built and tested, not fully demonstrated). The live
results come from the 8 GB cloud VM (section 7; setup in `docs/CLOUD_VM.md`, memory in
`infra/README.md`).

| Req. | Summary | Status | Evidence |
|---|---|---|---|
| O1 | Telemetry visible within 10 s | Partial | Suricata, Zeek and Wazuh ran live on the VM and their events reached ClickHouse and the Wazuh indexer (section 7); the 10 s delay was not measured |
| O2 | Signature detection of scan, brute force, web attack | Partial | Suricata 8 ran live on the VM with ET Open and filled `suricata_events`; signature alerts per attack type not measured |
| O3 | Multi-tier ML, PR-AUC >= 0.90, macro-F1, cross-dataset | Partial | A 1.000, B 0.996, C 0.994, D 0.987 (autoencoder); family macro-F1 0.57; cross-dataset 0.74 / 0.05 reported |
| O4 | Early-flow scoring, < 5 ms per flow | Met (offline) / Partial (live) | Tier B scores the first 20 packets in 0.67 ms p99 and is wired into the pipeline sensor in shadow; the demo's NetFlow replay carries no packets; on the VM the sensor runs it in process on live lab traffic, in shadow |
| O5 | Every ML alert explained, with plain language | Met | SHAP is NOT NULL on every detection; plain sentence on every alert; LLM summary where valid |
| O6 | False positives per host-day in a shadow run | Partial | measured on the Models page; no multi-day shadow run yet; on the live lab, Tier D re-baselining took fused false alerts on held-out benign flows from 12.1% to 0.0% (section 7) |
| O7 | No automated block without approval; audited | Met | section 4; gate tests; audit log |
| O8 | Zero licence cost | Met | all free / academic; JA4+ and NF datasets are academic-use |
| FR-01..03 | Suricata, Zeek + JA4, Wazuh + Sysmon | Met (Suricata, Zeek, Wazuh) / Partial (Sysmon) | on the VM, Suricata 8 and Zeek 8 both fingerprinted a TLS exchange with JA4 and the Zeek JA4 reached ClickHouse; a Wazuh agent with auditd sent 299 host alerts; Sysmon is configured (`hids` profile), not run (section 7) |
| FR-04 | Early-flow features | Partial | extractor + offline/live parity test |
| FR-05 | Bus + ClickHouse | Met | Redpanda and ClickHouse ran live on the VM; `network_flows`, `tier_c_scores`, `suricata_events` and `zeek_logs` all fill; the sinks' inserts had been refused by the real server until fixed (section 7) |
| FR-06 | Tier A calibrated | Met | Brier 0.00008 |
| FR-07 | Tier B | Met (offline) | trained on CIC-IDS2017 captures: PR-AUC 0.996, recall 0.977 at 0.69% FPR; in the pipeline sensor in shadow |
| FR-08 | Tier C | Met (offline) | PR-AUC 0.994; held-out attacker 0.978-0.996; scored in shadow over flow windows by the pipeline's Tier C scorer |
| FR-09 | Tier D | Met | autoencoder trained on benign flows only, served in the demo: PR-AUC 0.987, recall 0.985 at 0.80% FPR, p99 0.13 ms; the Isolation Forest scores beside it in shadow |
| FR-10 | Fusion with signatures and intel | Partial | A+D fused; intel raises severity; Suricata runs on the VM and its events are imported |
| FR-11 | Shadow / active, switchable | Met | promotion gate, CLI and dashboard |
| FR-12 | SHAP on every detection | Met | database constraint |
| FR-13 | Local LLM summary, read-only, validated | Met | section 4 |
| FR-14 | MISP enrichment | Partial | tested against fakes; MISP 2.5.17 answers on the VM, from the host and from the API container |
| FR-15 | Keep, DFIR-IRIS | Partial | tested against fakes; escalation works without IRIS; on the VM, Keep's healthcheck answers 200 and the IRIS API accepts the seeded key |
| FR-16 | Approve/reject; block only after approval | Met (gate) / Partial (enforcement) | CrowdSec tested against fakes; on the VM a test ban appeared in the nftables set and was removed when lifted; the responder is now a Compose service |
| FR-17 | OpenVAS findings per asset | Partial | importer tested; findings shown per host on the Estate page; hosts loaded by the inventory import; Greenbone runs on the VM in its own window, taking turns with MISP |
| FR-18 | Live alerts, details, SHAP, model metrics | Met | dashboard; alerts pushed over the WebSocket as they are stored (section 1) |
| FR-19 | Search and export | Met | address / network / technique search and a from/to time range (ISO 8601; a reversed or unreadable range is refused with a sentence); export as CSV or PDF with the same filters, audited |
| FR-20 | JWT + Admin, Analyst, ML Engineer, Viewer | Met | Viewer added 23 Sep |
| FR-21 | Audit of logins, approvals, changes, actions | Met | every login outcome, triage, decision, export, promotion |
| FR-22 | Model registry with SHA-256 | Met | registry refuses a mismatched file |
| FR-23 | Scripted attacks + replay | Met (replay, nmap scan on the live lab) / Partial (other scripts) | `lab/`; the nmap scan's 1000 flows on the VM, 999 above 0.5 (section 7) |
| NFR-01 | Latency | Met | Tier A 0.07 ms, Tier D autoencoder 0.13 ms p99, Tier B 0.67 ms p99 |
| NFR-02 | Page load | Met | section 3 |
| NFR-03 | Honest evaluation | Met | temporal split, PR-AUC, Brier, held-out attacker, cross-dataset |
| NFR-04 | HTTPS, bcrypt, JWT expiry, RBAC, secrets out of git | Met | nginx terminates TLS 1.2/1.3 for the dashboard, `/api` and the alert WebSocket (wss) on 127.0.0.1:5180, and redirects plain HTTP to HTTPS; the self-signed certificate is made at image build, so no key is in the repository (`frontend/nginx.conf`, `frontend/Dockerfile`); verified live: health 200 and analyst login 200 over HTTPS, wss stream connects, bad token refused |
| NFR-05 | Safe LLM | Met | section 2 and 4 |
| NFR-06 | Restart policies, buffering | Partial | `restart: unless-stopped`; bus buffering designed, not run |
| NFR-07 | Alert to decision in <= 3 clicks, clear text | Met | Overview -> alert -> action |
| NFR-08 | Modular, versioned, documented | Met | 7 packages, OpenAPI at /api/v1/docs |
| NFR-09 | Scalable later | Met (by design) | Kafka-protocol bus; Flink is future work |
| NFR-10 | Whole stack in Docker Compose on a 16 GB Linux host | Partial | `infra/docker-compose.yml` profiles with memory caps; only an 8 GB VM was available: everything but intel (MISP) and scan (Greenbone) runs together at 5.2 GB used, and those two take turns (`infra/README.md`) |
| NFR-11 | Verdict traceable to model version, features, SHAP | Partial | detection row carries `model_id` (name, version, SHA-256) and NOT NULL SHAP; input feature values not stored with it, only `flow_id`; the flow sink writes them to ClickHouse `network_flows`, which filled live on the VM |
| NFR-12 | Free licences, academic datasets, attacks only in the lab | Met | see O8; `lab/scenarios/_guard.sh` refuses any target outside 172.30.0.0/24; published ports bind to 127.0.0.1 |

## 7. Live run on the cloud VM (27 September 2026)

Azure for Students, Central India: 4 vCPU, 8 GB RAM, Ubuntu 24.04 LTS, swap raised to
12 GB. The 16 GB sizes in the plan were not available on the subscription. Only SSH is
open; every service binds to 127.0.0.1 and is reached through a tunnel. Setup is in
`docs/CLOUD_VM.md`, memory per profile in `infra/README.md`.

The live lab: attacker 172.30.0.100, victim-web 172.30.0.10 (nginx), victim-ssh
172.30.0.11, and a benign client 172.30.0.2 running a curl loop.

### Checks passed

| Check | Result |
|---|---|
| nmap SYN scan of 1000 ports from the attacker | 1000 flows, mean risk 0.937, 999 of 1000 above 0.5; alerts went from 97 to 1102 (medium 466, high 454, low 186 at that point) |
| Benign client flows | mean risk 0.168, none above 0.5 |
| ClickHouse tables | `network_flows`, `tier_c_scores`, `suricata_events` and `zeek_logs` all fill live |
| JA4 | a TLS exchange on the lab bridge fingerprinted by both Suricata and Zeek (`t13d311000_e8f1e7e78f70_518fb456ca59`, `t13i3111h2_e8f1e7e78f70_6bebaf5329ac`); the Zeek JA4 reached ClickHouse |
| Wazuh 4.14.8 | indexer cluster green, manager API issues tokens, dashboard serves; an agent with 21 auditd rules on the VM enrolled and sent 299 host alerts (audit commands, PAM sessions) within minutes |
| CrowdSec LAPI + nftables bouncer | a test ban on 203.0.113.9 appeared in the set `crowdsec-blacklists-cscli` and was removed when lifted |
| Grafana | ClickHouse datasource health "Data source is working"; the NetSentinel telemetry dashboard provisioned |
| DFIR-IRIS 2.4.29 | login page 200, API accepts the seeded key, customer 1 exists |
| MISP 2.5.17 | login answers on port 80, from the host and from the API container |
| Keep 0.33.6 | healthcheck 200 |
| Greenbone | run in its own window, taking turns with MISP |

### Defects found only against the real servers

Each of these passed the unit tests and the fakes. All 12 are fixed and committed.

| Component | Defect |
|---|---|
| ClickHouse | refused to start (code 36): the smaller merge pool (4 = 8 entries) was below three default merge-tree thresholds (20, 8, 25) |
| ClickHouse | unreachable from other containers: mounting the whole `config.d` hid the image's `listen_host` file |
| ClickHouse | memory ratio 0.12 applied to the 2 GB container limit, not host RAM: 245 MB, and merges failed; now 0.8 of the container |
| ClickHouse | healthcheck used `localhost`, which resolves to `::1`, where it does not listen |
| Suricata | restarted forever: the image entrypoint chowns `/etc/suricata` and died on the read-only overlay mounted there |
| Suricata | dropped about 6,800 ET rules: an `--include` mapping replaces the stock address and port groups wholesale, so `HTTP_SERVERS` and the rest were undefined; the offline pcap runs used the same overlay, so they loaded fewer rules |
| Vector | refused its config: the VRL function `to_timestamp` does not exist in Vector 0.41 |
| Vector | inserts rejected: ClickHouse's basic DateTime64 parser refuses RFC 3339 strings (`date_time_best_effort` now set) |
| Flow and Tier C sinks | every insert HTTP 400: JSONEachRow refuses an unquoted decimal timestamp; now integer milliseconds. The unit tests had checked only the row builder, never a real server |
| MISP | redirected all HTTP to https on 443, which nothing could reach |
| Keep | restarted 40+ times: its named volume belonged to root, and Keep runs as uid 999 |
| Sensor | ended a TCP flow on the first FIN, so the peer's FIN-ACK and the final ACK became one-packet flows of their own, two per connection, which Tier A scored like probes that got no reply; a flow now ends once both sides have sent a FIN, or at once on a RST |

Also: IRIS's nginx could not read its private key (it needed owner 33), and the responder,
which executes approved actions, had never been run on the VM; it is now a Compose service.

### Tier D false positives on live traffic

The benign client raised 119 low alerts in about 15 minutes. Tier A called these flows
benign (about 0.006), but both Tier D models scored them about 0.99: their "normal" was
calibrated on the benchmarks' benign traffic (CIC-IDS2017, UNSW), not the lab's. With
Tier D pinned at its threshold, the fused rule alerted whenever Tier A cleared its own low
threshold (0.0047), on about 10% of benign flows.

The fix is a re-baselining tool (`training/src/netsentinel_training/models/recalibrate.py`).
It refits Tier D's calibration quantiles and threshold on the deployment's own benign
flows and keeps the ONNX graph byte-identical, so the hash is unchanged. The new version
is born in shadow, and the card records where its baseline came from.

| Lab cards `tier_d_autoencoder 1.2.0-lab`, `tier_d_isolation_forest 1.1.0-lab` | Before | After |
|---|---|---|
| Fused false alerts, 1190 held-out lab benign flows after 05:20 UTC | 12.1% | 0.0% |
| nmap scan's 1000 flows detected | 100% | 100% |

Both were fitted on 1857 lab benign flows (04:37-05:20 UTC), are registered, and score in
shadow on the VM; promotion goes through the shadow report. The Isolation Forest detects
none of the scan before or after, and it was already in shadow.
