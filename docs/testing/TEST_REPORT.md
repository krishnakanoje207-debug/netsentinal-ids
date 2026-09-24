# Testing and validation report (Milestone 4)

Everything below was run on 23 September 2026 on the development laptop (Windows 11,
8 GB RAM) against the offline demonstration: PostgreSQL in Docker, the API, the
dashboard, and flows replayed from the NF-UNSW-NB15-v3 test window. Raw outputs sit
beside this file.

## 1. Automated tests

| Suite | Tests | Result | Command |
|---|---|---|---|
| Python: unit + integration (7 packages) | 713 | all pass | `uv run pytest` |
| End-to-end chain (detected, explained, enriched, case, approved, blocked) | included above (`tests/e2e`) | all pass | `uv run pytest tests/e2e` |
| Dashboard (React components, API client, stream) | 94 | all pass | `cd frontend; npx vitest run` |

**Coverage** (Python, `coverage.txt`): **81%** of 4,505 statements. The uncovered code is
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
| NFR-01: ML inference <= 5 ms per flow | Tier A 0.07 ms p50, 0.19 ms p99; Tier D 8.2 ms p50, 17.1 ms p99 (ONNX, one flow per call; `docs/evaluation/REPORT.md` §6) | Tier A met; Tier D over budget |
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

Status: **Met**, **Partial** (built and tested, not fully demonstrated), or
**Deferred** (needs the 16 GB cloud VM that was never provisioned; see
`docs/PROJECT_STATUS.md`).

| Req. | Summary | Status | Evidence |
|---|---|---|---|
| O1 | Telemetry visible within 10 s | Deferred | needs Suricata/Zeek/Wazuh on the VM |
| O2 | Signature detection of scan, brute force, web attack | Deferred | Suricata configured, not running |
| O3 | Multi-tier ML, PR-AUC >= 0.90, macro-F1, cross-dataset | Partial | A 1.000, C 0.994, D 0.64; macro-F1 0.52; cross-dataset 0.74 / 0.05 reported |
| O4 | Early-flow scoring, < 5 ms per flow | Partial | Tier A 0.07 ms, Tier D 8.2 ms; early-packet extractor built and parity-tested, served models use flow aggregates |
| O5 | Every ML alert explained, with plain language | Met | SHAP is NOT NULL on every detection; plain sentence on every alert; LLM summary where valid |
| O6 | False positives per host-day in a shadow run | Partial | measured on the Models page; no multi-day shadow run yet |
| O7 | No automated block without approval; audited | Met | section 4; gate tests; audit log |
| O8 | Zero licence cost | Met | all free / academic; JA4+ and NF datasets are academic-use |
| FR-01..03 | Suricata, Zeek + JA4, Wazuh + Sysmon | Deferred | Suricata and Zeek are services in the `sensors` Compose profile, never run; the JA4 package is not installed; Wazuh and Sysmon are not in Compose (`infra/README.md` points to Wazuh's own stack) |
| FR-04 | Early-flow features | Partial | extractor + offline/live parity test |
| FR-05 | Bus + ClickHouse | Partial | Redpanda consumer/producer tested; ClickHouse `network_flows` DDL generated from the contract, but no sink writes scored flows to it (they go sensor -> Redpanda -> writer -> PostgreSQL) |
| FR-06 | Tier A calibrated | Met | Brier 0.00008 |
| FR-07 | Tier B | Partial | code + tests; needs packet captures |
| FR-08 | Tier C | Met (offline) | PR-AUC 0.994; held-out attacker 0.978-0.996; not yet in the live path |
| FR-09 | Tier D | Partial | Isolation Forest met; autoencoder not built |
| FR-10 | Fusion with signatures and intel | Partial | A+D fused; intel raises severity; signatures not running |
| FR-11 | Shadow / active, switchable | Met | promotion gate, CLI and dashboard |
| FR-12 | SHAP on every detection | Met | database constraint |
| FR-13 | Local LLM summary, read-only, validated | Met | section 4 |
| FR-14 | MISP enrichment | Partial | tested against fakes |
| FR-15 | Keep, DFIR-IRIS | Partial | tested against fakes; escalation works without IRIS |
| FR-16 | Approve/reject; block only after approval | Met (gate) / Partial (enforcement) | CrowdSec tested against fakes |
| FR-17 | OpenVAS findings per asset | Partial | importer tested |
| FR-18 | Live alerts, details, SHAP, model metrics | Met | dashboard |
| FR-19 | Search and export | Partial | address / network / technique search and CSV; no time-range search or PDF |
| FR-20 | JWT + Admin, Analyst, ML Engineer, Viewer | Met | Viewer added 23 Sep |
| FR-21 | Audit of logins, approvals, changes, actions | Met | every login outcome, triage, decision, export, promotion |
| FR-22 | Model registry with SHA-256 | Met | registry refuses a mismatched file |
| FR-23 | Scripted attacks + replay | Met (replay) / Partial (scripts need the lab VM) | `lab/` |
| NFR-01 | Latency | Partial | Tier A within budget; the served Tier D Isolation Forest is not (section 3) |
| NFR-02 | Page load | Met | section 3 |
| NFR-03 | Honest evaluation | Met | temporal split, PR-AUC, Brier, held-out attacker, cross-dataset |
| NFR-04 | HTTPS, bcrypt, JWT expiry, RBAC, secrets out of git | Met | nginx terminates TLS 1.2/1.3 for the dashboard, `/api` and the alert WebSocket (wss) on 127.0.0.1:5180, and redirects plain HTTP to HTTPS; the self-signed certificate is made at image build, so no key is in the repository (`frontend/nginx.conf`, `frontend/Dockerfile`); verified live: health 200 and analyst login 200 over HTTPS, wss stream connects, bad token refused |
| NFR-05 | Safe LLM | Met | section 2 and 4 |
| NFR-06 | Restart policies, buffering | Partial | `restart: unless-stopped`; bus buffering designed, not run |
| NFR-07 | Alert to decision in <= 3 clicks, clear text | Met | Overview -> alert -> action |
| NFR-08 | Modular, versioned, documented | Met | 7 packages, OpenAPI at /api/v1/docs |
| NFR-09 | Scalable later | Met (by design) | Kafka-protocol bus; Flink is future work |
| NFR-10 | Whole stack in Docker Compose on a 16 GB Linux host | Partial | `infra/docker-compose.yml` profiles with memory caps; `app` profile verified (up in 34 s); full stack never run on a 16 GB host; Wazuh not in Compose |
| NFR-11 | Verdict traceable to model version, features, SHAP | Partial | detection row carries `model_id` (name, version, SHA-256) and NOT NULL SHAP; input feature values not stored with it, only `flow_id`; the ClickHouse flow table that would hold them has no sink writing to it |
| NFR-12 | Free licences, academic datasets, attacks only in the lab | Met | see O8; `lab/scenarios/_guard.sh` refuses any target outside 172.30.0.0/24; published ports bind to 127.0.0.1 |
