# Project status

Where NetSentinel-AI stands against the locked plan (Research Comparison and 15-Day
Execution Plan v1.0), what remains, and why some planned tools are not running yet.
Updated 26 September 2026.

## Measured today

| What | Result | Evidence |
|---|---|---|
| Tier A (LightGBM), temporal test split | PR-AUC 1.0000, precision 0.995, recall 1.000, FPR 0.05% | `docs/evaluation/REPORT.md` |
| M1 objective O3 (PR-AUC >= 0.90) | Met | same |
| Shortcut found and removed | TTL alone scores 0.998; excluded from the model | same, section 2 |
| Tier D autoencoder (benign-only, 64/8), test split | PR-AUC 0.987, recall 0.985 at 0.80% FPR, p50 0.07 ms, p99 0.13 ms; **active** in the demo | `artefacts/tier_d_ae/model_card.json` |
| Tier D Isolation Forest (benign-only) | PR-AUC 0.64, recall 0.39 at 0.84% FPR (0.2% before log-scaling); now in shadow beside the autoencoder | `artefacts/tier_d/model_card.json` |
| Attack-family classification | macro-F1 0.57, accuracy 70% (attack flows only); confident (>= 70%) on 74% of attacks, 76% of those right. Weakest: Backdoor 0.05, DoS 0.33, Analysis 0.37 | `artefacts/family/model_card.json` |
| MITRE technique on ML alerts | Claimed only at >= 70% family confidence, and only for Reconnaissance (T1046), Exploits (T1190) and DoS (T1499), whose confident labels were right >= 85% of the time on validation. In the demo, 24 of 135 alerts carry a technique; the rest say why they have none | same; demo database |
| Tier B (1D-CNN + BiLSTM, first 20 packets), CIC-IDS2017 Friday captures split by time | PR-AUC 0.996, recall 0.977 at 0.69% FPR; recall PortScan 1.00, DDoS 0.87, Bot 0.35; p99 0.67 ms; abstains on flows under 4 packets; shadow | `artefacts/tier_b/model_card.json` |
| Tier C (E-GraphSAGE), 20k-flow windows | PR-AUC 0.994, recall 0.988, precision 0.874; shadow | `artefacts/tier_c/model_card.json` |
| Held-out attacker (never seen in training) | Tier A PR-AUC >= 0.9999, Tier C 0.978-0.996 | `docs/evaluation/holdout/REPORT.md` |
| Cross-dataset (trained on UNSW) | 0.74 on ToN-IoT, 0.05 on CIC-IDS2018 | `docs/evaluation/REPORT.md`, section 5 |
| Latency per flow (NFR-01, <= 5 ms) | Tier A 0.07 ms; Tier D autoencoder 0.13 ms p99; Tier B 0.67 ms p99 | model cards |
| Replay of unseen flows through the real pipeline | 135/135 attacks alerted, 0/400 false alarms (re-run 26 Sep on the current models) | `lab/replay` |
| Live alert push, end to end | Alerts written by the writer process reach the dashboard's WebSocket: 8 of 8 and 12 of 12 frames in two runs, including after the database was dropped and recreated under a running API | section "Live feed" in `README.md` |
| Load: 25 concurrent analysts | 683 requests, 0 failures, feed p95 47 ms (24 Sep) | `docs/testing/TEST_REPORT.md` |
| Security scans | bandit (1 real issue, fixed), pip-audit and npm audit: 0 known vulnerabilities (24 Sep) | same |
| Automated tests | 965 Python + 133 dashboard, all passing (coverage 82% when last measured, 24 Sep) | `uv run pytest`, `npx vitest run` |

## Planned tools: built, running, or not

The plan splits the system across a 16 GB cloud VM (always-on services), Kaggle (training)
and the laptop (dashboard, LLM). **The cloud VM was never provisioned**, and this laptop has
8 GB of RAM (under 1 GB free with the usual desktop open), so every service that needs Linux
packet capture or several GB of memory is built and configured but not running. Nothing
below was dropped from the design.

| Planned | In the plan as | Status | Why |
|---|---|---|---|
| Suricata 8 + Zeek + JA4 (F1, F2) | Always-on on the VM | Configured (Compose `sensors` profile, ET Open, FoxIO JA4); run offline against capture files | Live capture needs a Linux host |
| Wazuh 4.14 + Sysmon + auditd (F3) | Always-on on the VM | Configured (Compose `hids` profile, agent and Sysmon config); Active Response client built and tested | Needs 3 GB+ and its own indexer |
| Redpanda (F5) | VM | Configured (`bus` profile, topics created by an init job); sensor, writer and sinks speak the Kafka protocol | Not run locally |
| ClickHouse, Vector, Grafana (F5, F19) | VM | Configured; the flow sink and Tier C sink are built and tested; Grafana is provisioned on ClickHouse | Not run locally; the dashboard's last-hour strip says flow counts are unavailable |
| Sensor, scorers, writers as one pipeline (F10) | VM | Compose `pipeline` profile: sensor (Tiers A, B, D), Tier C window scorer, detection writer, flow sinks, Suricata importer; model modes read from the API's registry | Needs the VM |
| MISP, Keep (F13, F14) | VM, intel profile | Integration built and tested against fakes | MISP needs ~4 GB |
| DFIR-IRIS (F15) | VM | Compose `case` profile; integration built and tested against fakes | Escalation says so honestly when unconfigured |
| CrowdSec + nftables (F16) | VM | Compose `response` profile with the nftables bouncer; integration tested against fakes | Needs a Linux edge |
| Greenbone/OpenVAS (F17) | VM, scan window | Compose `scan` profile; importer built and tested; findings and the date of each host's last scan shown on the Estate page | Runs in its own window on the VM |
| Asset inventory | Assumed by F16/F17 | **Built**: `netsentinel-import-assets` from a CSV; the demo imports the dataset's ten servers | |
| Ollama Copilot (F20) | Laptop GPU | **Running**: llama3.2:3b on the GTX 1650; summaries on the alert page | Replies that invent a measurement are rejected |
| Live alert feed (F18) | Dashboard | **Running**: a PostgreSQL trigger announces each stored alert and the API pushes it over the WebSocket | |
| Tier B (F7) | Kaggle | Trained on the laptop CPU; scored in shadow by the pipeline sensor | Not in the demo: the NetFlow replay carries no packets |
| Tier C (F8) | Kaggle | Trained on the laptop CPU; scored in shadow over flow windows by the pipeline | Not in the demo: it scores windows of a live stream |
| Tier D autoencoder (F9) | Kaggle | Trained on the laptop CPU; **active** in the demo, the forest in shadow | |
| CI (GitHub Actions) | Not in the plan | **Running** on every push to the private repository `netsentinal-ids`: per-package tests, frontend tests and build, bandit, pip-audit, npm audit, Compose validation; green since the first run on 26 Sep | |
| Apache Kafka | **Fallback** only | Not used, by design | The plan locks Redpanda (Kafka API, lighter) |
| Apache Flink | **Out of scope for v1.0** | Not built, by design | Future work in the plan (section 9.2); the Python scorer does the streaming |
| NVIDIA Triton | Dropped in rev. 1 | Not used, by design | In-process ONNX Runtime: 0.07 ms per flow, no GPU server |

## The dashboard

Rebuilt on 25 September to the owner's brief: a station information system, light by
default with a night mode, a station clock whose second hand runs only while the live feed
is connected, split-flap counts, a departures board of alerts, hover and focus detail
everywhere, a last-hour strip drawn to scale, and a 13-stop guided tour. Reviewed on 26
September against the real API and database rather than fixtures; the review found and
fixed: the live feed never pushing, the feed stopping at 50 alerts, shadow models shown by
their raw identifiers, alert counts drawn almost flat in the last-hour strip, and faint
night-mode tiles. The Estate page (hosts and their scan findings) was added the same day.

## Remaining work

| # | Task | For | Needs |
|---|---|---|---|
| 1 | Cloud VM with Suricata, Zeek, Wazuh, Redpanda and ClickHouse live, running the `pipeline` profile | Full plan | An Azure for Students (or other) VM, about 6-8 h after it exists |

**Attack-family accuracy (investigated 26 September, left as it is).** Backdoor, DoS and
Analysis stay weak (test F1 0.05-0.37), and flow features cannot fix it. On the same
split, adding the TCP flags the sensor can also produce raised macro-F1 from 0.566 to
0.587, and adding every NetFlow field except TTL reached only 0.591, with Backdoor still
0.06. The model fits its own training data to only F1 0.47 on Backdoor and DoS, so those
flows are not separable by these statistics; Backdoor also drifts over time (its test
window aims at ports 53, 80 and 445, its training window at 179 and 520). A gain of 0.02
is within the spread between runs, so the model was not changed. Telling these apart
needs packet content: Suricata signatures and Tier B on a live capture.

The Estate page now records which hosts a scan covered (`assets.last_scanned_at`, from
the Greenbone report's host list, done 26 September).

**Severity** (decided 26 September) combines how sure the models are with how much harm
the attack could do. Confidence alone made 134 of 135 demo alerts critical. Impact is
claimed only where the MITRE technique is: exploitation (T1190) and denial of service
(T1499) are harmful, a scan (T1046) is a precursor, and an attack of unknown kind counts as
middling, never harmless.

| How sure | harmful | not known | scan |
|---|---|---|---|
| >= 0.95 | critical | high | medium |
| >= 0.85 | high | medium | low |
| >= 0.70 | medium | low | low |

On the demo replay this gives 11 critical, 110 high, 13 medium and 1 low. Twelve of the
fifteen scans become medium; one Backdoor that the family model mislabelled as a scan
does too, which is the price of the scan label being about 85% precise. Intelligence
matches still raise a severity by one step.

## What I need from you

- For item 1: a VM, or a decision to present the VM-bound services as future work.
