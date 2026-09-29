# Project status

Where NetSentinel-AI stands against the locked plan (Research Comparison and 15-Day
Execution Plan v1.0), what remains, and why some planned tools are not running yet.
Updated 29 September 2026.

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
| Live lab on the cloud VM (27 Sep) | An nmap SYN scan of 1000 ports: 1000 flows, mean risk 0.937, 999 above 0.5, all alerted; benign flows mean 0.168, none above 0.5 | `docs/testing/TEST_REPORT.md` |
| JA4 on live traffic | A TLS exchange on the lab bridge fingerprinted by Suricata and Zeek; Zeek's JA4 stored in ClickHouse | same |
| Tier D on the lab's own traffic | The 11-12% of benign lab flows that alerted before the TCP teardown fix were all one-packet phantoms; after it, 0 of 28,738 benign flows alert with any Tier D card. Re-baselined on 21,631 post-fix flows (29 Sep): 0.84-0.89% flagged alone on 7,107 held-out ones; not promoted, since either would lose SSH brute-force (and, for the autoencoder, DNS tunnel) flows the fused rule catches today; in shadow | `docs/testing/TEST_REPORT.md`, section 9 |
| Automated tests | 1,064 Python + 155 dashboard, all passing (coverage 82% when last measured, 24 Sep) | `uv run pytest`, `npx vitest run` |

## Planned tools: built, running, or not

The plan splits the system across a 16 GB cloud VM (always-on services), Kaggle (training)
and the laptop (dashboard, LLM). **The VM ran on 27 September**, on 8 GB rather than 16:
Azure for Students offered no 16 GB size. Measured there, everything but MISP and
Greenbone runs at once in 5.2 GB, and those two take turns (`infra/README.md`, "Why
profiles"). The live runs found eighteen defects that the tests against fakes had not,
all fixed (`docs/testing/TEST_REPORT.md`). Nothing below was dropped from the design.

| Planned | In the plan as | Status | Why |
|---|---|---|---|
| Suricata 8 + Zeek + JA4 (F1, F2) | Always-on on the VM | **Running** on the VM's lab bridge: ET Open, JA4 from both, into ClickHouse through Vector | |
| Wazuh 4.14 + Sysmon + auditd (F3) | Always-on on the VM | **Running**: indexer, manager and dashboard; the VM's agent with auditd sent 299 host alerts in its first minutes | Sysmon on the laptop is not enrolled yet (it reaches the manager through the tunnel) |
| Redpanda (F5) | VM | **Running**: topics created by the init job; sensor, writer and sinks on it | |
| ClickHouse, Vector, Grafana (F5, F19) | VM | **Running**: all four tables filling live; Grafana's ClickHouse datasource healthy | |
| Sensor, scorers, writers as one pipeline (F10) | VM | **Running**: sensor (Tiers A, B, D, and the two lab-baselined Tier D cards in shadow), Tier C window scorer, detection writer, flow sinks, Suricata importer | |
| MISP, Keep (F13, F14) | VM, intel profile | **Run** in its window: Keep accepted forwarded alerts and de-duplicated them by fingerprint (28 Sep); MISP answers the API over the backplane | MISP's API key is made in its UI, so its sync has not run live |
| DFIR-IRIS (F15) | VM | **Running**: the API's case client opened a case on it (28 Sep) | |
| CrowdSec + nftables (F16) | VM | **Running**: a ban reached the kernel's nftables set and was lifted; the responder that executes approved actions is a service | |
| Wazuh Active Response (F16) | VM | **Run** (29 Sep): an approved process kill and account lock carried out on the VM's agent by the responder, and the lock undone | Isolation not run live: it would cut the SSH session driving the test |
| Greenbone/OpenVAS (F17) | VM, scan window | **Run** in its window (28 Sep): the lab scanned in 11 minutes, 44 results, none with a CVE; scan dates on the Estate page | Runs in its own window on the VM |
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
| 1 | Enrol the laptop's Wazuh agent with Sysmon through the SSH tunnel | F3 on Windows | The Wazuh agent installed on the laptop |

Done 29 September: the sensor on the VM runs the teardown fix, both lab Tier D cards were refitted
on the flows it produces, and the result was re-measured (`docs/testing/TEST_REPORT.md`, section 9).
Promoting them was weighed and declined on that evidence: it would cost detections and remove no
false alarm. They stay in shadow.

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

- For item 1: installing the Wazuh agent on the laptop (it needs administrator rights).
