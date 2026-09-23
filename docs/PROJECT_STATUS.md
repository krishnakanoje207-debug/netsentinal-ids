# Project status

Where NetSentinel-AI stands against the locked plan (Research Comparison and 15-Day
Execution Plan v1.0), what remains, and why some planned tools are not running yet.

## Measured today

| What | Result | Evidence |
|---|---|---|
| Tier A (LightGBM), temporal test split | PR-AUC 1.0000, precision 0.995, recall 1.000, FPR 0.05% | `docs/evaluation/REPORT.md` |
| M1 objective O3 (PR-AUC >= 0.90) | Met | same |
| Shortcut found and removed | TTL alone scores 0.998; excluded from the model | same, section 2 |
| Tier D (Isolation Forest, benign-only) | Recall 0.2% -> 40% after log-scaling | same, section 3 |
| Attack-family classification | macro-F1 0.52, accuracy 71% (attack flows only) | `artefacts/family/model_card.json` |
| MITRE technique on ML alerts | Claimed only at >= 70% confidence, for families right >= 85% of the time on validation: Reconnaissance (T1046), Exploits (T1190), DoS (T1499). On the test split 55% of attacks get a label and 85% of labels are right. On the family-balanced demo replay, which over-represents the hard rare families, 21 of 31 labels were right (68%) and 104 alerts got none | same |
| Cross-dataset (trained on UNSW) | 0.74 on ToN-IoT, 0.05 on CIC-IDS2018 | same, section 5 |
| Latency per flow (NFR-01, <= 5 ms) | 0.07 ms | same, section 6 |
| Replay of unseen flows through the real pipeline | 135/135 attacks alerted, 0/400 false alarms | `lab/replay` |
| Tier C (E-GraphSAGE), 20k-flow windows | PR-AUC 0.994, recall 0.988, precision 0.874 | `artefacts/tier_c/model_card.json` |
| Held-out attacker (never seen in training) | Tier A PR-AUC >= 0.9999, Tier C 0.978-0.996 | `docs/evaluation/holdout/REPORT.md` |
| Load: 25 concurrent analysts | 683 requests, 0 failures, feed p95 47 ms | `docs/testing/TEST_REPORT.md` |
| Security scans | bandit (1 real issue, fixed), pip-audit and npm audit: 0 known vulnerabilities | same |
| Automated tests | 703 Python (81% coverage) + 94 dashboard, all passing | `uv run pytest`, `npx vitest run` |

## Planned tools: built, running, or not

The plan splits the system across a 16 GB cloud VM (always-on services), Kaggle (training)
and the laptop (dashboard, LLM). **The cloud VM was never provisioned**, and this laptop has
8 GB of RAM, so every service that needs Linux packet capture or several GB of memory is
built and tested but not running. Nothing below was dropped from the design.

| Planned | In the plan as | Status | Why |
|---|---|---|---|
| Wazuh 4.14 + Sysmon (host IDS, F3) | Always-on on the VM | **Not deployed** | Needs 3 GB+ and its own indexer; installed from its official images on the VM. The Wazuh Active Response client (the block path) is built and tested |
| Apache Kafka | **Fallback** only | Not used, by design | The plan locks **Redpanda** (Kafka API, lighter). Redpanda is in `docker-compose` (profile `bus`) and the sensor/writer speak the Kafka protocol; not run locally |
| Apache Flink | **Out of scope for v1.0** | Not built, by design | Listed as future work in the plan (section 9.2); the Python scorer does the streaming |
| NVIDIA Triton | Dropped in rev. 1 | Not used, by design | Replaced by in-process ONNX Runtime (0.07 ms per flow, no GPU server) |
| NVIDIA GPU | Kaggle training, LLM on the GTX 1650 | Not needed yet | Tier A and D are trees and trained on the laptop CPU in minutes; Tiers B/C need the GPU |
| Hugging Face | Not in the plan | Used for data only | Public mirror of the NF-v3 datasets (the UQ portal needs a web form) |
| Suricata 8 + Zeek + JA4 (F1, F2) | Always-on on the VM | Configured, not running | In `docker-compose` (profile `sensors`); need a Linux host to capture |
| ClickHouse, Vector, Grafana (F5, F19) | VM | Configured, not running | In `docker-compose`; the demo uses PostgreSQL only |
| MISP, Keep (F13, F14) | VM, intel profile | Integration built and tested against fakes | MISP needs ~4 GB |
| DFIR-IRIS (F15) | VM | Integration built and tested against fakes | Escalation says so honestly when unconfigured |
| CrowdSec + nftables (F16) | VM | Integration built and tested against fakes | Needs a Linux edge |
| Greenbone/OpenVAS (F17) | VM, scan window | Importer built and tested | Runs in its own window on the VM |
| Ollama Copilot (F20) | Laptop GPU | **Running**: llama3.2:3b on the GTX 1650; summaries on the alert page | Replies that invent a measurement are rejected |
| Tier B, 1D-CNN + BiLSTM (F7) | Kaggle | Code + tests; **not trained** | Needs packet captures (SPLT); NetFlow datasets have none |
| Tier C, E-GraphSAGE (F8) | Kaggle | **Trained on the laptop CPU** (20k-flow windows) and evaluated | Not yet in the live scoring path: it scores windows, not single flows |
| Tier D autoencoder (F9) | Kaggle | Not built | Isolation Forest half is done |

## Remaining work, in order

Estimates are my working time. How many sessions that is depends on your plan's limits,
which I cannot see; as a reference, everything in the "Measured today" table plus the
dashboard redesign was one long session.

| # | Task | For | Estimate |
|---|---|---|---|
| 1 | ~~MITRE technique on ML alerts~~ | Done | |
| 2 | ~~Train and evaluate Tier C~~ | Done | |
| 3 | ~~Copilot live with a summary panel~~ | Done | |
| 4 | ~~Test report~~ (`docs/testing/TEST_REPORT.md`) | Done | |
| 5 | One-command deployment (API + dashboard + DB in Compose) and user manual | M5 | 3-4 h |
| 6 | Final report (SRS, design, implementation, testing) and slides | M5 | 4-6 h |
| 7 | Cloud VM with Suricata/Zeek/Wazuh live (needs your Azure for Students account) | Full plan | 6-8 h, plus your account setup |
| 8 | Tier B with packet captures (large download) | Full plan | 4-6 h |

Items 1-6 fit the 7-day window. Items 7-8 depend on a cloud VM and are the honest
"future work" if the window closes first.

## What I need from you

- **Nothing for items 1-6.**
- For item 7: an Azure for Students (or other) VM, or a decision to present the VM-bound
  services as future work.
- Your M3/M4/M5 report template, if your college has a fixed one; otherwise the
  M1/M2 style is reused.
