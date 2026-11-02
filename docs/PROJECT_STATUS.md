# Project status

Where NetSentinel-AI stands against the locked plan (Research Comparison and 15-Day
Execution Plan v1.0), what remains, and why some planned tools are not running yet.
Updated 2 November 2026.

## Hosted deployment preparation and counter restoration — 2 November

The API supports Render PostgreSQL URLs and an explicit dashboard CORS origin
list. The frontend supports a separate HTTPS API origin for both requests and its
direct secure WebSocket feed. `render.yaml` defines the API and database, and
`frontend/vercel.json` enables dashboard deep links. Operational instructions and
the separation between cloud data and local Windows evidence are in
[hosted deployment](HOSTED_DEPLOYMENT.md). The Vercel frontend reached READY at
`https://frontend-pi-eight-gvw406z5rs.vercel.app`. Its API origin is now
`https://netsentinel-api-15ig.onrender.com`. The Render API and private PostgreSQL
database are live. Administrator sign-in, reads, CSV/PDF exports, explicit CORS,
and the authenticated secure WebSocket passed hosted verification.

### Windows host telemetry — verified 2 November

Sysmon64 and SysmonDrv are running, with the Operational channel enabled. The
initial installation used default rules with network connections disabled. The
project configuration is now applied. A benign PowerShell connection to the
project's Render host produced Event 1 (process create, record 50660) and Event 3
(network connection, record 50738), both for process 13940. Loopback connections
are deliberately excluded by these rules.

The installed Wazuh agent now has exactly one Sysmon `eventchannel` input. Its
unconfigured `0.0.0.0` manager address was replaced with the project's local
`127.0.0.1` endpoint, and its original configuration was backed up. The launcher
reuses installed services and preserves trailing XML comments. Eight Windows
launcher tests passed, including repeat configuration and missing-manager checks.
The agent remains stopped and unenrolled until a manager is reachable.

Docker Desktop was migrated from C: to `D:\DockerDesktop` and updated to 4.97.0.
Engine 29.9.2 and the WSL registration at `D:\DockerData\main` are verified.
The preserved D: data disk restored the existing containers. Both the fresh C:
disk and older D: disk were backed up and SHA-256 verified under
`D:\DockerMigration\backup-20261102` before reinstalling. Installation/staging
also used D:, and C: free space increased to approximately 10 GB. Windows keeps
small installation metadata and integration files on C:. Local Wazuh manager
ingestion remains pending the staged service startup.

Verification passed 697 API/Windows launcher tests. The frontend run passed 173
of 174 tests, with the alert paging test reporting `Error: Test timed out in
5000ms.` A focused single-worker rerun passed all 14 tests covering alert paging,
hosted requests/exports and WebSocket routing. The production build and lint
passed; lint retains the existing warnings.

The temporary native capture test processed 8,343 packet observations and 57 flow
records; the writer stored 46 detections and 23 alerts. These model verdicts are
review items, not confirmed intrusions. The test used the finite `netsentinel_mypc`
database. After the test, elevated `pktmon status` verified the original state:
Counters, All packets, All components, No filters. No continuous NetSentinel watch
was left running by this test.

## Current scope: local real traffic

Run this computer's actual traffic through the existing sensor, trained models,
writer and dashboard. Azure and the historical VM are optional; restoring their
connectivity is not a prerequisite for the local work. A successful dataset replay
does not establish that packet capture works on this computer.

### Resident monitoring and This PC page

The current local version includes a **This PC** page at `/condition`, an
authenticated endpoint snapshot, and an administrator-only local browser audit.
The page polls Windows protection/capture evidence every 10 seconds and recorded
browser activity every 30 seconds. Nested evidence is displayed as labeled values,
including Yes/No/Unknown, rather than raw JSON. Snapshot freshness and capture
freshness are separate from dashboard refresh time.

On 1 November at approximately 20:05 IST, verification through the dashboard on
`http://127.0.0.1:5173` found a running monitor, fresh endpoint evidence, and advancing
scored-flow/alert timestamps in `netsentinel_live`. Browser metadata was readable
from eight profiles for the local administrator; viewer access returned HTTP 403.
Defender reported real-time and downloaded-file protection enabled, zero active
threats, and three historical detections. Both configured Downloads-folder scans
and the Defender quick scan completed earlier that day. Historical detections are
not findings attributable to those scans, and completion is not a clean bill of
health. Model alerts remain unconfirmed review items.

The resident watcher is independent of dashboard/browser windows. Its Windows
sign-in task requests packet-capture consent when a new watch starts. Power-off,
sign-out, and sleep leave observation gaps; reboot and actual sleep/wake recovery
have not been tested. The browser audit checks bounded recorded activity against
a limited local phishing feed after a visit. Native Windows/browser protections
handle real-time file scanning and pre-download warnings. This version does not
intercept every URL or inspect encrypted page/download contents.

See [resident monitor](RESIDENT_MONITOR.md), [endpoint checks](ENDPOINT_CHECKS.md),
and [browser audit scope](local-browser-audit.md) for operation and limits.

Read-only inventory on 31 October found:

| Component | Local state |
|---|---|
| Windows and memory | Windows 11 Home Single Language; 7.35 GB usable RAM, 0.79 GB free at the check |
| Free disk | C: 4.95 GB; D: 113.30 GB; keep large caches and data on D: |
| Python/runtime | Workspace `.venv` uses Python 3.11.15; uv, ONNX Runtime, LightGBM, dpkt, FastAPI, psycopg and CPU PyTorch installed |
| Frontend | Node 24.13.1 and `frontend/node_modules` present |
| Native services | PostgreSQL on 127.0.0.1:5433, API on 127.0.0.1:8010 and dashboard on 127.0.0.1:5173 |
| Packet capture | Windows pktmon installed; real capture requires an elevated process |
| Trained models | Tier A, B, C, both Tier D models, both lab-baselined Tier D models and family classifier present; ONNX/native hashes match their model cards |
| Docker/Linux | Desktop/CLI and WSL2 installed; `docker-desktop` distro and Docker service stopped, Linux engine pipe unavailable |
| Windows host monitoring | Wazuh agent installed, `WazuhSvc` stopped; Sysmon service absent; no local Wazuh manager listener |

No model training or Python package installation is needed to start the native
network-monitoring path. The system `python` points to Python 3.14; use `uv run
--no-sync` or `.venv\Scripts\python.exe` for this workspace. The full Docker stack
does not fit the current free memory: the Wazuh profile alone budgets 3 GB, before
Docker's VM and the other services. Keep the native path first; add local Linux
services in stages after freeing memory or increasing RAM.

Additional offline inventory verified on 1 November: all six `llama3.2:3b` blobs
under `D:\blobs`, with the manifest under `D:\manifests`, passed hash checks.
The active Ollama store lacks the manifest, the Ollama installer is already on
disk, and an installed Ollama runtime was not located. The valid `Sysmon.zip`
and `wazuh-agent-4.14.8-1.msi` are already in Downloads. These packages do not
need downloading again. Installing/configuring Ollama is optional for alert
summaries; installing Sysmon and enrolling the existing Wazuh agent are optional
host monitoring work after a manager is available.

The broader Linux deployment uses existing Compose definitions: storage and
pipeline services (PostgreSQL, Redpanda, ClickHouse, Vector, Grafana and the
sensor/scorers/writers), Suricata/Zeek sensors, Wazuh manager/indexer/dashboard,
DFIR-IRIS and response services, plus the optional intel profile (MISP/Keep) and
scan profile (Greenbone). Cached local installers or model files do not replace
the required container images. Pull only the profiles being enabled, after
Docker starts and enough RAM/disk is available. The native watch needs none of
these additional container downloads.

The native watch scores IPv4 packet flows with Tiers A, B and D; it does not run
the separate Tier C window scorer, Suricata or Zeek. TLS payloads remain encrypted.
The benchmark-trained models can flag ordinary local HTTPS as anomalous, so an
alert is a model verdict requiring review, not proof of an intrusion. pktmon's
window restarts also leave short capture gaps.

Wazuh/Sysmon is a separate host-monitoring extension. Sysmon supplies process and
connection events; the Wazuh agent also needs a running manager. The existing
`lab/local/enrol_wazuh_agent.ps1` targets 127.0.0.1 ports 1514/1515 and documents a
historical SSH tunnel. Do not treat installing that agent alone as a working local
Wazuh deployment. The manager must run locally first for a local-only setup.

Start continuous monitoring from the repository with
`powershell -ExecutionPolicy Bypass -File lab\local\watch_this_pc.ps1`, or use
`lab\replay\start_demo.ps1` without options. Both now select real live capture.
The launcher starts native PostgreSQL if needed, preserves the dedicated
`netsentinel_live` database, and writes accounts to
`lab\local\out\live\credentials.txt`. Approve the pktmon elevation prompt and
leave the launcher open; Ctrl+C stops capture and drains pending flows. See
`docs/USER_MANUAL.md`, Part 2, for dashboard-only and explicit replay commands.

On 1 November the real capture started and accounts in the separate
`netsentinel_live` database passed administrator and viewer login checks. The first
Wi-Fi NIC capture yielded native encrypted 802.11 frames, which the Ethernet IPv4
extractor correctly skipped. Capture now includes all Windows stack components so
usable Ethernet frames above Wi-Fi can reach the existing duplicate filter. The
corrected live run produced 76 scored flows with Tiers A, B and D, including 56
model alerts; 33 alerts were already readable through the API during verification.
A diagnostic window contained 474 parseable IPv4 frames;
the temporary diagnostic copy was deleted after inspection. The active dashboard
is `http://127.0.0.1:5174` and its API is `http://127.0.0.1:8011`; the earlier
dashboard/API on 5173/8010 were stopped after verifying their process commands.
Administrator access to
`/api/v1/admin/users` returned 200, while viewer access returned 403.

The launcher writes startup progress to `lab/local/out/watch-startup.log` when run
in the background. To stop a background watch gracefully, find its newest run and
request capture shutdown; the sensor and writer then drain before exiting:

```powershell
$run = Get-ChildItem lab/local/out/live -Directory |
    Where-Object Name -Match '^\d{8}-\d{6}-\d{3}$' |
    Sort-Object Name -Descending | Select-Object -First 1
if ($run) { Set-Content -LiteralPath (Join-Path $run.FullName 'windows/stop-request') -Value '' }
```

Completed ETL files are removed after conversion, and the sensor removes PCAPNG
windows after reading them. Scored flow JSON, alerts and local credentials persist
under the ignored output directory/database and should be treated as sensitive.

## Verified 31 October 2026

On 1 November 2026, final local verification passed 1,119 Python tests plus 6
Windows launcher tests, 167 dashboard tests, the production build, all 14 Compose
profile configurations, and the CI security gates. Python and npm dependency
audits reported no known vulnerabilities; lint passed with 29 existing warnings.

The native demo is at database revision `0008`, with 135 alerts. A real viewer login
and alert fetch succeeded; the API and dashboard both returned HTTP 200. The local
checks passed: 1,107 Python tests, 165 dashboard tests, and the dashboard build. Lint
completed with 28 warnings.

The 3 October GitHub Actions run `37138097970` for HEAD
`1becbd0` failed its security check on pip-audit's PyJWT finding. The 31 October npm
audit initially reported 3 moderate and 3 high vulnerabilities. After dependency
updates, the local CI-equivalent Python audit and npm audit both reported no known
vulnerabilities, and `uv lock --check` passed. The lock now includes PyJWT 2.15.1,
certifi 2026.10.23 and Pillow 13.0.0. Hosted CI still needs a push and a fresh run;
the earlier failed run is not evidence that these changes passed remotely.

VM SSH timed out on 31 October, so its services and the sensor fix could not be
rechecked. The Docker daemon was unavailable, so the Docker demo could not be refreshed
or verified. The native demo checks do not establish either deployment's current state.

## Historical measurements (September 2026)

The measurements below preserve the September evidence. Unless repeated above, they
have not been re-measured on 31 October; references to active models and running
services describe the deployment at the time of those measurements.

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
| Security scans (24 Sep; historical) | bandit (1 real issue, fixed), pip-audit and npm audit: 0 known vulnerabilities then; see the 31 Oct audit results above | same |
| Live lab on the cloud VM (27 Sep) | An nmap SYN scan of 1000 ports: 1000 flows, mean risk 0.937, 999 above 0.5, all alerted; benign flows mean 0.168, none above 0.5 | `docs/testing/TEST_REPORT.md` |
| JA4 on live traffic | A TLS exchange on the lab bridge fingerprinted by Suricata and Zeek; Zeek's JA4 stored in ClickHouse | same |
| Tier D on the lab's own traffic | The 11-12% of benign lab flows that alerted before the TCP teardown fix were all one-packet phantoms; after it, 0 of 28,738 benign flows alert with any Tier D card. Re-baselined on 21,631 post-fix flows (29 Sep): 0.84-0.89% flagged alone on 7,107 held-out ones; not promoted, since either would lose SSH brute-force (and, for the autoencoder, DNS tunnel) flows the fused rule catches today; in shadow | `docs/testing/TEST_REPORT.md`, section 9 |
| Automated tests | 1,107 Python + 165 dashboard, all passing (coverage 82% when last measured, 24 Sep) | `uv run pytest`, `npx vitest run` |

## Planned tools: September deployment evidence

The plan splits the system across a 16 GB cloud VM (always-on services), Kaggle (training)
and the laptop (dashboard, LLM). **The VM ran on 27 September**, on 8 GB rather than 16:
Azure for Students offered no 16 GB size. Measured there, everything but MISP and
Greenbone runs at once in 5.2 GB, and those two take turns (`infra/README.md`, "Why
profiles"). The live runs found twenty defects that the tests against fakes had not,
all fixed (`docs/testing/TEST_REPORT.md`). Nothing below was dropped from the design.
The table records those historical runs; the VM's current state was not verified on
31 October because SSH timed out.

| Planned | In the plan as | Status | Why |
|---|---|---|---|
| Suricata 8 + Zeek + JA4 (F1, F2) | Always-on on the VM | **Running** on the VM's lab bridge: ET Open, JA4 from both, into ClickHouse through Vector | |
| Wazuh 4.14 + Sysmon + auditd (F3) | Always-on on the VM | **Running**: indexer, manager and dashboard; the VM's agent with auditd sent 299 host alerts in its first minutes | Sysmon on the laptop is not enrolled yet (it reaches the manager through the tunnel) |
| Redpanda (F5) | VM | **Running**: topics created by the init job; sensor, writer and sinks on it | |
| ClickHouse, Vector, Grafana (F5, F19) | VM | **Running**: all four tables filling live; Grafana's ClickHouse datasource healthy | |
| Sensor, scorers, writers as one pipeline (F10) | VM | **Running**: sensor (Tiers A, B, D, and the two lab-baselined Tier D cards in shadow), Tier C window scorer, detection writer, flow sinks, Suricata importer | |
| MISP, Keep (F13, F14) | VM, intel profile | **Run** in its window: Keep accepted forwarded alerts and de-duplicated them by fingerprint (28 Sep); MISP synced abuse.ch's Feodo Tracker C2 list and 300 alerts from a replayed scan out of one of its addresses were linked to it (29 Sep) | Takes turns with Greenbone on the 8 GB VM |
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
| CI (GitHub Actions) | Not in the plan | Configured on every push to the private repository `netsentinal-ids`: per-package tests, frontend tests and build, bandit, pip-audit, npm audit, Compose validation | Historically green from 26 Sep; run `37138097970` (3 Oct, HEAD `1becbd0`) failed the PyJWT security check; updated dependencies pass local audits, pending a fresh hosted run |
| Apache Kafka | **Fallback** only | Not used, by design | The plan locks Redpanda (Kafka API, lighter) |
| Apache Flink | **Out of scope for v1.0** | Not built, by design | Future work in the plan (section 9.2); the Python scorer does the streaming |
| NVIDIA Triton | Dropped in rev. 1 | Not used, by design | In-process ONNX Runtime: 0.07 ms per flow, no GPU server |

## The dashboard

Rebuilt on 25 September to the owner's brief: a station information system, light by
default with a night mode, a station clock whose second hand runs only while the live feed
is connected, split-flap counts, a departures board of alerts, hover and focus detail
everywhere, a last-hour strip drawn to scale, and a 14-stop guided tour. Reviewed on 26
September against the real API and database rather than fixtures; the review found and
fixed: the live feed never pushing, the feed stopping at 50 alerts, shadow models shown by
their raw identifiers, alert counts drawn almost flat in the last-hour strip, and faint
night-mode tiles. The Estate page (hosts and their scan findings) was added the same day.

## Remaining work

| # | Task | For | Needs |
|---|---|---|---|
| 1 | Continue observing real local traffic and review model verdicts; live pktmon capture and scored flows were verified on 1 November | Continuous local capture | Keep the watch launcher running; administrator/UAC approval is needed on restart |
| 2 | Repair Docker startup, add local Wazuh manager/indexer/dashboard, then enrol the prepared Windows agent; Sysmon process/network events are verified | F3 on Windows | Working Docker/Linux engine, sufficient RAM and local ports 1514/1515 |
| 3 | Add local Suricata/Zeek and the remaining Linux pipeline services in stages | Broader local monitoring | A running Docker/Linux environment, capture access and sufficient RAM |
| 4 | Confirm the dependency updates in a fresh hosted CI run; local Python and npm audits pass | Dependency security | A push and a new GitHub Actions run; optional for local monitoring |
| 5 | Refresh and verify the Docker demo with `lab/replay/start_demo.ps1` (without `-Native`), if wanted | Optional replay demo on :5180 | A running Docker daemon and enough RAM; last recorded images were 23-24 Sep and its database was at revision `0005` |

The historical VM sensor update (`6becd1e`) and its restart measurements remain
unverified remotely. They are outside the current local-only path.

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
matches still raise a severity by one step, and so does a Suricata signature between the
same two addresses within 150 s (29 September; `docs/testing/TEST_REPORT.md`, section 14).

## Local access needed

- Real pktmon capture and Sysmon/Wazuh service installation require Windows
  administrator elevation.
- Docker/Linux services need additional free memory before the broader local stack
  can run. No Azure account or SSH tunnel is required for local monitoring.
