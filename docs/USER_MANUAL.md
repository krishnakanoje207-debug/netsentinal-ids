# NetSentinel-AI user manual

NetSentinel-AI watches network traffic, uses AI models to decide which connections look
like attacks, explains each decision, and lets people decide what to do about it.
Nothing is blocked without a person approving it.

Part 1 is for everyone who uses the dashboard. Part 2 is for whoever installs it.

---

## Part 1: Using the dashboard

### Signing in

Open the dashboard address you were given (for the demo on this laptop,
http://127.0.0.1:5173; with Docker, https://127.0.0.1:5180) and sign in. What you can do
depends on your account's role, and the Overview page tells you in one line under its
headline. Pages your role cannot use are not shown.

The first time you sign in, a card offers a guided tour ("New here? Follow the line").
It points at the real screen, one part at a time, and works with the keyboard (arrow
keys to move, Escape to leave). Take it again at any time from the **Tour** sign at the
top. The **Day** / **Night** sign beside it switches between the light and dark look, and
your browser remembers the choice.

### Is it live?

The station clock at the top right answers that. Its red second hand sweeps while the
dashboard is connected to the live alert feed, and the word beside it says **Live**. If
the connection drops, the hand stops at twelve and the header says **Feed stopped**; the
dashboard reconnects on its own and still refreshes every few seconds meanwhile. Hover
the clock to see how long the feed has been connected and when the last alert arrived.

Anything with more to say shows it when you hover it or move to it with the Tab key:
alert rows, counts, severities and the steps of "How NetSentinel works".

| Role | For | Can |
|---|---|---|
| **Viewer** | managers, host owners, anyone who needs to know | read everything; change nothing |
| **Security analyst** | the people who work the alerts | confirm or dismiss alerts, escalate them, approve or reject blocks |
| **Administrator** | whoever runs the system | propose blocks; cannot approve any block |
| **ML engineer** | whoever looks after the models | see how models perform, promote a new one |

No account can both propose a block and approve it. That is deliberate: one person should
never be able to cut a machine off the network alone.

### Overview

The first page. It opens with one sentence saying how things stand: how many threats were
detected, how many are critical, how many are still open, and how many blocks are waiting
for a decision. The numbers are flip digits that turn only when a count really changes;
click one to see the alerts behind it. Below it:

- **Threats by severity.** Click a severity to see those alerts. Severity combines how
  sure the models are with how much harm the attack could do: a near-certain exploit or
  denial of service is **critical**, a near-certain attack of unknown kind is **high**, and
  a near-certain port scan, which has done no harm yet, is **medium**. Hover a severity to
  read what it means.
- **Latest alerts.** A departures board of the newest alerts; a new one turns over onto it
  as it arrives. Hover a row to see why it was flagged; click it to open the alert. The
  thin line under the board's title fills while it waits for the next refresh, and if the
  data stops refreshing the board fades and says so.
- **The last hour, minute by minute.** One column per minute: alerts raised hang below the
  line, and flows checked rise above it when the flow store is running. When it is not,
  the strip says the flow count is unavailable rather than showing a quiet network.
  Hover a column, or focus the strip and use the arrow keys, to read one minute.
- **How NetSentinel works.** The four steps: watch, score, explain, decide. Hover a step
  to see what is happening there now.
- **Waiting for a decision.** Blocks proposed but not yet approved.
- **Addresses raising the most alerts.** Click an address to see its alerts.
- **Detectors on duty.** Which AI models are deciding, and which are only watching.

### Alerts

Every connection the models flagged, newest first, on the same board as the overview.
New alerts appear on their own. Fifty are shown at first; **Show older alerts** at the
bottom loads the next fifty.

- **Search** takes an address (`175.45.176.0`), a network (`175.45.176.0/24`) or an attack
  technique (`T1046`). Anything else gets a message saying what would work.
- **Filters** narrow by status or severity.
- **Export CSV** saves exactly what you are looking at, filters included.

### One alert

Open an alert by clicking its row.

1. **The sentence at the top** says what happened: who connected to whom, how likely the
   models think it is an attack, and what stood out most. Under it, a line shows how far
   the alert has come: seen, scored, explained, and decided (by a person).
2. **The details box** gives severity, status, both addresses and, when the model is sure
   enough, the **attack technique** from MITRE ATT&CK with its name. When there is none,
   it says why.
3. **Why this was flagged** is a chart of the measurements that mattered, drawn as a tug of
   war. Red bars made the connection look more like an attack, blue bars more normal;
   longer bars mattered more. Below it, each model's own score; a model marked
   *watching only* is in shadow mode and did not decide.
4. **AI summary** is a short write-up by a language model running on the same machine. It
   can be wrong; the evidence above it is what counts. Summaries that state things the
   evidence does not contain are thrown away before they reach this page.
5. **What you can do** shows only the actions your role allows:
   - *I'm looking at it*, *Confirm attack*, *False alarm*, *Reopen*: record your judgement.
     Confirmed and dismissed alerts are how the models are measured.
   - *Escalate to incident*: opens an incident so the investigation has an owner.
   - *Propose blocking* (administrators): asks for the source address to be blocked. It
     goes to the Approvals page and nothing happens until an analyst approves.

### Approvals

Blocks waiting for a decision. Read the linked alert, then **Approve** or **Reject**.
A rejection needs a comment saying why, so the next person knows. Approving authorises
the block; a separate response worker carries it out, and the block lifts on its own
after a few hours.

### Estate

The machines being protected, from the asset inventory, with how much each matters
(criticality) and the known weaknesses (CVEs) a Greenbone vulnerability scan reported on
it, worst first. Click a host's findings to list them; **Alerts involving it** opens the
alerts that name its address. A host a scan covered shows the date of its last scan, and
"Nothing found in the last scan" if the scan reported no CVE; that is what the scan could
check on that date, not a guarantee. A host no scan has covered says "Not yet scanned".
Blocks aimed at these addresses are refused, because a machine of your own is isolated
rather than blocked.

### Models

For the ML engineer, and readable by everyone. Each AI model, whether it is **active**
(deciding) or in **shadow** (watching and being measured only), its alert threshold, and
how its alerts were judged by analysts. A shadow model can be promoted only when enough
alerts have been reviewed; if the button is disabled, the reason is written under it.

### When something looks wrong

| You see | It means |
|---|---|
| The clock's red hand has stopped and the header says "Feed stopped" | the dashboard lost its live connection; it reconnects on its own and still refreshes every few seconds |
| A board or strip looks faded and says "Not updated since ..." | its data has missed several refreshes; the API may be down |
| "No AI summary has been written for this alert yet" | the Copilot has not been run for it, or its reply was rejected |
| A red message after clicking an action | the action was refused; the message says why (for example, your role cannot do it) |
| The sign-in page shows a connection error | the API is not running; see Part 2 |

---

## Part 2: Installing and running

### One-command deployment (Docker)

Needs Docker with Compose. From the repository:

```bash
cp infra/.env.example infra/.env     # then fill in every value
docker compose -f infra/docker-compose.yml --profile app up -d --build
docker compose -f infra/docker-compose.yml logs api    # the first start prints the admin password once
```

The dashboard is then at https://127.0.0.1:5180 and the API documentation at
http://127.0.0.1:8010/api/v1/docs. Everything listens on localhost only; reach a remote
server through an SSH tunnel.

The dashboard serves HTTPS with a self-signed certificate that is generated when its
image is built, so no key is kept in the repository. The browser warns about it once;
accept it for this address. A plain http:// request to the same port is redirected to
https://. For a server with a real host name, replace the certificate with one from a
certificate authority.

### The offline demonstration (Windows laptop)

```powershell
powershell -ExecutionPolicy Bypass -File lab\replay\build_demo.ps1   # once: builds the demo database
powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1   # each time: starts everything
```

`build_demo.ps1` replays flows from the dataset's unseen test period through the real
models and writes them as alerts, with explanations and techniques. Accounts and
passwords are written to `lab\replay\out\demo_credentials.txt`.

On a laptop without the memory for Docker, add `-Native` to both commands. PostgreSQL
then runs from binaries on the host (by default `D:\netsentinel-data\pgsql\bin`, with
its data in `D:\netsentinel-data\pgdata`; set `NETSENTINEL_PG_BIN` and
`NETSENTINEL_PG_DATA` to use others), and the dashboard is at http://127.0.0.1:5173.

To show alerts arriving live, give the build an interval in seconds between flows:
`build_demo.ps1 -Native -Interval 1` writes the 535 replayed flows over about nine
minutes, so an open dashboard fills up as you watch.

### The live pipeline on the cloud VM

The whole detection path, with the host sensors, response, dashboards and case
management, runs on an 8 GB cloud VM; the threat-intelligence and vulnerability-scan
services take turns there. Setting it up is in `docs/CLOUD_VM.md`, and what each part
costs in memory is in `infra/README.md`.

Only SSH is open on the VM. Open the tunnel from `docs/CLOUD_VM.md` (step 7) on the
laptop, then use:

| On the laptop | What |
|---|---|
| https://127.0.0.1:5180 | the NetSentinel dashboard |
| http://127.0.0.1:8010/api/v1/docs | the API |
| http://127.0.0.1:3000 | Grafana |
| https://127.0.0.1:5601 | the Wazuh dashboard |
| https://127.0.0.1:8443 | DFIR-IRIS |

To see an attack arrive, run a port scan from the lab's attacker. On the VM, in
`~/netsentinel/infra`:

```bash
docker compose exec attacker nmap -sS -p 1-1000 172.30.0.10
```

The scan's flows appear as alerts on the dashboard as they are scored, and the last-hour
strip shows flow counts, because the flow store is running there.

On the VM the anomaly detectors run twice: the versions calibrated on the benchmark
datasets, and versions re-baselined on the lab's own normal traffic, which watch in
shadow. The ML engineer promotes a re-baselined version from the **Models** page, or
with `netsentinel-shadow-report`, once enough alerts have been reviewed.

### The estate

The asset inventory is a CSV with the columns `hostname,ip_address,os,criticality`
(criticality is `low`, `medium` or `high`; blank means medium):

```bash
uv run netsentinel-import-assets --csv inventory.csv
```

Hosts are matched by address, so re-importing an edited file updates them, and a host
left out of a later file is kept. The whole file is refused if any line is wrong, with
the line number. Scan findings are then imported with `netsentinel-import-vulns`.

### AI summaries

The Copilot runs on the machine with the GPU, never inside the API:

```bash
ollama pull llama3.2:3b
uv run netsentinel-copilot --latest 10     # the ten newest alerts without a summary
uv run netsentinel-copilot --alert 134     # one alert
```

### Retraining the models

See the README ("Pipeline") and `docs/evaluation/REPORT.md` for how each model was
trained and measured. Every model starts in shadow mode and has to be promoted. The
offline demonstration is the exception: `build_demo.ps1` registers Tiers A and D as
active directly, without the shadow period.
