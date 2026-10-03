# Demo video script (about 8 minutes)

A scene-by-scene script for recording the NetSentinel-AI demonstration. Each scene
says what is on screen, what to click, and what to say. Everything shown is the
offline demonstration described in `docs/USER_MANUAL.md` (Part 2): real trained
models scoring flows replayed from the unseen test window of NF-UNSW-NB15-v3. A
shorter live version on the cloud VM follows the script ("The live VM").

Addresses:

- Dashboard: http://127.0.0.1:5173 (`start_demo.ps1 -Native` or `-Dev`), or
  https://127.0.0.1:5180 with the Docker default
- API and its interactive docs: http://127.0.0.1:8010/api/v1/docs
- Accounts: `admin`, `analyst`, `modeller`, `viewer`; passwords in
  `lab\replay\out\demo_credentials.txt`

Counts quoted below (135 alerts: 11 critical, 110 high, 13 medium, 1 low; 24 with a
MITRE technique; attackers 175.45.176.0-3) are the ones the current demo database produced. Read the real numbers
off the screen if a rebuild changes them.

## Pre-recording checklist

- [ ] Start the stack. On this laptop, without Docker:
      `powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1 -Native`
      (PostgreSQL, the API and the dashboard, about 400 MB). With Docker running, drop
      `-Native`. Wait for "Dashboard ..." and nothing else on ports 5173, 8010 or 5433.
- [ ] Build the database with the alerts arriving live, so the board fills on camera:
      `powershell -ExecutionPolicy Bypass -File lab\replay\build_demo.ps1 -Native -Interval 1`.
      Accounts are written before the alerts start (read the new passwords then); the
      535 flows then take about nine minutes, one alert every four seconds on average.
      Start it at the beginning of scene 2. Drop `-Interval` for a database filled at once.
- [ ] AI summaries for a few alerts (the alert page otherwise says "No AI summary has
      been written for this alert yet"). With Ollama running and
      `NETSENTINEL_DATABASE_URL` set to the `.env.local` URL with the database name
      changed to `netsentinel_demo`: `ollama pull llama3.2:3b`, then
      `uv run netsentinel-copilot --latest 10`. Note one alert id that got a summary.
- [ ] Credentials file open on a second screen, not in the recording.
- [ ] Browser at 100% zoom, a clean profile, window about 1600 x 900. A second tab on
      the API docs page. Clear the site's storage once so the tour invitation shows.
- [ ] Notifications off; terminal font large enough to read in the video.
- [ ] One dry run of scene 8, then rebuild the database so the queue starts empty.

## Script

### Scene 1 (0:00 - 0:30): Introduction

**Screen:** title slide of `deliverables/Milestone_5_Presentation.pptx`, or the sign-in page.

**Say:** "This is NetSentinel-AI, an intrusion detection and security monitoring system
that uses machine learning. It scores network flows with trained models, explains
every alert, and never blocks anything without a person approving it. Everything in
this video is running locally on my laptop."

### Scene 2 (0:30 - 1:15): Starting it, and a live feed

**Screen:** a PowerShell window at the project root, then the browser.

**Do:** show `start_demo.ps1 -Native` (already run), then run
`build_demo.ps1 -Native -Interval 1`. When it prints "Posting alerts live", sign in as
`analyst`.

**Say:** "One command starts PostgreSQL, the FastAPI backend and the React dashboard.
The second rebuilds the demonstration: the flows are the last 15% of the dataset by
time, which no model was trained or tuned on, replayed through the real scorer and
writer, one every second, as if a sensor were capturing them."

**Do:** point at the station clock in the header.

**Say:** "The clock's red second hand only sweeps while the live feed is connected. If
the connection drops, it stops at twelve and the header says 'Feed stopped', because a
dead feed that looks calm is the most dangerous thing a console can show."

### Scene 3 (1:15 - 2:00): The guided tour

**Do:** on the "New here? Follow the line" invitation, click **Start the tour**. Step
through the first four stops (clock, headline, severity, board), then press Escape.

**Say:** "Someone who has never seen a security console gets a guided tour that points
at the real screen, not screenshots. It can be taken again from the Tour sign."

### Scene 4 (2:00 - 3:00): Overview

**Do:** pause on the headline while a count flips. Hover a row on the Latest alerts
board, then a severity row, then a stop on "How NetSentinel works".

**Say:** "The overview opens with one plain sentence. Severity means two things at once:
how sure the models are, and how much harm the attack could do - so a confident exploit is
critical, while an equally confident port scan is only medium. The numbers are split-flap digits
that turn only when the server returns a different number; each new alert turns over
onto the departures board. Hovering a row shows why it was flagged, without opening
it. Two models are deciding: the pattern classifier, a LightGBM model trained on
labelled attacks, and the anomaly detector, an autoencoder trained only on normal
traffic. A second anomaly model, an isolation forest, is watching in shadow mode."

**Do:** point at "The last hour, minute by minute".

**Say:** "The last hour is drawn to scale, a column per real minute: alerts below the
line. Flow counts come from ClickHouse, which is not running on this laptop, so the
strip says 'unavailable' rather than drawing a quiet network."

**Do:** click the **critical** count.

### Scene 5 (3:00 - 3:40): The alert feed

**Do:** search `175.45.176.0/24`, then `T1046`. Clear the search. Scroll to the bottom
and click **Show older alerts**.

**Say:** "Every flagged connection, newest first. Search understands an address, a
whole network, or a MITRE ATT&CK technique. In the replay of 535 unseen flows, all 135
attacks were alerted and none of the 400 normal flows were. Export CSV saves exactly
what is on screen."

### Scene 6 (3:40 - 4:50): One alert, explained

**Do:** open an alert. Point at the sentence at the top, the progress line (seen,
scored, explained, decided), then **Why this was flagged** and **What each model said**.
Go back and open an alert from a different source address to show different bars.

**Say:** "The sentence says what happened: who connected to whom, how likely it is an
attack, and what stood out. The chart is a SHAP explanation for this one flow, drawn as
a tug of war: red bars pull towards attack, blue towards normal. The model in shadow
is listed too, marked 'watching only'. The technique is shown only when the
attack-family model is confident; otherwise the page says why there is none."

**Do:** open the alert id noted in the checklist and scroll to **AI summary**.

**Say:** "The AI summary is written by a small language model running on this laptop's
GPU. It is read-only, it has no path to the response controls, and a reply that
invents a number or contradicts the detector is thrown away before it reaches this
page."

### Scene 7 (4:50 - 5:20): The estate

**Do:** open **Estate**. Click **Alerts involving it** on `unsw-server-12`.

**Say:** "These are the machines being protected: the dataset's ten servers. Findings
from a Greenbone vulnerability scan appear under each host, worst first; no scan runs on
this laptop, so every host says 'not yet scanned'. After a scan, a host with nothing
found says so with the scan's date, so an unscanned machine never passes for a clean one. The system refuses to block one of these addresses: a machine
of your own is isolated instead."

### Scene 8 (5:20 - 7:00): Response with a human in the loop

**Say:** "Blocking needs two people. An administrator proposes; an analyst decides. No
role can do both."

**Do:** sign out, sign in as `admin`, open an alert, click **Propose blocking** (the
button ends with the alert's source address, e.g. 175.45.176.0). Show the confirmation
that it now waits on the Approvals page.

**Do:** in the API docs tab, click **Authorize**, sign in as `admin`. Take the
`action_id` from `GET /actions/pending`, then try `POST /actions/{action_id}/decision`
with `{"decision": "approved"}`.

**Say:** "The administrator who proposed it cannot approve it: the API answers 403."

**Do:** in the browser, sign in as `analyst`, open **Approvals**. Point at the disabled
**Reject** button with an empty comment. Click **Approve**.

**Say:** "A rejection needs a written reason. The analyst approves, and the action
leaves the queue. Approving does not execute it: a separate responder carries it out
through CrowdSec or Wazuh, which are not connected in this offline demo."

**Do:** in the API docs tab, **Authorize** as `analyst` and try
`POST /alerts/{alert_id}/actions` with `{"action_type": "block_ip"}`.

**Say:** "And the analyst cannot propose a block: 403 again. Every decision is written
to the audit log."

### Scene 9 (7:00 - 7:30): Models, and night mode

**Do:** sign in as `modeller`, open **Models**. Point at the mode, threshold, Reviewed
and Not reviewed columns and the note under the table. Click **Day** to switch to night.

**Say:** "The ML engineer's page. A new model starts in shadow mode: it scores traffic
but decides nothing, and can be promoted only once analysts' verdicts give enough
evidence. The note is honest that these are agreement with analysts, not ground truth.
And for a dark room, the same station after dark."

### Scene 10 (7:30 - 8:15): Closing

**Screen:** the Key results and Limitations slides, or the overview page.

**Say:** "On a temporal test split the Tier A model reaches PR-AUC 1.0000 with a 0.05%
false-positive rate; the anomaly autoencoder catches 98.5% of attacks at 0.8% false
alarms, in 0.13 milliseconds a flow. 1,085 Python and 165 dashboard tests pass. What it
does not claim: moved to other networks' traffic the same model drops to 0.74 and 0.05,
which is why every model must earn its place in shadow mode; the attack-family model
that decides how harmful an attack is gets only 57% macro-F1, so most alerts carry an
unknown kind and rank as high rather than critical; and on the live lab the anomaly
models first flagged normal traffic, until they were re-baselined on the lab's own. Thank you."

## After recording

- Rebuild the demo database (`build_demo.ps1 -Native`) to record again: it clears the
  approved action and issues new passwords.
- Do not show `lab\replay\out\demo_credentials.txt` or `.env.local` on screen.

## The live VM

The full pipeline runs on an 8 GB cloud VM (setup in `docs/CLOUD_VM.md`, memory per
profile in `infra/README.md`). Nothing on it is open but SSH; open the tunnel from
`docs/CLOUD_VM.md` step 7 on the laptop, then:

| On the laptop | What |
|---|---|
| https://127.0.0.1:5180 | the NetSentinel dashboard |
| http://127.0.0.1:8010/api/v1/docs | the API |
| http://127.0.0.1:3000 | Grafana |
| https://127.0.0.1:5601 | the Wazuh dashboard |
| https://127.0.0.1:8443 | DFIR-IRIS |

**Do:** sign in to the dashboard with an account created on the VM. On the VM, in
`~/netsentinel/infra`, run the scan from the lab's attacker:

```bash
docker compose exec attacker nmap -sS -p 1-1000 172.30.0.10
```

**Say:** "This is a real port scan on an isolated lab network, captured by the sensor
and scored as it happens. When it was run for this project, its 1000 flows averaged a
risk of 0.937 and 999 of them crossed 0.5; the lab's normal client averaged 0.168, with
none above 0.5."

**Do:** point at the last-hour strip, which now shows flow counts, then open Grafana and
the Wazuh dashboard.

**Say:** "Here ClickHouse is running, so the strip counts flows. The same flows are in
Grafana, and Wazuh shows what happened on the host itself."

**Do:** open **Models** (any role can read it; promoting needs the ML engineer).

**Say:** "On this lab the anomaly models first called ordinary web traffic unusual,
because they had learnt 'normal' from benchmark datasets. They were re-baselined on the
lab's own normal traffic: false alarms on held-out normal flows went from 12.1% to 0%,
and the scan was still caught in full. The re-baselined versions are scoring here in
shadow; they are promoted from this page, or with the shadow report, once analysts'
verdicts give enough evidence."
