# Demo video script (about 7 minutes)

A scene-by-scene script for recording the NetSentinel-AI demonstration. Each scene
says what is on screen, what to click, and what to say. Everything shown is the
offline demonstration described in `docs/USER_MANUAL.md` (Part 2): real trained
models scoring flows replayed from the unseen test window of NF-UNSW-NB15-v3.

Addresses:

- Dashboard: https://127.0.0.1:5180 (http://127.0.0.1:5173 with `start_demo.ps1 -Dev`)
- API and its interactive docs: http://127.0.0.1:8010/api/v1/docs
- Accounts: `admin`, `analyst`, `modeller`, `viewer`; passwords in
  `lab\replay\out\demo_credentials.txt`

Counts quoted below (135 alerts, 134 critical, 175.45.176.x attackers) are the ones
the current demo database produced. Read the real numbers off the screen if a rebuild
changes them.

## Pre-recording checklist

- [ ] Docker Desktop running; nothing else on ports 5180 or 8010.
- [ ] Fresh demo database, so the approval queue is empty and passwords are known:
      `powershell -ExecutionPolicy Bypass -File lab\replay\build_demo.ps1`
- [ ] AI summaries written for a few alerts (the alert page otherwise says "No AI
      summary has been written for this alert yet"). With Ollama running and
      `NETSENTINEL_DATABASE_URL` set in your shell to the `.env.local` URL with the
      database name changed to `netsentinel_demo` (`build_demo.ps1` sets it only inside
      its own run): `ollama pull llama3.2:3b`, then
      `uv run netsentinel-copilot --latest 10`. Note one alert id that got a summary.
- [ ] Start the stack: `powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1`;
      wait for "Dashboard: https://127.0.0.1:5180".
- [ ] Credentials file open on a second screen, not in the recording.
- [ ] Browser at 100% zoom, a clean profile (no bookmarks bar, no password prompts),
      window about 1600 x 900. A second tab open on the API docs page.
- [ ] Notifications off; terminal font large enough to read in the video.
- [ ] Do one dry run of scene 7 end to end, then rebuild the database (step 2) so the
      recording starts with an empty queue.

## Script

### Scene 1 (0:00 - 0:30): Introduction

**Screen:** title slide of `deliverables/Milestone_5_Presentation.pptx`, or the login page.

**Say:** "This is NetSentinel-AI, an intrusion detection and security monitoring system
that uses machine learning. It scores network flows with trained models, explains
every alert, and never blocks anything without a person approving it. Everything in
this video is running locally on my laptop."

### Scene 2 (0:30 - 1:00): Starting it

**Screen:** a PowerShell window at the project root.

**Do:** show the command
`powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1` (already run; show
its last line) and the browser opening at https://127.0.0.1:5180.

**Say:** "One command starts PostgreSQL, the FastAPI backend on port 8010 and the React
dashboard in Docker. The alerts in the database come from flows the models never saw:
the last 15% of the dataset by time, replayed through the real scorer and writer."

### Scene 3 (1:00 - 1:30): Viewer, the read-only role

**Do:** sign in as `viewer`. Point at the line under the headline. Open any alert from
the Alerts page and scroll to the bottom.

**Say:** "There are four roles. The viewer can read everything and change nothing: the
page says so, and there are no action buttons at all." Sign out.

### Scene 4 (1:30 - 2:15): Overview as the analyst

**Do:** sign in as `analyst`. Pause on the headline sentence, then on "Threats by
severity", "Addresses raising the most alerts" and "Detection models".

**Say:** "The overview opens with one plain sentence: 135 threats detected, 134 of them
critical, none waiting for a decision. Two models are deciding: the pattern
classifier, a LightGBM model trained on labelled attacks, and the anomaly detector, an
Isolation Forest trained only on normal traffic. The addresses raising most alerts are
the dataset's four attacking machines."

**Do:** click **Critical**.

### Scene 5 (2:15 - 3:00): The alert feed

**Do:** on the Alerts page, point at the green **live** dot. Search `175.45.176.0/24`,
then `T1046`. Clear the search.

**Say:** "Every flagged connection, newest first, pushed live over a WebSocket. Search
understands an address, a whole network, or a MITRE ATT&CK technique. In the replay of
535 unseen flows, all 135 attacks were alerted and none of the 400 normal flows were.
Export CSV saves exactly what is on screen."

### Scene 6 (3:00 - 4:15): One alert, explained

**Do:** open an alert by clicking its time. Point at the sentence at the top, the
details box (the technique field) and the **Why this was flagged** chart, then **What
each model said**. Go back and open a second alert from a different source address
to show different bars (the top two rows of the feed have near-identical bars).

**Say:** "The sentence says what happened: who connected to whom, how likely it is an
attack, and what stood out. The chart is a SHAP explanation for this one flow: red bars
pushed the verdict towards attack, blue towards normal. A second alert has different
bars, because explanations are per flow. The technique is only shown when the
attack-family model is confident; otherwise the page says why there is none."

**Do:** open the alert id noted in the checklist and scroll to **AI summary**.

**Say:** "The AI summary is written by a small language model running on this laptop's
GPU. It is read-only, it has no path to the response controls, and a reply that
invents a number or contradicts the detector is thrown away before it reaches this
page. The page reminds the analyst that the evidence above it is what counts."

### Scene 7 (4:15 - 6:00): Response with a human in the loop

**Say:** "Blocking needs two people. An administrator proposes; an analyst decides. No
role can do both."

**Do:** sign out, sign in as `admin`, open an alert, click **Propose blocking** (the
button ends with the alert's source address, e.g. 175.45.176.0). Show the confirmation
that it now waits on the Approvals page.

**Do:** switch to the API docs tab. Click **Authorize**, sign in as `admin`. Take the
`action_id` from `GET /actions/pending`, then try `POST /actions/{action_id}/decision`
with `{"decision": "approved"}`.

**Say:** "The administrator who proposed it cannot approve it: the API answers 403."

**Do:** in the browser, sign out, sign in as `analyst`, open **Approvals**. Point at
the disabled **Reject** button with an empty comment. Click **Approve**.

**Say:** "A rejection needs a written reason. The analyst approves, and the action
leaves the queue. Approving does not execute it: a separate responder carries it out
through CrowdSec or Wazuh, which are not connected in this offline demo."

**Do:** in the API docs tab, **Authorize** as `analyst` and try
`POST /alerts/{alert_id}/actions` with `{"action_type": "block_ip"}`.

**Say:** "And the analyst cannot propose a block: 403 again. Every decision is written
to the audit log."

### Scene 8 (6:00 - 6:40): Models

**Do:** sign out, sign in as `modeller`, open **Models**. Point at the mode, threshold,
Reviewed and Not reviewed columns and the note under the table. Switch the window
(Last 7d / Last 30d).

**Say:** "The ML engineer's page. Both models are active here; Tier A's threshold is
0.0047 and Tier D's 0.99. A new model starts in shadow mode: it scores traffic but
decides nothing, and can be promoted only once analysts' verdicts give enough evidence.
The note is honest that these are agreement with analysts, not ground truth."

### Scene 9 (6:40 - 7:30): Closing

**Screen:** the Key results and Limitations slides, or the overview page.

**Say:** "On a temporal test split the Tier A model reaches PR-AUC 1.0000 with a 0.05%
false-positive rate, and 733 Python and 94 dashboard tests pass. What it does not
claim: moved to other networks' traffic the same model drops to 0.74 and 0.05, which is
why every model must earn its place in shadow mode; the anomaly detector is over the
5 ms latency budget; and the signature and host sensors need a cloud VM that was not
provisioned in this project. Thank you."

## After recording

- Rebuild the demo database (`build_demo.ps1`) if you need to record again: it clears
  the approved action and issues new passwords.
- Do not show `lab\replay\out\demo_credentials.txt` or `.env.local` on screen.
