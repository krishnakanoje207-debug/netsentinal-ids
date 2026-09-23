# NetSentinel-AI user manual

NetSentinel-AI watches network traffic, uses AI models to decide which connections look
like attacks, explains each decision, and lets people decide what to do about it.
Nothing is blocked without a person approving it.

Part 1 is for everyone who uses the dashboard. Part 2 is for whoever installs it.

---

## Part 1: Using the dashboard

### Signing in

Open the dashboard address you were given (for the demo, https://127.0.0.1:5180) and sign
in. What you can do depends on your account's role, and the Overview page tells you in
one line under its headline.

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
for a decision. Below it:

- **Threats by severity.** Click a severity to see those alerts.
- **Waiting for a decision.** Blocks proposed but not yet approved.
- **Addresses raising the most alerts.** Click an address to see its alerts.
- **Detection models.** Which AI models are deciding, in plain words.
- **How NetSentinel works.** The four steps: watch, score, explain, decide.

### Alerts

Every connection the models flagged, newest first. Hover over a column heading to see
what it means. The green **live** dot means new alerts appear on their own.

- **Search** takes an address (`175.45.176.0`), a network (`175.45.176.0/24`) or an attack
  technique (`T1046`). Anything else gets a message saying what would work.
- **Filters** narrow by status or severity.
- **Export CSV** saves exactly what you are looking at, filters included.

### One alert

Open an alert by clicking its time.

1. **The sentence at the top** says what happened: who connected to whom, how likely the
   models think it is an attack, and what stood out most.
2. **The details box** gives severity, status, both addresses and, when the model is sure
   enough, the **attack technique** from MITRE ATT&CK with its name. When there is none,
   it says why.
3. **Why this was flagged** is a chart of the measurements that mattered. Red bars made the
   connection look more like an attack, blue bars more normal; longer bars mattered more.
   Below it, each model's own score.
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

### Models

For the ML engineer, and readable by everyone. Each AI model, whether it is **active**
(deciding) or in **shadow** (watching and being measured only), its alert threshold, and
how its alerts were judged by analysts. A shadow model can be promoted only when enough
alerts have been reviewed; if the button is disabled, the reason is written under it.

### When something looks wrong

| You see | It means |
|---|---|
| The live dot is not green | the dashboard lost its connection; it reconnects on its own |
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
