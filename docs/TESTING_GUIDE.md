# Testing NetSentinel-AI by hand

A guide for trying to break the system, not for watching it work. Every step says what
should happen; anything else is a bug worth writing down (step, what you did, what you
saw, what you expected).

## 0. Start it

```powershell
powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1
```

- Dashboard: https://127.0.0.1:5180 (http://127.0.0.1:5173 with `start_demo.ps1 -Dev`)
- API and its interactive docs: http://127.0.0.1:8010/api/v1/docs
- Accounts and passwords: `lab\replay\out\demo_credentials.txt`
- To reset everything to a clean demo (new passwords):
  `powershell -ExecutionPolicy Bypass -File lab\replay\build_demo.ps1`

| Account | Role | Can | Cannot |
|---|---|---|---|
| `admin` | administrator | read alerts, **propose** a block | approve anything |
| `analyst` | SOC analyst | read, triage, escalate, **approve/reject** | propose a block |
| `modeller` | ML engineer | read models, **promote** a model | triage, approve |
| `viewer` | viewer (everyday user) | read everything | change anything |

No role can both propose and approve. That is the point of the gate, and several tests
below check it.

In the API docs page, click **Authorize** (top right), enter a username and password,
and every request you try from that page runs as that user.

## 1. The model

Run these in a terminal at the project root, with `$env:UV_CACHE_DIR="D:/uv-cache"`.

| # | Do | Expect |
|---|---|---|
| 1.1 | Read `docs\evaluation\REPORT.md` | Tier A PR-AUC 1.0000 on the temporal test split; TTL-only 0.998; cross-dataset 0.74 / 0.05 |
| 1.2 | Replay a different sample: `uv run --no-sync python lab/replay/dataset_replay.py --dataset data/raw/NF-UNSW-NB15-v3.parquet --models artefacts/tier_a/model_card.json artefacts/tier_d/model_card.json --mode active --out lab/replay/out/test2.jsonl --benign 5000 --per-family 200 --seed 7` | Prints attacks, alerts, caught, missed, false alarms. Record them: this is your own accuracy measurement on data the model never saw |
| 1.3 | Repeat 1.2 with `--seed 1`, `--seed 99` | Numbers change a little, never collapse. A large swing between seeds is worth reporting |
| 1.4 | Repeat 1.2 with only `artefacts/tier_d/model_card.json` | Far fewer attacks caught (Tier D recalls ~40%): the unsupervised tier alone |
| 1.5 | Edit one byte of `artefacts/tier_a/tier_a.onnx` (make a copy first!) and run 1.2 | Refused: the file no longer matches the SHA-256 in its model card. Restore the copy afterwards |
| 1.6 | Re-run the whole benchmark: `uv run --no-sync python -m netsentinel_training.eval.benchmark --data data/processed/nf-unsw-nb15-v3 --out docs/evaluation-rerun` (~15 min, close other apps) | Same numbers as 1.1 to within rounding |

## 2. Signing in

| # | Do | Expect |
|---|---|---|
| 2.1 | Wrong password | An error message; no dashboard |
| 2.2 | Correct username, empty password | Browser blocks submit (field required) |
| 2.3 | Sign in, then reload the page | Still signed in ("Restoring session..." briefly) |
| 2.4 | Sign out, press Back | Login page, not the dashboard |
| 2.5 | Username `admin' OR '1'='1` | Rejected like any wrong password |

## 2b. The overview (any account)

| # | Do | Expect |
|---|---|---|
| 2b.1 | Sign in | The Overview opens with a sentence: how many threats, how many critical, how many open, how many blocks waiting |
| 2b.2 | Read the line under it | It names your role and what it may do; different for each account |
| 2b.3 | Click **Critical** in "Threats by severity" | The Alerts page opens filtered to critical |
| 2b.4 | Click an address under "Addresses raising the most alerts" | The Alerts page opens searched for that address |
| 2b.5 | Narrow the window to phone width | Navigation shrinks to icons; nothing runs off the screen |

## 3. The alert feed (as `analyst`)

| # | Do | Expect |
|---|---|---|
| 3.1 | Open Alerts | Up to 50 alerts, "live" in green |
| 3.2 | Search `175.45.176.0` | Only alerts from or to that address |
| 3.3 | Search `175.45.176.0/24` | Every alert on that network |
| 3.4 | Search `149.171.126.10` | Matches in the **To** column too (either end matches) |
| 3.5 | Search `hello`, `175.45`, `999.1.1.1` | A message saying what would have worked; never an empty list pretending nothing matched |
| 3.6 | Search `'; DROP TABLE alerts; --` | Refused as not an address; alerts still there afterwards |
| 3.7 | Filter severity `low` | The one low alert |
| 3.8 | Export CSV with a filter on | The file holds only the filtered rows, with risk score and model columns |
| 3.9 | Stop the API window, wait 10 s | Indicator leaves "live"; restart the API and it returns |

## 4. Alert detail and triage (as `analyst`)

| # | Do | Expect |
|---|---|---|
| 4.1 | Open any alert | A sentence saying what happened, the risk score, what each model said (Pattern classifier, Anomaly detector) and a "Why this was flagged" chart in plain words |
| 4.2 | Compare two alerts | Different SHAP bars: explanations are per flow, not one global chart |
| 4.3 | Click **Confirm attack** on five alerts | Status changes to "Closed - true positive"; on the Models page Tier A's *Reviewed* count rises |
| 4.3b | Click **Escalate to incident** | "Incident N opened", and an honest note that the case system is not connected in the demo |
| 4.3c | Sign in as `viewer` and open any alert | The page says the account can read but not act; no buttons at all |
| 4.4 | Open `/alerts/99999` in the address bar | A not-found message, not a crash |
| 4.5 | Look at the Technique column in the feed; open alerts with and without one | About a quarter of alerts carry T1046, T1190 or T1499 with its title and "Suggested by the attack-family model"; the rest say why there is none. Compare against the dataset label in `lab\replay\out\flows.jsonl` (`"label"`) to measure it yourself |

## 5. The approval gate

| # | As | Do | Expect |
|---|---|---|---|
| 5.1 | admin | Open an alert, click **Propose blocking ...** | "Block on ... proposed. It now waits on the Approvals page" |
| 5.2 | analyst | Approvals page | The new block is listed |
| 5.3 | analyst | Click **Reject** with an empty comment | Button disabled / refused: a rejection needs a reason |
| 5.4 | analyst | Approve one | It leaves the queue. Nothing is blocked yet: an executor carries it out, and none is configured in the demo |
| 5.5 | analyst | Open the same alert | No propose button. Through the API docs page, `POST /alerts/{id}/actions` answers 403 |
| 5.6 | admin | `POST /actions/{id}/decision` | 403: the proposer cannot approve |
| 5.7 | admin | In the API docs page, `POST /alerts/{id}/actions` with `{"action_type": "block_ip", "target": "192.0.2.1"}` | Refused: that is one of the estate's own assets |
| 5.8 | modeller | Approvals page | No approve/reject buttons at all |

## 6. Models (as `modeller`)

| # | Do | Expect |
|---|---|---|
| 6.1 | Open Models | Both tiers active; Tier A threshold 0.0047, Tier D 0.99 |
| 6.2 | Switch the window (Last 24h / Last 7d / Last 14d / Last 30d) | Counts follow the window |
| 6.3 | As `analyst`, open Models | Readable, no promote controls |

## 7. Robustness

| # | Do | Expect |
|---|---|---|
| 7.1 | Stop PostgreSQL (`docker stop netsentinel-postgres-1`) and use the dashboard | Clear errors, no blank page. `docker start netsentinel-postgres-1` recovers it |
| 7.2 | Two browsers, analyst in both, approve the same action in each | The second is refused: an action is decided once |
| 7.3 | Resize the window to phone width | Tables scroll sideways; nothing overlaps |
| 7.4 | Tab through the login and feed with the keyboard only | A visible blue focus ring on every control |

## 8. The automated suites

```powershell
uv run --no-sync pytest -q          # 709 Python tests, no database needed
cd frontend; npx vitest run         # 94 dashboard tests
```

Both must be all green. A failure is a bug in the code or in the test, and either is
worth reporting.
