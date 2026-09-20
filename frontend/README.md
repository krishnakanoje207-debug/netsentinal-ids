# frontend

`netsentinel-dashboard` — the SOC console: live alert feed, model explanations,
triage, and the approval queue that fronts the human gate.

Runs in the browser on the laptop, reaching the API through the SSH tunnel to the
cloud VM.

## Running it

```bash
npm install
npm run dev          # http://localhost:5173, proxying /api to 127.0.0.1:8000
npm test             # 55 tests
npm run build        # bundle for production
npm run lint         # oxlint
```

Point the proxy somewhere else with `NETSENTINEL_API=http://host:port npm run dev`.

Vite proxies `/api` rather than the browser calling the API directly. That
reproduces deployment, where the tunnel makes the API same-origin — which is why the
backend deliberately ships no CORS middleware.

## Layout

Plain JavaScript with JSX, not TypeScript. Shapes are written down as JSDoc typedefs in
`api/types.js` - comments, so they read as plain English and still drive editor
completions, without type syntax in the way. The tests are the real safety net.

| Path | What it is |
|---|---|
| `api/` | Client, plus JSDoc typedefs mirroring the backend schemas |
| `auth/` | Session context and the login form |
| `alerts/` | Feed, detail view, SHAP chart |
| `actions/` | The approval queue |
| `stream/` | WebSocket alert feed with backoff |
| `components/` | Risk score, severity badges, error notices |

## Rules the interface has to honour

**Undecided is not benign.** The fusion scorer returns no risk score when only shadow
models voted, and the API sends no explanation for alerts raised by Suricata or Wazuh.
Both would be easy to render as `0%` — low, green, reassuring — which would invent a
conclusion nobody reached. `RiskScore` renders them as a neutral dash labelled
*undecided*, with the reason on hover, and `toneFor` is tested to keep a genuine `0.0`
distinct from a missing score.

**Approving is not executing.** The API moves an action to `approved`; the D12
executors carry it out and call `mark_executed`. So the button says *Approve*, and the
card says in words that the executor acts afterwards. A button labelled "Block now"
would describe something that has not happened.

**A rejection needs a reason.** The API enforces it with a 422. The submit button stays
disabled until a comment is written, so the rule is visible before the round trip
rather than arriving as an error after it.

**Permissions come from the server.** `GET /auth/me` returns the caller's permission
list, and controls the account cannot use are not rendered at all. Duplicating the
role-to-permission table in TypeScript would guarantee the two drift, and showing
buttons that only ever return 403 teaches an analyst to ignore errors.

**A stopped feed must look stopped.** The stream indicator shows connecting, live or
disconnected, because an analyst watching a feed that has silently died will read the
absence of alerts as calm. Reconnection backs off to 30s, since a tunnel drop is
routine and a tight retry loop would be a self-inflicted denial of service.

## Deviations from M2 §4

The document specifies **TypeScript** "for a type-safe UI"; this is JavaScript. Typed
source is only an asset to someone who can read and maintain it, and this codebase has to
be defended by its author. The 55 tests cover the behaviour that types would have caught
at the boundaries - error mapping, permission gating, the undecided-vs-benign rule - and
they are language-agnostic. **M2 §4 needs updating to match.**

The document also specifies React 18; this is React 19, which is what `create vite` now
scaffolds and is the current stable release. Nothing in the design depends on 18.

Recharts is loaded lazily, so the feed — the landing page — does not pay for it. That
keeps the initial bundle at ~317 kB (99 kB gzipped) with the chart in a separate chunk.
