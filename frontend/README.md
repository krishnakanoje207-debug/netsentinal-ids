# frontend

`netsentinel-dashboard` — the SOC console: live alert feed, model explanations,
triage, the approval queue that fronts the human gate, and the model registry that
promotion is decided from.

Runs in the browser on the laptop, reaching the API through the SSH tunnel to the
cloud VM.

## Running it

```bash
npm install
npm run dev          # http://localhost:5173, proxying /api to 127.0.0.1:8000
npm test             # 132 tests
npm run build        # bundle for production
npm run lint         # oxlint
```

Point the proxy somewhere else with `NETSENTINEL_API=http://host:port npm run dev`.

Vite proxies `/api` rather than the browser calling the API directly. That
reproduces deployment, where the tunnel makes the API same-origin — which is why the
backend deliberately ships no CORS middleware.

## Layout

Look and motion rules are in [`DESIGN.md`](DESIGN.md). Plain JavaScript with JSX, not TypeScript. Shapes are written down as JSDoc typedefs in
`api/types.js` - comments, so they read as plain English and still drive editor
completions, without type syntax in the way. The tests are the real safety net.

| Path | What it is |
|---|---|
| `api/` | Client, plus JSDoc typedefs mirroring the backend schemas |
| `auth/` | Session context and the sign-in page |
| `overview/` | The landing page: headline, severity, latest alerts, the last hour, how it works |
| `alerts/` | Feed, search, detail view, the reasons chart, CSV export |
| `actions/` | The approval queue |
| `estate/` | The protected hosts, their scan findings worst first, and links to their alerts |
| `models/` | The registry, its shadow evidence and the promote control |
| `stream/` | The one WebSocket alert feed, with backoff, shared through context |
| `theme/` | Day and night |
| `tour/` | The guided tour and its stops |
| `components/` | The station clock, split-flap numbers, the departures board, hover cards, the activity strip, the line map, risk score, severity plates, error notices |

## Look and motion

The console is drawn as a station's information system. Alerts are posted on a blue
departures board, one fixed row anatomy (time, severity, from -> to, technique, status)
wherever a row appears. Pages are wayfinding signs. "How it works" is a transit line,
and the guided tour follows it. Day is the default, because the console is shown in lit
rooms and on projectors. Night is a switch in the header, remembered per browser. The
typeface is Overpass, a signage face, with Overpass Mono for addresses and times.

Everything that moves reports real state; nothing moves for decoration:

- **The station clock.** Its red second hand sweeps only while the live feed is
  connected, and parks at twelve when it is not.
- **Split-flap counts.** They flip only when the API returns a different number.
- **The departures board.** A row turns over onto it when it arrives. The thin line
  under its header fills over the real refresh interval, and data that misses three
  refreshes fades and says so.
- **The line map.** A marker runs the line once each time the feed pushes an alert.

Reduced motion is respected throughout. Every hover card also opens on keyboard focus,
because information only a mouse can reach is information some people never get.

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

**A metric with nothing behind it is a dash, not a zero.** The models page renders a
null precision or average precision as `--`, for the reason `RiskScore` renders a
missing score as undecided: no evidence and a measurement that came out at zero are
different findings, and merging them would let the page argue something the data does
not support. Unlabelled volume is a column beside precision rather than a footnote,
because a tier that fires constantly on flows nobody opens reads as perfect precision
and is not.

**A refusal is a sentence.** Promotion is refused with the reason the API wrote —
"19 labelled detection(s), and 50 are required" — shown under a disabled button. A
disabled control with no reason sends an ML engineer to the logs to find out whether
to keep triaging or to try a different candidate.

**Search happens on submit, not on keystroke.** Half a typed address is not an
address, and searching as the analyst types `203.0.113.9` would refuse `203`, `203.0`
and `203.0.11` on the way. A box that flashes errors while it is being used is a box
people stop reading.

**An export must match the screen it came from.** The export button sends the
filters the feed is currently showing, and warns on screen when the server capped the
rows — while the analyst is still looking at the list they thought they had exported.
The file is saved under the server's filename rather than the browser's, because that
name is where the truncation is recorded once the file is on disk.

**A stopped feed must look stopped.** The header shows connecting, live or stopped, and
the station clock's red hand stops with the feed, because an analyst watching a feed
that has silently died will read the absence of alerts as calm. Reconnection backs off to 30s, since a tunnel drop is
routine and a tight retry loop would be a self-inflicted denial of service.

## Deviations from M2 §4

The document specifies **TypeScript** "for a type-safe UI"; this is JavaScript. Typed
source is only an asset to someone who can read and maintain it, and this codebase has to
be defended by its author. The 132 tests cover the behaviour that types would have caught
at the boundaries - error mapping, permission gating, the undecided-vs-benign rule - and
they are language-agnostic. **M2 §4 needs updating to match.**

The document also specifies React 18; this is React 19, which is what `create vite` now
scaffolds and is the current stable release. Nothing in the design depends on 18.

The explanation chart is drawn in HTML and CSS, not with a chart library. The pages
beyond the overview load when first opened, so the first load is about 359 kB
(110 kB gzipped).
