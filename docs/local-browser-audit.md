The **This PC** page at `/condition` shows local endpoint evidence and a bounded
browser audit. Native launches against `netsentinel_live` enable the audit. It is
disabled by default elsewhere; the API requires an administrator and a loopback
connection. Do not enable `NETSENTINEL_LOCAL_BROWSER_AUDIT=1` behind a remote-facing
proxy. Recent personal history is returned only to this local dashboard, never
written to the project database or uploaded to a reputation service.

Chrome, Edge, Brave and Firefox history is read from the current Windows account.
At most eight profiles are read, prioritizing the registered default browser, with
50 recent site and download records per profile. Full URLs remain in memory for
exact phishing comparisons; only domains are returned. Firefox downloads are
currently unsupported. SQLite read-only connections include committed WAL data;
For exclusively locked Chromium databases, a bounded private temporary snapshot
includes the main database and its WAL, rejects active rollback journals and any
source changes, validates SQLite consistency, then deletes the raw copy immediately.
Committed SQLite PERSIST journals with an invalidated zero header are recognized.
Unreadable, changing, or unsupported sources report unavailable.

The optional OpenPhish community feed is for this personal/academic lab only,
subject to [OpenPhish terms](https://openphish.com/terms.html). Do not use it for an
organization's commercial operations without the provider's written permission.
Refresh manually with `.venv\Scripts\python.exe -m netsentinel_api.services.site_risk`.
This downloads a fixed public feed without sending browser history, and stores
only URL hashes and provenance in ignored `lab/local/out/site-risk.json`.
The dashboard labels the feed stale after 24 hours; missing/stale data means unknown.
No exact match in the limited feed establishes no safety guarantee.
This personal lab opts into background feed refresh through the ignored
`lab/local/out/site-risk-opt-in` marker. Resident health polling may run the same
module with `--if-due`; without that marker it exits without network activity,
and with it downloads at most once per 12 hours. Delete the marker to opt out.

These are observations after the browser records activity, not a download blocker.
Windows Defender and browser protection handle native real-time checks; their
settings and scan outcomes are reported separately. Missing explicit Safe Browsing
preferences and SmartScreen policy values mean unknown. HTTPS alone is not safety.
