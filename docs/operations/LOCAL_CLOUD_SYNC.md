# Local Wazuh and cloud metadata

Wazuh alerts appear in the local NetSentinel feed with rule ID, original Wazuh
level, agent, event identifiers and process basename. Command lines, raw events
and full paths are excluded. Wazuh levels map to low (3–6), medium (7–10), high
(11–14), and critical (15–16). A rule match still needs analyst review.

The importer reads the manager's current alerts file through Docker, reconnects
after interruptions, and deduplicates by manager/event ID. Each connection catches
up the latest 1,000 lines; rotated archives and larger backlogs need explicit
`python -m netsentinel_api.sync_wazuh --alerts <export.json>` import. This is a
trusted local worker, with no Docker command endpoint in the web API.

An optional explicit `--agent-id`/`--asset-id` mapping allows links to ML alerts
on that asset within 150 seconds. These links supply context only and never
increase severity or assert a shared cause. Without a mapping, no links are made.

Cloud ingestion is disabled until `NETSENTINEL_TELEMETRY_TOKEN` is configured on
Render. This separate credential permits writes to `/api/v1/telemetry/alerts`;
it cannot read alerts or authenticate as a dashboard user. The sender uses HTTPS
with certificate verification and does not follow redirects.

Only event time, severity, original sensor type, local alert ID, rule/model IDs
and a random pseudonymous host ID leave this PC. IP addresses, hostnames, process
details, browser history, full paths, packet captures and model explanations are
excluded. The receiver rejects unknown fields. Cloud copies have source
`telemetry`; local rule evidence and ML explanations remain in the local database.
Cloud triage decisions and local triage decisions are independent.

The sender retries unacknowledged batches without advancing its cursor. The
receiver has a database uniqueness constraint, so a replay after a lost response
does not create duplicates. Keep the ignored state file: deleting it creates a
new pseudonym and starts another import. This sends newly inserted alerts; it
does not mirror later edits or deletion of previously sent alerts.

Start both workers after local database migration and secret provisioning:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File lab/local/start_integrations.ps1 -AssetId <verified-local-asset-id>
```

The launcher reads database/JWT settings from `.env.local` and the write secret
from `lab/local/out/integrations/telemetry.env`. Logs and per-database cursors stay
under that ignored directory. It supervises the workers and prevents duplicate
launches with a Windows mutex. It does not start packet capture or change Windows
security settings. The same command can run at user logon via Task Scheduler.

Render's telemetry token is managed through its service environment settings,
separately from `render.yaml`. Do not add its value to Git or frontend variables.
