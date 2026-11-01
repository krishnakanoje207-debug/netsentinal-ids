# Optional Gemini summaries

The summary worker uses Google's stable `gemini-3.5-flash-lite` model over the
Gemini REST API. The detector, writer and dashboard still run locally; this only
changes the optional explanation paragraph. No Ollama install, model download or
GPU is required. No key has been configured or cloud call made by this change.

## Data and opt-in

Cloud summaries are disabled by default. Supplying a key alone does not enable
them: set `NETSENTINEL_COPILOT_ALLOW_CLOUD=true` to authorize the worker to send
minimized evidence to Google. The request contains severity, risk score, a valid
MITRE technique identifier, up to five known contributing feature names and their
directions, and fixed `SOURCE_ENDPOINT` / `DESTINATION_ENDPOINT` labels. Raw IP
addresses, hostnames, indicator values, alert IDs, payloads, credentials and other
alerts are omitted. This is data minimization, not a promise that security evidence
is non-sensitive; Google's API terms, your key's billing tier and organizational
policy apply. Requests can consume paid quota. Removing opt-in stops future calls.

The key is read only by the worker from `GEMINI_API_KEY`, sent in the
`x-goog-api-key` header, and never exposed to browser code. Create your own key in
[Google AI Studio](https://aistudio.google.com/api-keys); keep it out of Git, command
arguments and screenshots. It is separate from Google sign-in's public client ID.
For deployment, supply it through your secret manager or process environment.

## This PC's live database

Run from the repository root while the live monitor is running. This explicitly
selects `netsentinel_live`; a bare worker command can use a different default
database. The first lines load only database connection and signing settings from
the existing ignored `.env.local`, without printing them:

```powershell
foreach ($line in Get-Content .env.local) {
    if ($line -match '^(NETSENTINEL_DATABASE_URL|NETSENTINEL_JWT_SECRET)=(.*)$') {
        [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
}
$env:NETSENTINEL_DATABASE_URL = $env:NETSENTINEL_DATABASE_URL -replace '/[^/]+$', '/netsentinel_live'
$geminiKey = Read-Host 'Gemini API key' -AsSecureString
$env:GEMINI_API_KEY = [System.Net.NetworkCredential]::new('', $geminiKey).Password
$env:NETSENTINEL_COPILOT_ALLOW_CLOUD = 'true'
try {
    uv run netsentinel-copilot --latest 10
} finally {
    Remove-Item Env:GEMINI_API_KEY, Env:NETSENTINEL_COPILOT_ALLOW_CLOUD
    $geminiKey.Dispose()
}
```

This is an on-demand batch, not a background loop. Use `--alert ID` instead of
`--latest 10` to summarize one existing alert. `NETSENTINEL_COPILOT_MODEL` or
`--model` can select another compatible Gemini model available to your key. Without
both opt-in and a key the worker exits before opening a database or sending data.

## Docker database

The established Compose API image intentionally excludes the Copilot; it serves
requests and never performs model calls. Run the same native worker separately.
Set `NETSENTINEL_DATABASE_URL` to the Docker PostgreSQL **published host port**,
actual credentials and live database name; do not use Compose's internal
`postgres:5432` hostname from a host process. Use the same database as the live API,
not the historical `netsentinel_demo` database. Supply `NETSENTINEL_JWT_SECRET`,
`GEMINI_API_KEY` and explicit cloud opt-in in the worker environment. No Gemini key
needs to be forwarded into the API or frontend containers.

## Validation and failures

Gemini receives the response JSON schema. Endpoint labels are restored locally,
then existing schema, unsupported-measurement, contradictory-verdict and reversed
flow checks run before a summary can be shown. The model has no tools and cannot
change an alert or approve containment. Rejected summaries remain stored for
review. Missing credentials, provider authentication errors, quota exhaustion,
timeouts, blocked/truncated output or invalid JSON fail the summary attempt;
detection remains independent. Availability and quota have not been verified with
a real key yet.

Sources (checked November 1, 2026): [stable model](https://ai.google.dev/gemini-api/docs/models/gemini-3.5-flash-lite),
[REST generation](https://ai.google.dev/api/generate-content),
[structured output](https://ai.google.dev/gemini-api/docs/generate-content/structured-output),
[current generation parameters](https://ai.google.dev/gemini-api/docs/generate-content/whats-new-gemini-3.6),
[key security](https://ai.google.dev/gemini-api/docs/api-key).
