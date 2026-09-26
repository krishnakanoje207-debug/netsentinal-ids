# Build (or rebuild) the demonstration database from scratch.
#
#   powershell -ExecutionPolicy Bypass -File lab\replay\build_demo.ps1
#   powershell -ExecutionPolicy Bypass -File lab\replay\build_demo.ps1 -Native -Interval 4
#
# Drops and recreates the netsentinel_demo database - never the main one - then
# migrates it, creates one account per role, imports the estate, registers the trained models, and writes
# the replayed test-window flows through the real writer with explanations and MITRE
# techniques. New passwords go to lab\replay\out\demo_credentials.txt.
#
# Expects PostgreSQL running (start_demo.ps1 starts it) and the trained artefacts in
# artefacts\. The API container is stopped while the database is rebuilt, because a
# database with open connections cannot be dropped, and started again at the end. With
# the dev servers (start_demo.ps1 -Dev), close the API window first.
#
# -Native uses the PostgreSQL installed on the host (start_demo.ps1 -Native) rather than
# the container. The API may stay running: its connections are closed for the drop and
# it reconnects on its own.
#
# -Interval spaces the replayed flows out by that many seconds, so the alerts arrive on an
# open dashboard one at a time, as they would from a capture. Left out, the whole test
# window is written at once.

param([switch]$Native, [double]$Interval = 0)

$ErrorActionPreference = "Continue"
$root = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $root
$env:UV_CACHE_DIR = "D:/uv-cache"
$env:PYTHONIOENCODING = "utf-8"

function Step($name, [scriptblock]$body) {
    Write-Host "== $name"
    & $body
    if ($LASTEXITCODE -ne 0) { Write-Host "failed: $name" -ForegroundColor Red; exit 1 }
}

$vars = @{}
foreach ($line in (Get-Content .env.local | Where-Object { $_ -match "^NETSENTINEL_" })) {
    $k, $v = $line -split "=", 2
    $vars[$k] = $v
}
$env:NETSENTINEL_DATABASE_URL = $vars["NETSENTINEL_DATABASE_URL"] -replace "/[^/]+$", "/netsentinel_demo"
$env:NETSENTINEL_JWT_SECRET = $vars["NETSENTINEL_JWT_SECRET"]

if ($Native) {
    # Host, port, user and password come from the URL the API itself uses.
    $pgBin = if ($env:NETSENTINEL_PG_BIN) { $env:NETSENTINEL_PG_BIN } else { "D:\netsentinel-data\pgsql\bin" }
    $null = $env:NETSENTINEL_DATABASE_URL -match "://([^:]+):([^@]+)@([^:/]+):(\d+)/"
    $pg = @("-h", $Matches[3], "-p", $Matches[4], "-U", $Matches[1])
    $env:PGPASSWORD = $Matches[2]
    Step "recreate netsentinel_demo" {
        & "$pgBin\dropdb.exe" @pg --if-exists --force netsentinel_demo
        & "$pgBin\createdb.exe" @pg netsentinel_demo
    }
} else {
    docker compose -f infra\docker-compose.yml --env-file infra\.env stop api *> $null
    Step "recreate netsentinel_demo" {
        docker exec netsentinel-postgres-1 dropdb -U netsentinel --if-exists netsentinel_demo
        docker exec netsentinel-postgres-1 createdb -U netsentinel netsentinel_demo
    }
}
Step "migrate" { Push-Location backend; uv run --no-sync alembic upgrade head; Pop-Location }

Remove-Item lab\replay\out\demo_credentials.txt -ErrorAction SilentlyContinue
Step "accounts" { uv run --no-sync python lab/replay/demo_users.py --out lab/replay/out/demo_credentials.txt }
# The estate is the UNSW-NB15 testbed's ten servers, which the replayed attacks aim at.
# Their names are labels for the demo; the dataset publishes addresses only, so OS and
# criticality are left unassessed (medium).
Step "import the estate" { uv run --no-sync python -m netsentinel_api.sync_assets --csv lab/replay/demo_inventory.csv }
Step "register Tier A" { uv run --no-sync netsentinel-register-model artefacts/tier_a/model_card.json --mode active }
Step "register Tier D autoencoder" { uv run --no-sync netsentinel-register-model artefacts/tier_d_ae/model_card.json --mode active }
# The forest stays in shadow: it is scored and recorded beside the autoencoder, and raises nothing.
Step "register Tier D forest" { uv run --no-sync netsentinel-register-model artefacts/tier_d/model_card.json }
$sensor = (uv run --no-sync python lab/replay/register_sensor.py | Select-Object -Last 1).Trim()

Step "replay the test window" {
    uv run --no-sync python -W ignore lab/replay/dataset_replay.py `
        --dataset data/raw/NF-UNSW-NB15-v3.parquet `
        --models artefacts/tier_a/model_card.json artefacts/tier_d_ae/model_card.json `
        --shadow-models artefacts/tier_d/model_card.json `
        --mode active --out lab/replay/out/flows.jsonl
}
if ($Interval -gt 0) { Write-Host "Posting alerts live, one flow every $Interval s. Open the dashboard now." }
Step "write explained alerts" {
    uv run --no-sync netsentinel-writer --card artefacts/tier_a/model_card.json `
        --family-card artefacts/family/model_card.json `
        --sensor-id $sensor --replay lab/replay/out/flows.jsonl --replay-interval $Interval
}

if (-not $Native) { docker compose -f infra\docker-compose.yml --env-file infra\.env --profile app up -d *> $null }
Write-Host "Demo database ready. Accounts: lab\replay\out\demo_credentials.txt" -ForegroundColor Green
