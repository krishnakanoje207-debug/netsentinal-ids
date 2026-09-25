# Build (or rebuild) the demonstration database from scratch.
#
#   powershell -ExecutionPolicy Bypass -File lab\replay\build_demo.ps1
#
# Drops and recreates the netsentinel_demo database - never the main one - then
# migrates it, creates one account per role, registers the trained models, and writes
# the replayed test-window flows through the real writer with explanations and MITRE
# techniques. New passwords go to lab\replay\out\demo_credentials.txt.
#
# Expects PostgreSQL running (start_demo.ps1 starts it) and the trained artefacts in
# artefacts\. The API container is stopped while the database is rebuilt, because a
# database with open connections cannot be dropped, and started again at the end. With
# the dev servers (start_demo.ps1 -Dev), close the API window first.

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

docker compose -f infra\docker-compose.yml --env-file infra\.env stop api *> $null

Step "recreate netsentinel_demo" {
    docker exec netsentinel-postgres-1 dropdb -U netsentinel --if-exists netsentinel_demo
    docker exec netsentinel-postgres-1 createdb -U netsentinel netsentinel_demo
}
Step "migrate" { Push-Location backend; uv run --no-sync alembic upgrade head; Pop-Location }

Remove-Item lab\replay\out\demo_credentials.txt -ErrorAction SilentlyContinue
Step "accounts" { uv run --no-sync python lab/replay/demo_users.py --out lab/replay/out/demo_credentials.txt }
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
Step "write explained alerts" {
    uv run --no-sync netsentinel-writer --card artefacts/tier_a/model_card.json `
        --family-card artefacts/family/model_card.json `
        --sensor-id $sensor --replay lab/replay/out/flows.jsonl
}

docker compose -f infra\docker-compose.yml --env-file infra\.env --profile app up -d *> $null
Write-Host "Demo database ready. Accounts: lab\replay\out\demo_credentials.txt" -ForegroundColor Green
