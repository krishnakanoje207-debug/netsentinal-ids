# Start the offline demonstration: PostgreSQL, the API and the dashboard.
#
#   powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1
#
# Expects the demo database built as in the README ("Without the VM: replaying the
# dataset"). Opens http://127.0.0.1:5173; accounts are in lab\replay\out\demo_credentials.txt.
# Close the two windows it opens to stop the API and the dashboard.

# Native tools (docker, npm) write progress to stderr. Windows PowerShell turns that
# into errors under "Stop", so failures are judged by exit code instead.
$ErrorActionPreference = "Continue"

# 8010 rather than uvicorn's usual 8000: other projects on this machine publish 8000
# from Docker, and a demo that dies on "address in use" is worse than an odd port.
$apiPort = 8010
$root = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $root

function Test-Docker { docker info *> $null; return $LASTEXITCODE -eq 0 }

if (-not (Test-Docker)) {
    Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    Write-Host "waiting for Docker..."
    while (-not (Test-Docker)) { Start-Sleep -Seconds 3 }
}

docker compose -f infra\docker-compose.yml --env-file infra\.env --profile storage up -d postgres
if ($LASTEXITCODE -ne 0) { Write-Host "PostgreSQL did not start." -ForegroundColor Red; exit 1 }

# The API reads NETSENTINEL_* from the environment; the demo points it at its own database.
$vars = @{}
foreach ($line in (Get-Content .env.local | Where-Object { $_ -match "^NETSENTINEL_" })) {
    $k, $v = $line -split "=", 2
    $vars[$k] = $v
}
$db = $vars["NETSENTINEL_DATABASE_URL"] -replace "/[^/]+$", "/netsentinel_demo"

$api = @"
`$env:UV_CACHE_DIR='D:/uv-cache'
`$env:NETSENTINEL_DATABASE_URL='$db'
`$env:NETSENTINEL_JWT_SECRET='$($vars["NETSENTINEL_JWT_SECRET"])'
`$env:NETSENTINEL_PROMOTION_MIN_LABELLED='5'
`$env:NETSENTINEL_PROMOTION_MIN_SHADOW_DAYS='0'
Set-Location '$root'
uv run --no-sync uvicorn netsentinel_api.app:app --host 127.0.0.1 --port $apiPort
"@
Start-Process powershell -ArgumentList "-NoExit", "-Command", $api

$web = "`$env:NETSENTINEL_API='http://127.0.0.1:$apiPort'; Set-Location '$root\frontend'; npm run dev -- --host 127.0.0.1 --port 5173"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $web

Write-Host "waiting for the API..."
$deadline = (Get-Date).AddSeconds(90)
do {
    Start-Sleep -Seconds 2
    try { $up = (Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$apiPort/api/v1/health" -TimeoutSec 2).StatusCode -eq 200 }
    catch { $up = $false }
} until ($up -or (Get-Date) -gt $deadline)
if (-not $up) { Write-Host "The API did not answer; read its window for the error." -ForegroundColor Red; exit 1 }

Start-Process "http://127.0.0.1:5173"
Write-Host "Dashboard: http://127.0.0.1:5173   API: http://127.0.0.1:$apiPort/api/v1/docs"
