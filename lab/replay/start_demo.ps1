# Start the offline demonstration: PostgreSQL, the API and the dashboard.
#
#   powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1
#
# Expects the demo database built as in the README ("Without the VM: replaying the
# dataset"). Opens http://127.0.0.1:5173; accounts are in lab\replay\out\demo_credentials.txt.
# Close the two windows it opens to stop the API and the dashboard.

$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $root

if (-not (docker info 2>$null)) {
    Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    Write-Host "waiting for Docker..."
    while (-not (docker info 2>$null)) { Start-Sleep -Seconds 3 }
}
docker compose -f infra\docker-compose.yml --env-file infra\.env --profile storage up -d postgres

# The API reads NETSENTINEL_* from the environment; the demo points it at its own database.
$env_lines = Get-Content .env.local | Where-Object { $_ -match "^NETSENTINEL_" }
$vars = @{}
foreach ($line in $env_lines) { $k, $v = $line -split "=", 2; $vars[$k] = $v }
$db = $vars["NETSENTINEL_DATABASE_URL"] -replace "/[^/]+$", "/netsentinel_demo"

$api = @"
`$env:UV_CACHE_DIR='D:/uv-cache'
`$env:NETSENTINEL_DATABASE_URL='$db'
`$env:NETSENTINEL_JWT_SECRET='$($vars["NETSENTINEL_JWT_SECRET"])'
`$env:NETSENTINEL_PROMOTION_MIN_LABELLED='5'
`$env:NETSENTINEL_PROMOTION_MIN_SHADOW_DAYS='0'
Set-Location '$root'
uv run --no-sync uvicorn netsentinel_api.app:app --host 127.0.0.1 --port 8000
"@
Start-Process powershell -ArgumentList "-NoExit", "-Command", $api
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\frontend'; npm run dev -- --host 127.0.0.1 --port 5173"

Start-Sleep -Seconds 8
Start-Process "http://127.0.0.1:5173"
