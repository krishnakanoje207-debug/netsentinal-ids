# Start the demonstration.
#
#   powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1         # Docker (default)
#   powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1 -Dev    # dev servers, hot reload
#
# Default: the app profile in Docker - PostgreSQL, the API and the nginx-served
# dashboard - at https://127.0.0.1:5180. Its containers restart with Docker, so after
# the first run this mostly just opens the browser.
#
# -Dev: the API and the Vite dev server on the host, for working on the dashboard, at
# http://127.0.0.1:5173. It stops the Docker API first, because both use port 8010.
#
# -Native: the dev servers with no Docker at all, on a PostgreSQL installed on the host
# (binaries in $env:NETSENTINEL_PG_BIN, cluster in $env:NETSENTINEL_PG_DATA; both default
# under D:\netsentinel-data). For a laptop whose free memory cannot hold Docker's VM:
# PostgreSQL, the API and Vite together take about 400 MB.
#
# Either way the data is the demo database built by build_demo.ps1; accounts are in
# lab\replay\out\demo_credentials.txt.

param([switch]$Dev, [switch]$Native)

# Native tools (docker, npm) write progress to stderr. Windows PowerShell turns that
# into errors under "Stop", so failures are judged by exit code instead.
$ErrorActionPreference = "Continue"

# 8010 rather than uvicorn's usual 8000: other projects on this machine publish 8000
# from Docker, and a demo that dies on "address in use" is worse than an odd port.
$apiPort = 8010
$root = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $root
$compose = @("compose", "-f", "infra\docker-compose.yml", "--env-file", "infra\.env")

function Test-Docker { docker info *> $null; return $LASTEXITCODE -eq 0 }

function Wait-Healthy($url) {
    Write-Host "waiting for $url ..."
    $deadline = (Get-Date).AddSeconds(120)
    do {
        Start-Sleep -Seconds 2
        # curl.exe rather than Invoke-WebRequest: Windows PowerShell 5.1 cannot skip
        # the check on the dashboard's self-signed certificate, and -k can.
        $up = (curl.exe -ks -o NUL -w "%{http_code}" --max-time 2 $url) -eq "200"
    } until ($up -or (Get-Date) -gt $deadline)
    return $up
}

if ($Native) {
    $Dev = $true
    $pgBin = if ($env:NETSENTINEL_PG_BIN) { $env:NETSENTINEL_PG_BIN } else { "D:\netsentinel-data\pgsql\bin" }
    $pgData = if ($env:NETSENTINEL_PG_DATA) { $env:NETSENTINEL_PG_DATA } else { "D:\netsentinel-data\pgdata" }
    $url = (Get-Content .env.local | Where-Object { $_ -match "^NETSENTINEL_DATABASE_URL=" }) -replace "^[^=]+=", ""
    $null = $url -match "@([^:/]+):(\d+)/"
    & "$pgBin\pg_isready.exe" -h $Matches[1] -p $Matches[2] *> $null
    if ($LASTEXITCODE -ne 0) {
        # Started detached with its own log, so closing this window leaves it running.
        Start-Process -WindowStyle Hidden "$pgBin\pg_ctl.exe" -ArgumentList "-D", "`"$pgData`"", "-l", "`"$pgData\..\postgres.log`"", "start"
        Write-Host "waiting for PostgreSQL..."
        do { Start-Sleep -Seconds 1; & "$pgBin\pg_isready.exe" -h $Matches[1] -p $Matches[2] *> $null } until ($LASTEXITCODE -eq 0)
    }
} elseif (-not (Test-Docker)) {
    Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    Write-Host "waiting for Docker..."
    while (-not (Test-Docker)) { Start-Sleep -Seconds 3 }
}

if (-not $Dev) {
    # --build reuses cached layers, so it is quick unless the code changed - and then
    # rebuilding is exactly what is wanted.
    docker @compose --profile app up -d --build
    if ($LASTEXITCODE -ne 0) { Write-Host "The app profile did not start." -ForegroundColor Red; exit 1 }
    if (-not (Wait-Healthy "https://127.0.0.1:5180/api/v1/health")) {
        Write-Host "The dashboard did not answer; see: docker compose -f infra\docker-compose.yml logs api" -ForegroundColor Red
        exit 1
    }
    Start-Process "https://127.0.0.1:5180"
    Write-Host "Dashboard: https://127.0.0.1:5180   API: http://127.0.0.1:$apiPort/api/v1/docs"
    exit 0
}

# --- dev servers ----------------------------------------------------------------

if (-not $Native) {
    docker @compose stop api dashboard *> $null
    docker @compose --profile storage up -d postgres
    if ($LASTEXITCODE -ne 0) { Write-Host "PostgreSQL did not start." -ForegroundColor Red; exit 1 }
}

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

if (-not (Wait-Healthy "http://127.0.0.1:$apiPort/api/v1/health")) {
    Write-Host "The API did not answer; read its window for the error." -ForegroundColor Red
    exit 1
}
Start-Process "http://127.0.0.1:5173"
Write-Host "Dashboard (dev): http://127.0.0.1:5173   API: http://127.0.0.1:$apiPort/api/v1/docs"
