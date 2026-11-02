# Default launch: watch this PC's real traffic (lab/local/watch_this_pc.ps1).
#
#   powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1
#
# Dataset demonstrations are explicit and use the database built by build_demo.ps1:
#   powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1 -Demo          # Docker
#   powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1 -Demo -Dev     # host dev servers
#   powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1 -Demo -Native  # no Docker
# Demo accounts are in lab/replay/out/demo_credentials.txt.
#
# Reopen a specific local dashboard without starting capture or seeding anything:
#   powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1 -Native -Database netsentinel_live
# Native PostgreSQL paths default to D:\netsentinel-data; override NETSENTINEL_PG_BIN
# and NETSENTINEL_PG_DATA if needed. API/dashboard use free loopback ports starting
# at 8010/5173, so an existing dashboard cannot silently show another database.

param([switch]$Dev, [switch]$Native, [string]$Database = "netsentinel_demo",
      [switch]$Demo, [switch]$DashboardOnly)

# The ordinary laptop launch observes this PC. Dataset demonstrations must be explicit.
$DashboardOnly = $DashboardOnly -or $PSBoundParameters.ContainsKey("Database")
if (-not $Demo -and -not $DashboardOnly) {
    & "$PSScriptRoot\..\local\watch_this_pc.ps1" -Live
    exit $LASTEXITCODE
}
if ($DashboardOnly -and -not $Native) { throw "-DashboardOnly requires -Native." }
if ($Database -notmatch '^[a-z][a-z0-9_]*$') { throw "Invalid database name." }

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

function Find-FreePort([int]$preferred) {
    while (Get-NetTCPConnection -LocalPort $preferred -State Listen -ErrorAction SilentlyContinue) { $preferred++ }
    return $preferred
}

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
    $apiPort = Find-FreePort $apiPort
    $dashboardPort = Find-FreePort 5173
    $pgBin = if ($env:NETSENTINEL_PG_BIN) { $env:NETSENTINEL_PG_BIN } else { "D:\netsentinel-data\pgsql\bin" }
    $pgData = if ($env:NETSENTINEL_PG_DATA) { $env:NETSENTINEL_PG_DATA } else { "D:\netsentinel-data\pgdata" }
    $url = (Get-Content .env.local | Where-Object { $_ -match "^NETSENTINEL_DATABASE_URL=" }) -replace "^[^=]+=", ""
    $null = $url -match "@([^:/]+):(\d+)/"
    & "$pgBin\pg_isready.exe" -h $Matches[1] -p $Matches[2] *> $null
    if ($LASTEXITCODE -ne 0) {
        # Started detached with its own log, so closing this window leaves it running.
        Start-Process -WindowStyle Hidden "$pgBin\pg_ctl.exe" -ArgumentList "-D", "`"$pgData`"", "-l", "`"$pgData\..\postgres.log`"", "start"
        Write-Host "waiting for PostgreSQL..."
        $deadline = (Get-Date).AddSeconds(60)
        do { Start-Sleep -Seconds 1; & "$pgBin\pg_isready.exe" -h $Matches[1] -p $Matches[2] *> $null } until ($LASTEXITCODE -eq 0 -or (Get-Date) -gt $deadline)
        if ($LASTEXITCODE -ne 0) { throw "PostgreSQL did not start; read $pgData\..\postgres.log." }
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
$db = $vars["NETSENTINEL_DATABASE_URL"] -replace "/[^/]+$", "/$Database"

function Start-DevServer($command, $workingDirectory, $environment, [switch]$ClearSettings) {
    # PowerShell 5.1 has no Start-Process -Environment. The child inherits this
    # temporary snapshot; restore the launcher before starting the next child.
    $names = @($environment.Keys)
    if ($ClearSettings) {
        $names += @(Get-ChildItem Env:NETSENTINEL_* | ForEach-Object { $_.Name })
        $names += "PGPASSWORD"
    }
    $original = @{}
    foreach ($name in $names) { $original[$name] = [Environment]::GetEnvironmentVariable($name, "Process") }
    try {
        # The dashboard must not inherit database credentials or the signing secret.
        if ($ClearSettings) {
            foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $null, "Process") }
        }
        foreach ($entry in $environment.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
        }
        Start-Process powershell -PassThru -WindowStyle Hidden -ArgumentList "-NoProfile", "-Command", "$command; exit `$LASTEXITCODE" -WorkingDirectory $workingDirectory
    } finally {
        foreach ($entry in $original.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
        }
    }
}

$apiEnvironment = @{
    UV_CACHE_DIR = "D:/uv-cache"
    NETSENTINEL_DATABASE_URL = $db
    NETSENTINEL_JWT_SECRET = $vars["NETSENTINEL_JWT_SECRET"]
}
foreach ($entry in $vars.GetEnumerator()) { if (-not $apiEnvironment.ContainsKey($entry.Key)) { $apiEnvironment[$entry.Key] = $entry.Value } }
function Get-LocalEndpointLabels {
    # Network settings only: never disclose the machine's browsing/DNS cache.
    # Accumulate roles independently so DNS configuration cannot imply a gateway.
    $roles = @{}
    foreach ($config in (Get-NetIPConfiguration -ErrorAction SilentlyContinue)) {
        foreach ($group in @(
            @{ Addresses = @($config.IPv4Address.IPAddress) + @($config.IPv6Address.IPAddress); Role = "This computer ($env:COMPUTERNAME)" },
            @{ Addresses = @($config.IPv4DefaultGateway.NextHop) + @($config.IPv6DefaultGateway.NextHop); Role = 'Network gateway' },
            @{ Addresses = @($config.DNSServer.ServerAddresses); Role = 'Configured DNS server' }
        )) {
            foreach ($address in $group.Addresses) {
                if ($address) { $roles[$address] = @($roles[$address]) + $group.Role }
            }
        }
    }
    $labels = @{}
    foreach ($address in $roles.Keys) {
        $labels[$address] = (@($roles[$address] | Where-Object { $_ } | Select-Object -Unique) -join ' / ')
    }
    return $labels
}
if ($Native -and $Database -eq 'netsentinel_live') {
    $apiEnvironment.NETSENTINEL_LOCAL_BROWSER_AUDIT = '1'
    $apiEnvironment.NETSENTINEL_ENDPOINT_LABELS = ConvertTo-Json -Compress -InputObject (Get-LocalEndpointLabels)
}
if ($Demo) {
    $apiEnvironment.NETSENTINEL_PROMOTION_MIN_LABELLED = "5"
    $apiEnvironment.NETSENTINEL_PROMOTION_MIN_SHADOW_DAYS = "0"
}
$apiProc = Start-DevServer "uv run --no-sync uvicorn netsentinel_api.app:app --host 127.0.0.1 --port $apiPort" $root $apiEnvironment
if (-not $dashboardPort) { $dashboardPort = Find-FreePort 5173 }
$dashboardProc = Start-DevServer "npm run dev -- --host 127.0.0.1 --port $dashboardPort --strictPort" "$root\frontend" @{
    NETSENTINEL_API = "http://127.0.0.1:$apiPort"
} -ClearSettings

if (-not (Wait-Healthy "http://127.0.0.1:$apiPort/api/v1/health") -or $apiProc.HasExited) {
    throw "The API did not start on its assigned port $apiPort."
}
if (-not (Wait-Healthy "http://127.0.0.1:$dashboardPort") -or $dashboardProc.HasExited) {
    throw "The dashboard did not start on its assigned port $dashboardPort."
}
Start-Process "http://127.0.0.1:$dashboardPort"
Write-Host "Dashboard ($Database): http://127.0.0.1:$dashboardPort   API: http://127.0.0.1:$apiPort/api/v1/docs"
