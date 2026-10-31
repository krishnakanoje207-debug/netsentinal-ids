# Watch this computer's real IPv4 traffic continuously and open its dashboard.
#
#   powershell -ExecutionPolicy Bypass -File lab\local\watch_this_pc.ps1
#   powershell -ExecutionPolicy Bypass -File lab\local\watch_this_pc.ps1 -Window 30
#
# Ctrl+C requests an orderly capture -> sensor -> writer shutdown. Only pktmon asks
# for administrator rights. netsentinel_live and out/live/credentials.txt persist;
# captured windows and scored flows stay under out/live/<run>/ (git ignored).
#
# Explicit finite/file scoring uses a separate legacy database, netsentinel_mypc:
#   powershell -ExecutionPolicy Bypass -File lab\local\watch_this_pc.ps1 -Once -Seconds 120
#   powershell -ExecutionPolicy Bypass -File lab\local\watch_this_pc.ps1 -Pcap some.pcapng
# Reopen either database's dashboard using start_demo.ps1 -Native -Database <name>.
# -Fresh only resets the explicit finite/file database; it cannot erase live history.
#
# pktmon publishes complete capture windows; one sensor maintains flows across them,
# and the writer follows the sensor's scored output. No dataset replay or traffic
# generation runs here. Inventory and accounts describe this local installation.
# Only IPv4 is scored; encrypted payload contents are not decrypted. Models learned
# a 2015 testbed: expect false alarms on ordinary browsing (docs/evaluation/REPORT.md).

param([ValidateRange(1, 86400)][int]$Seconds = 120, [string]$Pcap = "", [switch]$Live,
      [ValidateRange(1, 3600)][int]$Window = 15, [switch]$Fresh, [switch]$Once)

if ($Live -and ($Once -or $Pcap)) { throw "-Live cannot be combined with -Once or -Pcap." }
$Live = -not ($Once -or $Pcap)
if ($Live -and $Fresh) { throw "Live history is persistent; -Fresh applies only to explicit -Once/-Pcap runs." }

$ErrorActionPreference = "Continue"
$root = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $root
$env:UV_CACHE_DIR = "D:/uv-cache"
$env:PYTHONIOENCODING = "utf-8"
$database = if ($Live) { "netsentinel_live" } else { "netsentinel_mypc" }
$out = if ($Live) { "$root\lab\local\out\live" } else { "$root\lab\local\out" }
New-Item -ItemType Directory -Force $out | Out-Null
if ($Live) {
    # FileShare.None makes a second launcher fail before it touches this session's files.
    try { $watchLock = [IO.File]::Open("$out\watch.lock", 'OpenOrCreate', 'ReadWrite', 'None') }
    catch { throw "A live watch is already running. Stop it from its launcher before starting another." }
}

try {
function Step($name, [scriptblock]$body) {
    Write-Host "== $name"
    & $body
    if ($LASTEXITCODE -ne 0) { Write-Host "failed: $name" -ForegroundColor Red; exit 1 }
}

# --- 1. capture -------------------------------------------------------------------

if ($Live) {
    # Nothing to capture up front: the windows arrive while the sensor runs (section 4).
} elseif (-not $Pcap) {
    $etl ="$out\capture.etl"
    $Pcap = "$out\capture.pcapng"
    Remove-Item $etl, $Pcap -ErrorAction SilentlyContinue
    # Whole packets across the stack, including Ethernet frames above native Wi-Fi.
    $capture = @"
pktmon start --capture --comp all --pkt-size 0 --file-name '$etl' | Out-Null
Write-Host 'Capturing for $Seconds seconds. Use the computer normally; this window closes by itself.'
Start-Sleep -Seconds $Seconds
pktmon stop | Out-Null
pktmon etl2pcap '$etl' --out '$Pcap' | Out-Null
"@
    $script = "$out\capture.ps1"
    Set-Content -Path $script -Value $capture -Encoding utf8
    Write-Host "== capture ($Seconds s; Windows will ask for administrator rights)"
    try {
        Start-Process powershell -Verb RunAs -Wait -ArgumentList "-ExecutionPolicy", "Bypass", "-File", "`"$script`""
    } catch {
        Write-Host "The capture needs administrator rights, and they were refused." -ForegroundColor Red
        exit 1
    }
    Remove-Item $etl -ErrorAction SilentlyContinue
    if (-not (Test-Path $Pcap)) { Write-Host "pktmon produced no capture." -ForegroundColor Red; exit 1 }
}
if (-not $Live) {
    $Pcap = Resolve-Path $Pcap
    Write-Host "capture: $Pcap ($([math]::Round((Get-Item $Pcap).Length / 1MB, 1)) MB)"
}

# --- 2. the database --------------------------------------------------------------

$vars = @{}
foreach ($line in (Get-Content .env.local | Where-Object { $_ -match "^NETSENTINEL_" })) {
    $k, $v = $line -split "=", 2
    $vars[$k] = $v
}
$env:NETSENTINEL_DATABASE_URL = $vars["NETSENTINEL_DATABASE_URL"] -replace "/[^/]+$", "/$database"
$env:NETSENTINEL_JWT_SECRET = $vars["NETSENTINEL_JWT_SECRET"]
$pgBin = if ($env:NETSENTINEL_PG_BIN) { $env:NETSENTINEL_PG_BIN } else { "D:\netsentinel-data\pgsql\bin" }
if ($env:NETSENTINEL_DATABASE_URL -notmatch "://([^:]+):([^@]+)@([^:/]+):(\d+)/") { throw "Invalid NETSENTINEL_DATABASE_URL in .env.local." }
$pg = @("-h", $Matches[3], "-p", $Matches[4], "-U", $Matches[1])
$env:PGPASSWORD = $Matches[2]
& "$pgBin\pg_isready.exe" @pg *> $null
if ($LASTEXITCODE -ne 0) {
    $pgData = if ($env:NETSENTINEL_PG_DATA) { $env:NETSENTINEL_PG_DATA } else { "D:\netsentinel-data\pgdata" }
    Start-Process -WindowStyle Hidden "$pgBin\pg_ctl.exe" -ArgumentList "-D", "`"$pgData`"", "-l", "`"$pgData\..\postgres.log`"", "start"
    Write-Host "== waiting for PostgreSQL"
    $deadline = (Get-Date).AddSeconds(60)
    do { Start-Sleep -Seconds 1; & "$pgBin\pg_isready.exe" @pg *> $null } until ($LASTEXITCODE -eq 0 -or (Get-Date) -gt $deadline)
    if ($LASTEXITCODE -ne 0) { throw "PostgreSQL did not start; read $pgData\..\postgres.log." }
}

# A continuous watch keeps what it has seen, and the accounts whose passwords are in
# credentials.txt: demo_users.py writes passwords only for the accounts it creates.
$exists = (& "$pgBin\psql.exe" @pg -d postgres -Atc "select 1 from pg_database where datname = '$database'") -eq "1"
if ($LASTEXITCODE -ne 0) { throw "Cannot check the local database." }
$reuse = $exists -and -not $Fresh
if ($reuse) {
    Write-Host "== keeping $database"
} else {
    Step "create $database" {
        if ($Fresh) {
            & "$pgBin\dropdb.exe" @pg --if-exists $database
            if ($LASTEXITCODE -ne 0) { throw "Could not drop $database." }
        }
        & "$pgBin\createdb.exe" @pg $database
    }
}
Step "migrate" { Push-Location backend; uv run --no-sync alembic upgrade head; Pop-Location }
if (-not $reuse) {
    Remove-Item "$out\credentials.txt" -ErrorAction SilentlyContinue
}
Step "accounts" { uv run --no-sync python lab/replay/demo_users.py --out "$out\credentials.txt" }

# The estate is this computer: every IPv4 address it holds, so alerts on it link to it.
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$rows = @("hostname,ip_address,os,criticality")
Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
    ForEach-Object { $rows += "$($env:COMPUTERNAME.ToLower())-$($_.InterfaceAlias -replace '[^A-Za-z0-9]', '').ToLower(),$($_.IPAddress),$os,high" }
Set-Content -Path "$out\inventory.csv" -Value $rows -Encoding utf8
Step "import this computer" { uv run --no-sync python -m netsentinel_api.sync_assets --csv "$out\inventory.csv" }

Step "register Tier A" { uv run --no-sync netsentinel-register-model artefacts/tier_a/model_card.json --mode active }
Step "register Tier D autoencoder" { uv run --no-sync netsentinel-register-model artefacts/tier_d_ae/model_card.json --mode active }
Step "register Tier D forest" { uv run --no-sync netsentinel-register-model artefacts/tier_d/model_card.json }
Step "register Tier B" { uv run --no-sync netsentinel-register-model artefacts/tier_b/model_card.json }
# The sensor sits on the first of this computer's addresses: that is where it captured.
if ($rows.Count -lt 2) { throw "This computer has no usable IPv4 address to capture." }
$sensorHost = ($rows[1] -split ",")[0]
$sensor = (uv run --no-sync python lab/replay/register_sensor.py --host $sensorHost | Select-Object -Last 1).Trim()
if ($LASTEXITCODE -ne 0 -or -not $sensor) { throw "Could not register this computer's sensor." }

# --- 3. a private API for the model registry --------------------------------------

$token = -join ((1..48) | ForEach-Object { "{0:x}" -f (Get-Random -Maximum 16) })
$env:NETSENTINEL_SENSOR_TOKEN = $token
$registryPort = 8011
while (Get-NetTCPConnection -LocalPort $registryPort -State Listen -ErrorAction SilentlyContinue) { $registryPort++ }
$api = Start-Process -PassThru -WindowStyle Hidden -RedirectStandardError "$out\registry.log" uv -ArgumentList "run", "--no-sync", "uvicorn",
    "netsentinel_api.app:app", "--host", "127.0.0.1", "--port", "$registryPort"
$deadline = (Get-Date).AddSeconds(60)
do {
    Start-Sleep -Seconds 1
    $up = (curl.exe -s -o NUL -w "%{http_code}" --max-time 2 "http://127.0.0.1:$registryPort/api/v1/health") -eq "200"
} until ($up -or $api.HasExited -or (Get-Date) -gt $deadline)
if (-not $up -or $api.HasExited) {
    if (-not $api.HasExited) { taskkill /PID $api.Id /T /F *> $null }
    throw "The registry API did not start; see $out\registry.log."
}

# --- 4. score and write -----------------------------------------------------------

if ($Live) {
    # Relative paths: Start-Process does not quote arguments, and the repository's path
    # has spaces in it. The elevated capture starts in System32, so it gets quoted ones.
    $run = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $liveDir = "lab\local\out\live\$run\windows"
    $flows = "lab\local\out\live\$run\flows.jsonl"
    New-Item -ItemType Directory -Force $liveDir | Out-Null
    $sensorProc = $null
    $writerProc = $null
    $capture = $null
    $why = "stopped"
    try {
    Write-Host "== start the sensor"
    $sensorProc = Start-Process -PassThru -WindowStyle Hidden -RedirectStandardError "$out\sensor.log" uv -ArgumentList `
        "run", "--no-sync", "python", "-m", "netsentinel_sensor.agent", "--pcap-dir", $liveDir, "--drop-repeats",
        "--models", "artefacts/tier_a/model_card.json", "artefacts/tier_d_ae/model_card.json",
        "artefacts/tier_d/model_card.json", "artefacts/tier_b/model_card.json",
        "--registry-url", "http://127.0.0.1:$registryPort", "--sensor-name", "this-pc", "--out", $flows
    # The sensor opens its output only after it has read the registry, so once the file
    # exists the registry API has done its job.
    $deadline = (Get-Date).AddSeconds(120)
    while (-not (Test-Path $flows) -and -not $sensorProc.HasExited -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 1 }
    taskkill /PID $api.Id /T /F *> $null
    $env:NETSENTINEL_SENSOR_TOKEN = $null
    if (-not (Test-Path $flows)) {
        throw "The sensor did not start; see $out\sensor.log."
    }

    Write-Host "== start the writer"
    $writerProc = Start-Process -PassThru -WindowStyle Hidden -RedirectStandardError "$out\writer.log" uv -ArgumentList `
        "run", "--no-sync", "netsentinel-writer", "--card", "artefacts/tier_a/model_card.json",
        "--family-card", "artefacts/family/model_card.json", "--sensor-id", $sensor, "--replay", $flows, "--follow"

    Write-Host "== start the capture ($Window-second windows; Windows will ask for administrator rights)"
    try {
        $capture = Start-Process -PassThru -Verb RunAs -WindowStyle Minimized powershell -ArgumentList "-ExecutionPolicy", "Bypass",
            "-File", "`"$root\lab\local\capture_windows.ps1`"", "-Dir", "`"$root\$liveDir`"", "-Seconds", "$Window"
    } catch {
        $capture = $null
        Write-Host "The capture needs administrator rights, and they were refused." -ForegroundColor Red
    }

    if (-not $capture) { throw "Live capture was not started." }
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Test-Path "$liveDir\started") -and -not $capture.HasExited -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 1 }
    if (-not (Test-Path "$liveDir\started") -or $capture.HasExited) { throw "pktmon did not start. Check the capture window; another pktmon session may already be running." }
    if ($capture) {
        & "$root\lab\replay\start_demo.ps1" -Native -DashboardOnly -Database $database
        if ($LASTEXITCODE -ne 0) { throw "The local dashboard did not start." }
        Set-Location $root
        Write-Host "Watching. Accounts: $out\credentials.txt. Ctrl+C here stops the watch." -ForegroundColor Green
    }

        while ($capture) {
            Start-Sleep -Seconds 15
            if ($capture.HasExited) {
                if ((Test-Path "$liveDir\stop-request") -and -not (Test-Path "$liveDir\failed")) { break }
                throw "The capture stopped; see $liveDir\failed if present."
            }
            if ($sensorProc.HasExited) { throw "The sensor stopped; see $out\sensor.log." }
            if ($writerProc.HasExited) { throw "The writer stopped; see $out\writer.log." }
            $alerts = & "$pgBin\psql.exe" @pg -d $database -Atc "select count(*) from alerts"
            $last = Select-String -Path "$out\sensor.log" -Pattern "sensor: " | Select-Object -Last 1
            $stats = if ($last) { ($last.Line -split "sensor: ", 2)[1] } else { "no window read yet" }
            Write-Host "$(Get-Date -Format HH:mm:ss)  $alerts alerts stored  $stats"
        }
    } finally {
        # In order, so nothing captured is lost: the capture publishes its last window and
        # says so, the sensor reads what is left and ends, and only then is the writer told
        # that the flows file is complete.
        Write-Host "== stopping ($why)"
        New-Item -ItemType File -Force "$liveDir\stop-request" | Out-Null
        if ($capture -and -not $capture.HasExited) { $null = $capture.WaitForExit(($Window + 60) * 1000) }
        if (-not (Test-Path "$liveDir\stop")) {
            if ($capture) { Write-Host "The capture did not stop cleanly; run 'pktmon stop' as administrator." -ForegroundColor Yellow }
            New-Item -ItemType File -Force "$liveDir\stop" | Out-Null
        }
        if ($sensorProc -and -not $sensorProc.WaitForExit(120000)) { taskkill /PID $sensorProc.Id /T /F *> $null }
        New-Item -ItemType File -Force "$flows.done" | Out-Null
        if ($writerProc -and -not $writerProc.WaitForExit(120000)) { taskkill /PID $writerProc.Id /T /F *> $null }
        if (-not $api.HasExited) { taskkill /PID $api.Id /T /F *> $null }
        $env:NETSENTINEL_SENSOR_TOKEN = $null
        Write-Host "Stopped. Alerts stay in $database; the dashboard remains available. Captured files: $root\lab\local\out\live\$run"
    }
    exit 0
}

Write-Host "== score the capture"
uv run --no-sync python -m netsentinel_sensor.agent --pcap "$Pcap" --drop-repeats `
    --models artefacts/tier_a/model_card.json artefacts/tier_d_ae/model_card.json `
             artefacts/tier_d/model_card.json artefacts/tier_b/model_card.json `
    --registry-url "http://127.0.0.1:$registryPort" --sensor-name this-pc --out "$out\flows.jsonl"
$scored = $LASTEXITCODE
# uv starts uvicorn as a child; stop the whole tree.
taskkill /PID $api.Id /T /F *> $null
$env:NETSENTINEL_SENSOR_TOKEN = $null
if ($scored -ne 0) { Write-Host "failed: score the capture" -ForegroundColor Red; exit 1 }

Step "write explained alerts" {
    uv run --no-sync netsentinel-writer --card artefacts/tier_a/model_card.json `
        --family-card artefacts/family/model_card.json `
        --sensor-id $sensor --replay "$out\flows.jsonl"
}

Write-Host "Ready. Start the dashboard on it:" -ForegroundColor Green
Write-Host "  powershell -ExecutionPolicy Bypass -File lab\replay\start_demo.ps1 -Native -Database netsentinel_mypc"
Write-Host "Accounts: $out\credentials.txt"
} finally {
    if ($watchLock) { $watchLock.Dispose() }
}
