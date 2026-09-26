# Score this computer's own traffic and show it on the dashboard.
#
#   powershell -ExecutionPolicy Bypass -File lab\local\watch_this_pc.ps1              # capture 120 s
#   powershell -ExecutionPolicy Bypass -File lab\local\watch_this_pc.ps1 -Seconds 300
#   powershell -ExecutionPolicy Bypass -File lab\local\watch_this_pc.ps1 -Pcap some.pcapng
#
# Then: lab\replay\start_demo.ps1 -Native -Database netsentinel_mypc
#
# The full design captures on a Linux sensor and passes flows through Redpanda. Neither
# runs on this laptop, so this is the same path with two substitutions: Windows' own
# packet monitor (pktmon) captures, and the scored flows go to a file the writer replays.
# The sensor, the models, the writer and the dashboard are the real ones.
#
# Steps:
#   1. Capture with pktmon for -Seconds (Windows asks for administrator rights once; only
#      the capture runs elevated). Browse, stream, update - use the machine normally.
#   2. Rebuild the netsentinel_mypc database - never the demo one - with one account per
#      role, this computer as the estate, and the models registered in their demo modes.
#   3. Start a private API on port 8011, so the sensor reads each model's mode from the
#      registry exactly as it does on the VM, then stop it.
#   4. Score the capture (Tiers A, B, D; Tier B scores in shadow, since real packets
#      exist here) and write the alerts with explanations and MITRE techniques.
#
# The capture holds your real traffic. It stays in lab\local\out\, which git ignores;
# delete it when you are done. Only IPv4 is scored: the feature extractor does not parse
# IPv6, and with TLS nothing inside encrypted payloads is read by anything here.
#
# Expect false alarms. The models learned "normal" from a 2015 university testbed whose
# benign traffic is FTP, DNS, HTTP, AIM and BitTorrent - its training split holds not one
# benign flow to port 443 - so Tiers A and D find ordinary HTTPS browsing foreign. Moved to
# other networks the same model scored 0.74 and 0.05 (docs/evaluation/REPORT.md). That is
# what this run shows, and why every model has to earn its place in shadow mode.

param([int]$Seconds = 120, [string]$Pcap = "")

$ErrorActionPreference = "Continue"
$root = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $root
$env:UV_CACHE_DIR = "D:/uv-cache"
$env:PYTHONIOENCODING = "utf-8"
$out = "$root\lab\local\out"
New-Item -ItemType Directory -Force $out | Out-Null

function Step($name, [scriptblock]$body) {
    Write-Host "== $name"
    & $body
    if ($LASTEXITCODE -ne 0) { Write-Host "failed: $name" -ForegroundColor Red; exit 1 }
}

# --- 1. capture -------------------------------------------------------------------

if (-not $Pcap) {
    $etl = "$out\capture.etl"
    $Pcap = "$out\capture.pcapng"
    Remove-Item $etl, $Pcap -ErrorAction SilentlyContinue
    # NICs only, whole packets. Run in its own elevated window, which closes when done.
    $capture = @"
pktmon start --capture --comp nics --pkt-size 0 --file-name '$etl' | Out-Null
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
$Pcap = Resolve-Path $Pcap
Write-Host "capture: $Pcap ($([math]::Round((Get-Item $Pcap).Length / 1MB, 1)) MB)"

# --- 2. the database --------------------------------------------------------------

$vars = @{}
foreach ($line in (Get-Content .env.local | Where-Object { $_ -match "^NETSENTINEL_" })) {
    $k, $v = $line -split "=", 2
    $vars[$k] = $v
}
$env:NETSENTINEL_DATABASE_URL = $vars["NETSENTINEL_DATABASE_URL"] -replace "/[^/]+$", "/netsentinel_mypc"
$env:NETSENTINEL_JWT_SECRET = $vars["NETSENTINEL_JWT_SECRET"]
$pgBin = if ($env:NETSENTINEL_PG_BIN) { $env:NETSENTINEL_PG_BIN } else { "D:\netsentinel-data\pgsql\bin" }
$null = $env:NETSENTINEL_DATABASE_URL -match "://([^:]+):([^@]+)@([^:/]+):(\d+)/"
$pg = @("-h", $Matches[3], "-p", $Matches[4], "-U", $Matches[1])
$env:PGPASSWORD = $Matches[2]
& "$pgBin\pg_isready.exe" @pg *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "PostgreSQL is not running; start it with lab\replay\start_demo.ps1 -Native" -ForegroundColor Red
    exit 1
}

Step "recreate netsentinel_mypc" {
    & "$pgBin\dropdb.exe" @pg --if-exists --force netsentinel_mypc
    & "$pgBin\createdb.exe" @pg netsentinel_mypc
}
Step "migrate" { Push-Location backend; uv run --no-sync alembic upgrade head; Pop-Location }
Remove-Item "$out\credentials.txt" -ErrorAction SilentlyContinue
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
$sensorHost = ($rows[1] -split ",")[0]
$sensor = (uv run --no-sync python lab/replay/register_sensor.py --host $sensorHost | Select-Object -Last 1).Trim()

# --- 3. a private API for the model registry --------------------------------------

$token = -join ((1..48) | ForEach-Object { "{0:x}" -f (Get-Random -Maximum 16) })
$env:NETSENTINEL_SENSOR_TOKEN = $token
$registryPort = 8011
$api = Start-Process -PassThru -WindowStyle Hidden uv -ArgumentList "run", "--no-sync", "uvicorn",
    "netsentinel_api.app:app", "--host", "127.0.0.1", "--port", "$registryPort"
$deadline = (Get-Date).AddSeconds(60)
do {
    Start-Sleep -Seconds 1
    $up = (curl.exe -s -o NUL -w "%{http_code}" --max-time 2 "http://127.0.0.1:$registryPort/api/v1/health") -eq "200"
} until ($up -or (Get-Date) -gt $deadline)
if (-not $up) { Stop-Process -Id $api.Id -Force; Write-Host "the registry API did not start" -ForegroundColor Red; exit 1 }

# --- 4. score and write -----------------------------------------------------------

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
