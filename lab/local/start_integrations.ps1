# Start the local Wazuh importer and approved metadata-only cloud sync.
# Run as this Windows user; no administrator privileges or capture changes needed.
param(
    [string]$Database = 'netsentinel_live',
    [string]$CloudOrigin = 'https://netsentinel-api-15ig.onrender.com',
    [ValidatePattern('^[0-9]{1,32}$')][string]$AgentId = '001',
    [ValidateRange(0,2147483647)][int]$AssetId = 0
)
$ErrorActionPreference = 'Stop'
if ($Database -notmatch '^[a-z][a-z0-9_]*$') { throw 'Invalid database name.' }
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$python = Join-Path $root '.venv\Scripts\python.exe'
$outDir = Join-Path $PSScriptRoot 'out\integrations'
$secretFile = Join-Path $outDir 'telemetry.env'
if (-not (Test-Path $secretFile)) { throw 'Configure out\integrations\telemetry.env before starting.' }
$mutex = New-Object Threading.Mutex($false, 'Local\NetSentinelIntegrations')
try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
if (-not $locked) { $mutex.Dispose(); Write-Host 'Integrations already running.'; exit 0 }
$children = @{}
try {
    Set-Location $root
    foreach ($line in Get-Content (Join-Path $root '.env.local')) {
        if ($line -match '^(NETSENTINEL_DATABASE_URL|NETSENTINEL_JWT_SECRET)=(.*)$') {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        }
    }
    $env:NETSENTINEL_DATABASE_URL = $env:NETSENTINEL_DATABASE_URL -replace '/[^/]+$', "/$Database"
    foreach ($line in Get-Content $secretFile) {
        if ($line -match '^NETSENTINEL_TELEMETRY_TOKEN=(.*)$') { $env:NETSENTINEL_TELEMETRY_TOKEN = $Matches[1] }
    }
    $wazuh = '-u -m netsentinel_api.sync_wazuh --container netsentinel-wazuh.manager-1 --follow --docker "D:\DockerDesktop\resources\bin\docker.exe" --agent-id ' + $AgentId
    if ($AssetId -gt 0) { $wazuh += " --asset-id $AssetId" }
    $commands = @{
        wazuh = $wazuh
        telemetry = "-u -m netsentinel_api.sync_telemetry --origin $CloudOrigin --state `"$outDir\$Database-state.json`" --follow"
    }
    Write-Host 'Local Wazuh import and metadata-only cloud sync started.'
    while ($true) {
        foreach ($name in $commands.Keys) {
            if (-not $children.ContainsKey($name) -or $children[$name].HasExited) {
                $children[$name] = Start-Process -FilePath $python -ArgumentList $commands[$name] -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput "$outDir\$name.log" -RedirectStandardError "$outDir\$name.err"
            }
        }
        Start-Sleep -Seconds 15
    }
} finally {
    foreach ($child in $children.Values) {
        if (-not $child.HasExited) { Stop-Process -Id $child.Id -ErrorAction SilentlyContinue }
    }
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
