# Use Windows PowerShell 5.1: Defender's native module uses CIM.
# Status collection changes no security settings. Scans accept only the current
# user's registered/configured Downloads folders or Defender's built-in quick scan.
param([ValidateSet('None', 'Downloads', 'ConfiguredDownloads', 'Quick', 'Both')][string]$Scan = 'None')
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$out = Join-Path $PSScriptRoot 'out'
New-Item -ItemType Directory -Force $out | Out-Null
$lock = $null
try { $lock = [IO.File]::Open("$out\endpoint.lock", 'OpenOrCreate', 'ReadWrite', 'None') }
catch { throw 'An endpoint check or scan is already running.' }
try {
$snapshot = [ordered]@{
    collected_at = $null
    defender = @{ available = $false; status = $null; error = $null }
    smart_screen = @{}
    download_locations = @()
    scans = @{ downloads = @{ state = 'not_run' }; quick = @{ state = 'not_run' } }
    threats = @{ available = $false; active_count = $null; historical_detection_count = $null; error = $null }
    limitation = 'Point-in-time Windows status. Real-time Defender scans opened/downloaded files when enabled. SmartScreen policy values alone do not prove browser protection. Network scoring does not inspect encrypted page content or every download.'
}
if (Test-Path "$out\endpoint.json") {
    try {
        $previous = Get-Content "$out\endpoint.json" -Raw | ConvertFrom-Json
        foreach ($name in @('downloads', 'configured_downloads', 'quick')) {
            if ($previous.scans.$name) { $snapshot.scans[$name] = $previous.scans.$name }
        }
    } catch { }
}
function Add-DownloadLocation([string]$Path, [string]$Source) {
    if (-not $Path) { return }
    $entry = [ordered]@{ path = $Path; source = $Source; eligible = $false; error = $null }
    try {
        $full = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path))
        if ($full -notmatch '^[A-Za-z]:\\' -or $full.TrimEnd('\') -eq [IO.Path]::GetPathRoot($full).TrimEnd('\')) { throw 'Drive roots and network paths are not scan targets.' }
        foreach ($systemDir in @($env:WINDIR, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)) {
            if ($systemDir -and ($full.TrimEnd('\') -eq $systemDir -or $full.StartsWith($systemDir.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase))) { throw 'System directories are not download scan targets.' }
        }
        if ((Split-Path $full -Leaf) -notmatch '(?i)download') { throw 'Custom folder requires manual review: its name does not identify a Downloads directory.' }
        $item = Get-Item -LiteralPath $full -ErrorAction Stop
        if (-not $item.PSIsContainer) { throw 'Download target is not a folder.' }
        for ($ancestor = $item; $ancestor; $ancestor = $ancestor.Parent) {
            if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected or linked download paths require manual review.' }
        }
        $entry.path = $item.FullName
        $entry.eligible = $true
    } catch { $entry.error = $_.Exception.Message }
    $snapshot.download_locations += $entry
}
$known = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
Add-DownloadLocation $known.'{374DE290-123F-4565-9164-39C4925E467B}' 'Windows Downloads'
foreach ($browser in @(
    @('Chrome', "$env:LOCALAPPDATA\Google\Chrome\User Data"),
    @('Edge', "$env:LOCALAPPDATA\Microsoft\Edge\User Data"),
    @('Brave', "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data")
)) {
    if (-not (Test-Path -LiteralPath $browser[1])) { continue }
    foreach ($profile in @(Get-ChildItem -LiteralPath $browser[1] -Directory | Where-Object { $_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$' })) {
        try {
            $prefs = Get-Content -LiteralPath (Join-Path $profile.FullName 'Preferences') -Raw | ConvertFrom-Json
            Add-DownloadLocation $prefs.download.default_directory ($browser[0] + ' ' + $profile.Name)
        } catch { }
    }
}
function Save-Snapshot {
    $snapshot.collected_at = [DateTime]::UtcNow.ToString('o')
    $json = $snapshot | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText("$out\endpoint.json.tmp", $json, (New-Object Text.UTF8Encoding $false))
    Move-Item -LiteralPath "$out\endpoint.json.tmp" -Destination "$out\endpoint.json" -Force
}
function Read-Defender {
    try {
        $status = Get-MpComputerStatus
        $snapshot.defender = @{ available = $true; error = $null; status = @{
            antivirus_enabled = $status.AntivirusEnabled
            service_enabled = $status.AMServiceEnabled
            real_time_enabled = $status.RealTimeProtectionEnabled
            behavior_monitor_enabled = $status.BehaviorMonitorEnabled
            downloads_scan_enabled = $status.IoavProtectionEnabled
            network_inspection_enabled = $status.NISEnabled
            signatures_updated_at = if ($status.AntivirusSignatureLastUpdated) { $status.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') } else { $null }
            quick_scan_finished_at = if ($status.QuickScanEndTime -and $status.QuickScanEndTime.Year -gt 2000) { $status.QuickScanEndTime.ToUniversalTime().ToString('o') } else { $null }
            reboot_required = $status.RebootRequired
        } }
    } catch { $snapshot.defender = @{ available = $false; status = $null; error = $_.Exception.Message } }
    try {
        $active = @(Get-MpThreat -ErrorAction Stop | Where-Object { $_.IsActive })
        $history = @(Get-MpThreatDetection -ErrorAction Stop)
        $snapshot.threats = @{ available = $true; active_count = $active.Count; historical_detection_count = $history.Count; error = $null }
    } catch { $snapshot.threats = @{ available = $false; active_count = $null; historical_detection_count = $null; error = $_.Exception.Message } }
}
Read-Defender
foreach ($entry in @(
    @('windows_policy', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System', 'EnableSmartScreen'),
    @('windows_setting', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer', 'SmartScreenEnabled'),
    @('edge_machine_policy', 'HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'SmartScreenEnabled'),
    @('edge_user_policy', 'HKCU:\SOFTWARE\Policies\Microsoft\Edge', 'SmartScreenEnabled')
)) {
    $value = $null
    try { $value = Get-ItemPropertyValue -LiteralPath $entry[1] -Name $entry[2] -ErrorAction Stop } catch { }
    $snapshot.smart_screen[$entry[0]] = $value
}
Save-Snapshot
foreach ($name in @('downloads', 'configured_downloads', 'quick')) {
    $selected = $Scan.ToLowerInvariant() -eq $name -or ($Scan -eq 'ConfiguredDownloads' -and $name -eq 'configured_downloads') -or ($Scan -eq 'Both')
    if (-not $selected) { continue }
    $record = [ordered]@{ state = 'running'; started_at = [DateTime]::UtcNow.ToString('o'); finished_at = $null; path = $null; error = $null; result = $null }
    $snapshot.scans[$name] = $record
    Save-Snapshot
    try {
        if ($name -ne 'quick') {
            $targets = @($snapshot.download_locations | Where-Object { $_.eligible -and (($name -eq 'downloads' -and $_.source -eq 'Windows Downloads') -or ($name -eq 'configured_downloads' -and $_.source -ne 'Windows Downloads')) } | ForEach-Object { $_.path } | Select-Object -Unique)
            $windowsPath = @($snapshot.download_locations | Where-Object { $_.source -eq 'Windows Downloads' } | ForEach-Object { $_.path })
            if ($name -eq 'configured_downloads') { $targets = @($targets | Where-Object { $_ -notin $windowsPath }) }
            if ($name -eq 'downloads' -and -not $targets.Count) { throw 'Registered Downloads folder is unavailable or requires manual review.' }
            $record.folders = @()
            foreach ($target in $targets) {
                $folder = [ordered]@{ path = $target; state = 'running'; started_at = [DateTime]::UtcNow.ToString('o'); finished_at = $null; error = $null }
                $record.folders += $folder
                $record.path = $target
                Save-Snapshot
                try { Start-MpScan -ScanType CustomScan -ScanPath $target -ErrorAction Stop; $folder.state = 'completed' }
                catch { $folder.state = 'failed'; $folder.error = $_.Exception.Message }
                $folder.finished_at = [DateTime]::UtcNow.ToString('o')
                Save-Snapshot
            }
            if (-not $targets.Count) { $record.result = 'No additional eligible Downloads folder found.' }
            if (@($record.folders | Where-Object { $_.state -eq 'failed' }).Count) { throw 'One or more folder scans failed; inspect per-folder evidence.' }
        } else { Start-MpScan -ScanType QuickScan -ErrorAction Stop }
        $record.state = 'completed'
        if (-not $record.result) { $record.result = 'Defender scan command completed. Review Windows Security Protection history for detections and remediation; completion is not a guarantee of safety.' }
    } catch {
        $record.state = 'failed'
        $record.error = $_.Exception.Message
    }
    $record.finished_at = [DateTime]::UtcNow.ToString('o')
    Read-Defender
    Save-Snapshot
}
$snapshot | ConvertTo-Json -Depth 10
} finally { if ($lock) { $lock.Dispose() } }
