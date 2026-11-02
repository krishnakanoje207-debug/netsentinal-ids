# Resident local monitor. Runs as the signed-in user; pktmon still asks for UAC.
# Install registers automatic startup at user sign-in and starts the task now.
# Start resumes a stopped installation. Stop preserves history. Uninstall removes
# automatic startup and requests orderly shutdown. No dashboard/browser is launched.
param([ValidateSet('Install', 'Start', 'Stop', 'Uninstall', 'Status', 'Run')]
      [string]$Action = 'Status', [ValidateRange(1, 3600)][int]$Window = 15)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$out = Join-Path $PSScriptRoot 'out\live'
$taskName = 'NetSentinel Local Monitor'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$powershell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
New-Item -ItemType Directory -Path $out -Force | Out-Null

function Request-Stop {
    New-Item -ItemType File -Path "$out\stop-request" -Force | Out-Null
    # Also notify capture directly, including while launcher startup is in progress.
    Get-ChildItem -LiteralPath $out -Directory | ForEach-Object {
        $windows = Join-Path $_.FullName 'windows'
        if ((Test-Path "$windows\started") -and -not (Test-Path "$windows\stop")) {
            New-Item -ItemType File -Path "$windows\stop-request" -Force | Out-Null
        }
    }
}

switch ($Action) {
    'Install' {
        $arguments = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Action Run -Window {1}' -f $PSCommandPath, $Window
        $taskAction = New-ScheduledTaskAction -Execute $powershell -Argument $arguments -WorkingDirectory $root
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
        $principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $trigger `
            -Principal $principal -Settings $settings -Description 'Real local IPv4 monitoring. Capture requires interactive UAC consent at each sign-in/start.' -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        Write-Host 'Installed and started. Approve the Windows capture prompt. Startup runs at sign-in, not before login.'
    }
    'Start' {
        Start-ScheduledTask -TaskName $taskName
        Write-Host 'Start requested. Approve the Windows capture prompt if a new watch is needed.'
    }
    'Stop' { Request-Stop; Write-Host 'Orderly stop requested; capture, sensor and writer will drain. History is preserved.' }
    'Uninstall' {
        Request-Stop
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host 'Automatic startup removed and orderly stop requested. History is preserved.'
    }
    'Status' {
        Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Select-Object TaskName, State
        if (Test-Path "$out\status.json") { Get-Content -LiteralPath "$out\status.json" }
    }
    'Run' {
        # Protect startup and the watch together. Task settings also reject duplicate starts.
        try { $residentLock = [IO.File]::Open("$out\resident.lock", 'OpenOrCreate', 'ReadWrite', 'None') }
        catch { exit 0 }
        try {
            # Refuse another launcher before clearing its stop request.
            try { $check = [IO.File]::Open("$out\watch.lock", 'OpenOrCreate', 'ReadWrite', 'None'); $check.Dispose() }
            catch { exit 0 }
            Remove-Item -LiteralPath "$out\stop-request" -ErrorAction SilentlyContinue
            Start-Transcript -Path "$out\resident.log" -Append | Out-Null
            # One attempt per invocation: denied UAC/failure never produces a prompt loop.
            & "$PSScriptRoot\watch_this_pc.ps1" -Live -NoDashboard -Window $Window
        } finally {
            Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
            $residentLock.Dispose()
        }
    }
}
