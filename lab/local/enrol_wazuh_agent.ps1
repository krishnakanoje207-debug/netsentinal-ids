<#
Enrol this laptop with the VM's Wazuh manager, with Sysmon feeding it (F3 on Windows).

Run elevated (installing a service needs it), with the SSH tunnel to the VM open:

    ssh -i $HOME\.ssh\netsentinel_key -N -L 1514:127.0.0.1:1514 -L 1515:127.0.0.1:1515 azureuser@<vm>
    powershell -ExecutionPolicy Bypass -File lab\local\enrol_wazuh_agent.ps1

The manager publishes 1514 (events) and 1515 (enrolment) on the VM's 127.0.0.1 only, so
the agent is pointed at this machine's end of the tunnel. Sysmon gets the repository's
trimmed config (process creation and network connections), and the agent is told to
read its channel, which Wazuh's stock rules (61600 range) decode.
#>
param(
    [string]$AgentName = $env:COMPUTERNAME,
    [string]$WazuhVersion = "4.14.8-1"
)
$ErrorActionPreference = "Stop"
$repo = Resolve-Path "$PSScriptRoot\..\.."
$work = Join-Path $env:TEMP "netsentinel-wazuh"
New-Item -ItemType Directory -Force $work | Out-Null

# Sysmon, with the repository's config. -c updates the config of one already installed.
$sysmon = Join-Path $work "Sysmon64.exe"
if (-not (Test-Path $sysmon)) {
    Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$work\Sysmon.zip"
    Expand-Archive "$work\Sysmon.zip" -DestinationPath $work -Force
}
$config = Join-Path $repo "sensors\sysmon\sysmonconfig.xml"
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    & $sysmon -accepteula -c $config
} else {
    & $sysmon -accepteula -i $config
}

# The agent, enrolled through the tunnel.
$msi = Join-Path $work "wazuh-agent-$WazuhVersion.msi"
if (-not (Test-Path $msi)) {
    Invoke-WebRequest "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion.msi" -OutFile $msi
}
Start-Process msiexec.exe -Wait -ArgumentList @(
    "/i", "`"$msi`"", "/q",
    "WAZUH_MANAGER=127.0.0.1", "WAZUH_REGISTRATION_SERVER=127.0.0.1",
    "WAZUH_AGENT_NAME=$AgentName"
)

# Read the Sysmon channel: the localfile block goes inside <ossec_config>, once.
$conf = "${env:ProgramFiles(x86)}\ossec-agent\ossec.conf"
$text = Get-Content $conf -Raw
if ($text -notmatch "Microsoft-Windows-Sysmon/Operational") {
    $block = (Get-Content (Join-Path $repo "sensors\sysmon\ossec-localfile.xml") -Raw) -replace "(?s)<!--.*?-->", ""
    $text = $text -replace "</ossec_config>\s*$", "$($block.Trim())`r`n</ossec_config>`r`n"
    Set-Content $conf $text -Encoding ascii
}

Restart-Service -Name WazuhSvc
Get-Service WazuhSvc, Sysmon64 | Format-Table Name, Status
