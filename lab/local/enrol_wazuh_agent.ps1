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

# Reuse the existing local installers and services before downloading anything.
$sysmon = Join-Path $repo "Sysmon64.exe"
if (-not (Test-Path $sysmon)) { $sysmon = Join-Path $work "Sysmon64.exe" }
if (-not (Test-Path $sysmon)) {
    Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$work\Sysmon.zip"
    Expand-Archive "$work\Sysmon.zip" -DestinationPath $work -Force
}
$config = Join-Path $repo "sensors\sysmon\sysmonconfig.xml"
$operation = if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) { '-c' } else { '-i' }
$update = Start-Process -FilePath $sysmon -NoNewWindow -PassThru -ArgumentList '-accepteula', $operation, ('"' + $config + '"')
$null = $update.Handle
$update.WaitForExit()
if ($update.ExitCode -ne 0) { throw "Sysmon configuration failed (exit $($update.ExitCode))." }

# The agent, enrolled through the tunnel.
if (-not (Get-Service WazuhSvc -ErrorAction SilentlyContinue)) {
    $msi = Join-Path $work "wazuh-agent-$WazuhVersion.msi"
    if (-not (Test-Path $msi)) {
        Invoke-WebRequest "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion.msi" -OutFile $msi
    }
    $install = Start-Process msiexec.exe -PassThru -ArgumentList @(
        "/i", "`"$msi`"", "/q",
        "WAZUH_MANAGER=127.0.0.1", "WAZUH_REGISTRATION_SERVER=127.0.0.1",
        "WAZUH_AGENT_NAME=$AgentName"
    )
    $null = $install.Handle
    $install.WaitForExit()
    if ($install.ExitCode -notin @(0, 3010)) { throw "Wazuh installation failed (exit $($install.ExitCode))." }
}

# Read the Sysmon channel: the localfile block goes inside <ossec_config>, once.
$conf = "${env:ProgramFiles(x86)}\ossec-agent\ossec.conf"
$text = Get-Content $conf -Raw
$parsed = New-Object Xml.XmlDocument
$parsed.PreserveWhitespace = $true
$parsed.LoadXml($text)
$changed = $false
if (-not ($parsed.SelectNodes('//localfile/location') | Where-Object InnerText -eq 'Microsoft-Windows-Sysmon/Operational')) {
    $block = (Get-Content (Join-Path $repo "sensors\sysmon\ossec-localfile.xml") -Raw) -replace "(?s)<!--.*?-->", ""
    $inputXml = [xml]$block
    $null = $parsed.DocumentElement.AppendChild($parsed.ImportNode($inputXml.DocumentElement, $true))
    $changed = $true
}
foreach ($address in $parsed.SelectNodes('//client/server/address')) {
    if ($address.InnerText -eq '0.0.0.0') { $address.InnerText = '127.0.0.1'; $changed = $true }
}
if ($changed) {
    Copy-Item -LiteralPath $conf -Destination ($conf + '.netsentinel-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.bak')
    [IO.File]::WriteAllText($conf, $parsed.OuterXml, (New-Object Text.UTF8Encoding $false))
}

# Prepare collection even when the manager is not available, but do not start an
# unenrolled agent that can only retry against an absent server.
$servers = @($parsed.SelectNodes('//client/server'))
$ready = $false
foreach ($server in $servers) {
    $address = [string]$server.address
    $port = if ($server.port) { [int]$server.port } else { 1514 }
    $probe = New-Object Net.Sockets.TcpClient
    try {
        $connect = $probe.ConnectAsync($address, $port)
        if ($connect.Wait(1500) -and $probe.Connected) { $ready = $true }
    } catch { } finally { $probe.Dispose() }
}
if (-not $ready) {
    throw 'Sysmon and its Wazuh input are configured. No configured Wazuh manager accepts agent connections; start the manager before enrollment.'
}
Restart-Service -Name WazuhSvc
Get-Service WazuhSvc, Sysmon64 | Format-Table Name, Status
