"""Exercise Windows launcher behavior without starting services or capturing traffic."""

import shutil
import socket
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
POWERSHELL = shutil.which("powershell")
pytestmark = pytest.mark.skipif(not POWERSHELL, reason="Windows PowerShell required")


def run_ps(source: str):
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", source],
        cwd=ROOT, capture_output=True, text=True, timeout=20,
    )


def test_all_launchers_parse_in_windows_powershell():
    result = run_ps(r"""        $ErrorActionPreference = 'Stop'
        foreach ($file in @('lab/local/watch_this_pc.ps1',
                            'lab/local/monitor_this_pc.ps1', 'lab/local/check_endpoint.ps1',
                            'lab/local/enrol_wazuh_agent.ps1',
                            'lab/local/capture_windows.ps1', 'lab/replay/start_demo.ps1')) {
            $tokens = $null; $errors = $null
            $null = [Management.Automation.Language.Parser]::ParseFile(
                (Resolve-Path $file), [ref]$tokens, [ref]$errors)
            if ($errors) { throw ($errors | Out-String) }
        }
    """)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("failure", ["", "start", "conversion"])
def test_capture_owns_only_its_session_and_publishes_complete_windows(tmp_path, failure):
    target = str(tmp_path).replace("'", "''")
    result = run_ps(r"""
        $ErrorActionPreference = 'Stop'
        $testDir = '__DIR__'
        $testFailure = '__FAILURE__'
        function pktmon {
            switch ($args[0]) {
                'start' {
                    if ($testFailure -eq 'start') { $global:LASTEXITCODE = 5; return }
                    $i = [Array]::IndexOf($args, '--file-name')
                    Set-Content -LiteralPath $args[$i + 1] -Value 'captured ETL'
                }
                'stop' { Add-Content -LiteralPath "$testDir/stops.txt" -Value 'stop' }
                'etl2pcap' {
                    if ($testFailure -eq 'conversion') { $global:LASTEXITCODE = 6; return }
                    $i = [Array]::IndexOf($args, '--out')
                    Set-Content -LiteralPath $args[$i + 1] -Value 'converted pcap'
                }
                default { throw 'Unexpected pktmon command' }
            }
            $global:LASTEXITCODE = 0
        }
        function Start-Sleep { Set-Content -LiteralPath "$testDir/stop-request" -Value '' }
        & './lab/local/capture_windows.ps1' -Dir $testDir -Seconds 1
    """.replace("__DIR__", target).replace("__FAILURE__", failure))
    assert (tmp_path / "stop").exists(), result.stderr
    if failure == "start":
        assert result.returncode != 0
        assert not (tmp_path / "started").exists()
        assert not (tmp_path / "stops.txt").exists(), "Must not stop another pktmon session"
    else:
        assert (tmp_path / "started").exists()
        assert (tmp_path / "stops.txt").read_text().splitlines() == ["stop"]
        if failure == "conversion":
            assert result.returncode != 0
            assert (tmp_path / "staging/window-000001.etl").exists()
            assert not (tmp_path / "window-000001.pcapng").exists()
        else:
            assert result.returncode == 0, result.stderr
            assert (tmp_path / "window-000001.pcapng").read_text().strip() == "converted pcap"
            assert not (tmp_path / "staging/window-000001.etl").exists()


def test_dashboard_child_gets_only_its_proxy_setting_and_parent_secrets_are_restored():
    result = run_ps(r"""
        $ErrorActionPreference = 'Stop'
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            (Resolve-Path 'lab/replay/start_demo.ps1'), [ref]$tokens, [ref]$errors)
        $definition = $ast.Find({ param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Start-DevServer'
        }, $true)
        Invoke-Expression $definition.Extent.Text
        function Start-Process {
            param($ArgumentList, $WorkingDirectory, [switch]$PassThru, [switch]$WindowStyle)
            if ($env:NETSENTINEL_DATABASE_URL -or $env:NETSENTINEL_JWT_SECRET -or
                $env:NETSENTINEL_GOOGLE_CLIENT_ID -or $env:PGPASSWORD) {
                throw 'Dashboard inherited server credentials'
            }
            if ($env:NETSENTINEL_API -ne 'http://127.0.0.1:8014') { throw 'Wrong proxy' }
        }
        $env:NETSENTINEL_DATABASE_URL = 'test-database-secret'
        $env:NETSENTINEL_JWT_SECRET = 'test-signing-secret'
        $env:NETSENTINEL_GOOGLE_CLIENT_ID = 'test-google-id'
        $env:PGPASSWORD = 'test-postgres-password'
        Start-DevServer 'test-command' '.' @{
            NETSENTINEL_API = 'http://127.0.0.1:8014'
        } -ClearSettings
        if ($env:PGPASSWORD -ne 'test-postgres-password' -or
            $env:NETSENTINEL_DATABASE_URL -ne 'test-database-secret' -or
            $env:NETSENTINEL_GOOGLE_CLIENT_ID -ne 'test-google-id') {
            throw 'Parent environment not restored'
        }
    """)
    assert result.returncode == 0, result.stderr


def test_occupied_ports_are_skipped_without_reusing_existing_dashboard():
    result = run_ps(r"""
        $ErrorActionPreference = 'Stop'
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            (Resolve-Path 'lab/replay/start_demo.ps1'), [ref]$tokens, [ref]$errors)
        $definition = $ast.Find({ param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Find-FreePort'
        }, $true)
        Invoke-Expression $definition.Extent.Text
        function Get-NetTCPConnection {
            param($LocalPort, $State, $ErrorAction)
            if ($LocalPort -in @(8010, 8011, 5173)) { return @{ OwningProcess = 42 } }
        }
        if ((Find-FreePort 8010) -ne 8012 -or (Find-FreePort 5173) -ne 5174) {
            throw 'Occupied port selected'
        }
    """)
    assert result.returncode == 0, result.stderr


def test_endpoint_labels_combine_only_observed_roles_and_never_read_dns_cache():
    result = run_ps(r"""
        $ErrorActionPreference = 'Stop'
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            (Resolve-Path 'lab/replay/start_demo.ps1'), [ref]$tokens, [ref]$errors)
        $definition = $ast.Find({ param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Get-LocalEndpointLabels'
        }, $true)
        Invoke-Expression $definition.Extent.Text
        function Get-DnsClientCache { throw 'Must not read browsing history' }
        function Get-NetIPConfiguration {
            @{
                IPv4Address = @{ IPAddress = '10.0.0.20' }
                IPv4DefaultGateway = @{ NextHop = '10.0.0.1' }
                DNSServer = @{ ServerAddresses = @('10.0.0.1', '10.0.0.53', '10.0.0.20') }
            }, @{
                IPv4Address = @{ IPAddress = '10.0.0.20' }
                DNSServer = @{ ServerAddresses = @('10.0.0.53') }
            }
        }
        $labels = Get-LocalEndpointLabels
        if ($labels.Count -ne 3) { throw 'Unexpected endpoint disclosure' }
        if ($labels['10.0.0.1'] -ne 'Network gateway / Configured DNS server') { throw 'Missing gateway role' }
        if ($labels['10.0.0.53'] -ne 'Configured DNS server') { throw 'Invented gateway role' }
        if ($labels['10.0.0.20'] -ne "This computer ($env:COMPUTERNAME) / Configured DNS server") { throw 'Lost computer role' }
    """)
    assert result.returncode == 0, result.stderr


def test_installed_host_setup_preserves_config_and_waits_for_manager(tmp_path):
    launcher = tmp_path / 'lab/local'
    launcher.mkdir(parents=True)
    shutil.copyfile(ROOT / 'lab/local/enrol_wazuh_agent.ps1', launcher / 'enrol_wazuh_agent.ps1')
    sensor = tmp_path / 'sensors/sysmon'
    sensor.mkdir(parents=True)
    shutil.copyfile(ROOT / 'sensors/sysmon/ossec-localfile.xml', sensor / 'ossec-localfile.xml')
    (tmp_path / 'Sysmon64.exe').touch()
    agent = tmp_path / 'ossec-agent'
    agent.mkdir()
    with socket.socket() as closed_port:
        closed_port.bind(('127.0.0.1', 0))
        port = closed_port.getsockname()[1]
        config = agent / 'ossec.conf'
        original = (f'<ossec_config><client><server><address>0.0.0.0</address>'
                    f'<port>{port}</port></server></client></ossec_config>\n'
                    '<!-- Preserve this trailing operator comment. -->\n')
        config.write_text(original, encoding='utf-8')
        target = str(tmp_path).replace("'", "''")
        result = run_ps(r"""
            $ErrorActionPreference = 'Stop'
            ${env:ProgramFiles(x86)} = '__DIR__'
            $env:TEMP = '__DIR__'
            $global:sysmonCalls = 0
            function Get-Service { param($Name, $ErrorAction); return @{ Name = $Name } }
            function Invoke-WebRequest { throw 'Must reuse installed services without downloading' }
            function Restart-Service { throw 'Must not start an agent without a reachable manager' }
            function Start-Process {
                param($FilePath, $ArgumentList, [switch]$NoNewWindow, [switch]$PassThru)
                if ((Split-Path $FilePath -Leaf) -ne 'Sysmon64.exe') { throw 'Unexpected installer launch' }
                $global:sysmonCalls++
                $process = [pscustomobject]@{ Handle = 1; ExitCode = 0 }
                $process | Add-Member ScriptMethod WaitForExit { }
                return $process
            }
            1..2 | ForEach-Object {
                try {
                    & '__DIR__/lab/local/enrol_wazuh_agent.ps1'
                    throw 'Missing manager was not reported'
                } catch {
                    if ($_ -notlike '*No configured Wazuh manager accepts agent connections*') { throw }
                }
            }
            if ($global:sysmonCalls -ne 2) { throw 'Installed Sysmon was not reused' }
        """.replace('__DIR__', target))
    assert result.returncode == 0, result.stderr
    from xml.etree import ElementTree
    parsed = ElementTree.parse(config)
    assert parsed.findtext('client/server/address') == '127.0.0.1'
    inputs = parsed.findall('localfile')
    assert len(inputs) == 1
    assert inputs[0].findtext('location') == 'Microsoft-Windows-Sysmon/Operational'
    assert inputs[0].findtext('log_format') == 'eventchannel'
    assert 'Preserve this trailing operator comment.' in config.read_text(encoding='utf-8')
    backups = list(agent.glob('ossec.conf.netsentinel-*.bak'))
    assert len(backups) == 1
    assert backups[0].read_text(encoding='utf-8') == original
