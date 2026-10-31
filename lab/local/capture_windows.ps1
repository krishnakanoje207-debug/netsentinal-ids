# Capture this computer's traffic as consecutive windows, for the continuous watch.
#
# Started elevated by watch_this_pc.ps1 -Live; not meant to be run by hand. pktmon can
# only write files, so the stream is cut into windows of -Seconds each: a window is
# converted to pcapng in a staging folder and then moved into -Dir in one rename, so the
# sensor reading -Dir never sees half a file. The next window starts before the last one
# is converted, keeping the gap between them to the time pktmon takes to stop and start.
#
# Stopping: the launcher creates "stop-request" in -Dir. The loop then ends the window it
# is in, publishes it, and creates "stop", which tells the sensor that once it has read
# what is left there is nothing more. Closing this window instead leaves pktmon running;
# "pktmon stop" in an administrator prompt ends it.

param([Parameter(Mandatory)][string]$Dir, [ValidateRange(1, 3600)][int]$Seconds = 15)

$ErrorActionPreference = "Continue"
$staging = Join-Path $Dir "staging"
New-Item -ItemType Directory -Force $staging | Out-Null
$request = Join-Path $Dir "stop-request"
$script:ownsCapture = $false

function Start-Window([int]$n) {
    $etl = Join-Path $staging ("window-{0:D6}.etl" -f $n)
    # Include stack components: native Wi-Fi NIC frames can still be encrypted.
    # The sensor accepts IPv4 Ethernet frames and drops repeated stack copies.
    pktmon start --capture --comp all --pkt-size 0 --file-name $etl | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "pktmon did not start (exit $LASTEXITCODE)" }
    $script:ownsCapture = $true
    return $etl
}

function Stop-Window {
    pktmon stop | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "pktmon did not stop (exit $LASTEXITCODE)" }
    $script:ownsCapture = $false
}

function Publish-Window([string]$etl) {
    $pcap = [IO.Path]::ChangeExtension($etl, ".pcapng")
    pktmon etl2pcap $etl --out $pcap | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "pktmon conversion failed (exit $LASTEXITCODE); kept $etl" }
    Remove-Item $etl -ErrorAction SilentlyContinue
    # A window with no packets converts to nothing; there is nothing to publish.
    if (Test-Path $pcap) { Move-Item $pcap $Dir -Force }
}

# pktmon is system-wide. If someone else owns a session, start fails; never stop theirs.
Write-Host "Watching this computer in $Seconds-second windows. Stop it from the window that started it."

$n = 1
$etl = $null
try {
    $etl = Start-Window $n
    New-Item -ItemType File -Force (Join-Path $Dir "started") | Out-Null
    while (-not (Test-Path $request)) {
        Start-Sleep -Seconds $Seconds
        Stop-Window
        $previous = $etl
        $etl = $null
        if (-not (Test-Path $request)) {
            $n++
            $etl = Start-Window $n
        }
        Publish-Window $previous
    }
} catch {
    Write-Host $_ -ForegroundColor Red
    Set-Content -LiteralPath (Join-Path $Dir "failed") -Value "$_" -Encoding utf8
} finally {
    if ($etl -and $script:ownsCapture) {
        Stop-Window
        Publish-Window $etl
    }
    New-Item -ItemType File -Force (Join-Path $Dir "stop") | Out-Null
}
if (Test-Path (Join-Path $Dir "failed")) { exit 1 }
