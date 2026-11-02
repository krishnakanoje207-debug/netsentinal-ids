Windows protection evidence is collected by `lab/local/check_endpoint.ps1` with
Windows PowerShell 5.1, using Defender's supported native cmdlets. The dashboard's
authenticated `GET /api/v1/endpoint/status` reads the fixed local JSON snapshot;
it cannot run commands or accept scan paths. The resident traffic watcher refreshes
the snapshot every minute. The API labels protection evidence older than three
minutes stale, and the watcher's heartbeat older than one minute stale.

Run a manual check from the project directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File lab/local/check_endpoint.ps1
```

Run the registered current user's Downloads folder, additional configured browser
Downloads folders, and then a quick scan:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File lab/local/check_endpoint.ps1 -Scan Both
```

Defender may require an administrator session. Errors are recorded rather than
reported as protection or clean results. Defender uses its existing remediation
policy. The script changes no antivirus settings and accepts no caller-selected
scan paths. Configured Chrome, Edge and Brave download paths are read from local
profile preferences. Roots, network shares, system directories, linked paths and
custom directory names without `download` are rejected for manual review. Each
eligible folder receives a separate state and timestamps. `-Scan ConfiguredDownloads`
scans only additional browser download directories; `-Scan Downloads` scans only
the registered Windows Downloads directory. A lock prevents overlapping collectors/scans. Results persist in the
git-ignored `lab/local/out/endpoint.json` with start/finish timestamps.

Scan completion means the native scan command finished; it does not prove a file
or this computer is safe. Review Windows Security > Virus & threat protection >
Protection history for detections and remediation. Threat counts are Defender's
current active count and historical detection count, not findings attributed to a
particular scan. A killed collector may leave a running record: check its timestamp
and Windows Security rather than assuming progress. A quick scan is not a full
disk scan. Defender applies configured exclusions and engine limitations.

Real-time protection and IOAV state establish native file/download protection only
when available and enabled. Registry SmartScreen policy values are evidence, not
proof of browser enforcement. Missing values are unknown. This dashboard does not
intercept every URL, decrypt HTTPS, inspect private browser sessions, or promise
every download is safe. The traffic classifier and native malware engine have
different coverage.

Native references: [Get-MpComputerStatus](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus),
[Start-MpScan](https://learn.microsoft.com/en-us/powershell/module/defender/start-mpscan),
[Get-MpThreatDetection](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpthreatdetection),
[Edge SmartScreen policy](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/smartscreenenabled).
