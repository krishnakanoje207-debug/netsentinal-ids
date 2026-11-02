# Local traffic evidence review

Verified 1 November 2026 (IST). This review describes the retained real capture,
not a fresh capture or a determination that traffic was malicious or benign.

## Host telemetry update — 2 November 2026

Sysmon is now installed and its service/driver are running. Applying
`sensors/sysmon/sysmonconfig.xml` enabled the selected network-connection events,
which were disabled in the initial default installation. A benign connection to
the project's Render host generated process-create record 50660 and network
record 50738 for the same PowerShell process (13940). The evidence summary is in
the ignored `lab/local/out/sysmon-verification.json`; raw command lines were not
copied into this report.

The installed Wazuh agent is prepared with one Sysmon `eventchannel` input, a
backed-up configuration, and the intended loopback manager address. It has an
enrollment key, and reports Active to the local manager as agent `001`. Docker
Desktop has been migrated to D: and updated to 4.97.0; Engine 29.9.2 runs with the
preserved D: disk. The indexer is green, Filebeat's TLS output test passes, and a
controlled benign command reached the alerts index as document
`jjsanaEBipqqdtg-zTjt` (Sysmon Event 1, record 332361, Wazuh rule 92052).
This is a pipeline check, not a confirmed intrusion. The installation discussion
below records the earlier 1 November state and is superseded by this update.

## Source and counting method

Read `lab/local/out/live/20261101-004559-000/flows.jsonl`, the sensor/startup
logs, current model cards and scoring/writer code. Queried `netsentinel_live`
using a PostgreSQL read-only transaction; credentials were not copied here.

The source was this computer's Windows pktmon capture, converted to PCAPNG and
scored by the sensor. Live flow labels are null. It was not a replay of the
training dataset. The retained database contains 162 alerts, created between
00:46:52 and 00:49:21 IST on 1 November (19:16:52–19:19:21 UTC on 31 October).

| Sensor outcome | Flow records | Database effect |
|---|---:|---|
| Complete, above fused threshold | 162 | Detection and alert |
| Cut short, above fused threshold | 58 | Detection only; alert suppressed |
| Complete, below threshold | 6 | Neither |
| Cut short, below threshold | 3 | Neither |
| Total | 229 | 220 detections, 162 alerts |

The sensor reported 46,370 packets and 61 cut-short records. That packet count is
the sensor's processing count, not a demonstrated count of unique wire packets.
Capture includes multiple Windows stack components; `--drop-repeats` removes
repeated packet observations, but does not turn flow windows into incidents.
There are 152 distinct flow IDs across all 229 records, 149 across the 220 stored
detections, and 115 across the 162 alerts. A flow ID encodes the directional
address/port/protocol tuple; repeated windows and reverse directions remain
separate records. There are zero incident rows.

All alerts have status `new` and source `this-pc`: 127 high, 26 low, five medium
and four critical. Severity is a software assignment. No alert has a linked IoC
match or signature corroboration; no host alert is present. These records do not
contain an analyst adjudication or establish a measured live false-positive rate.

## Why DNS and HTTPS appeared

| Observed tuple category | Alerts | What the data establishes |
|---|---:|---|
| UDP destination 53 | 75 | All from 10.205.93.31 to 10.205.93.60; DNS-port traffic |
| TCP destination 443 | 70 | HTTPS-port traffic; application/service identity unverified |
| UDP destination 5353 | 7 | mDNS-port traffic |
| UDP destination 138 | 2 | NetBIOS datagram-port traffic |
| TCP destination ephemeral ports | 8 | Reverse-direction records with source port 443 |

All 145 DNS/HTTPS-port alerts used active Tier A LightGBM 1.0.0 and Tier D
autoencoder 1.1.0. Tier A contributes weight 0.5 and Tier D 0.1, normalized over
the active tiers. Their thresholds are 0.004700197838483269 and
0.9900000014138836, producing fused threshold 0.16891683176771669. Tier B 1.2.0
and the Tier D isolation forest 1.0.2 were shadow models and did not move this
decision. Tier C was not running in the native path.

The DNS group's fused scores range from 0.171026 to 0.999276. Its Tier A scores
range from 0.007111 to 0.999933 and autoencoder scores from 0.990191 to 0.995991.
Stored Tier A SHAP contributions most often put packet rate (60/75), inbound
bytes (55/75) and outbound bytes per packet (47/75) in the top three positive
features. These are explanations of the benchmark model's output, not evidence
of malicious DNS content. No queried domains or payload evidence were retained
in these feature records.

The HTTPS group's fused scores range from 0.677970 to 0.999004. Its Tier A scores
range from 0.614804 to 1.000000 and autoencoder scores from 0.990019 to 0.994441.
Destination port is among the top three positive Tier A contributions in all
70 records; packet rate is in 66 and inbound bytes per packet in 37. This strong
dependence on port and flow shape is a reason to investigate dataset/domain
shift. TLS content is encrypted; this evidence does not identify the service,
process, requested resource or attacker. SHAP explains Tier A only, not the full
fused score, and its contributions are not probability percentages.

## Training data and practical limits

Tier A and the served Tier D artifacts use the processed NF-UNSW-NB15-v3
benchmark lineage, derived from the UNSW-NB15 2015 testbed captures (the local
dataset card gives 22 January–18 February 2015). Tier A's documented temporal split contains 1,655,797 training,
354,814 validation and 354,813 test flows; Tier D is trained on benign flows.
Tier A uses Platt calibration; Tier D uses benign empirical quantiles. A Tier D
value near 0.99 is an anomaly percentile relative to that baseline, not a 99%
probability of an attack. Tier B uses CIC-IDS2017 Friday packet captures split by
time, as recorded in `docs/PROJECT_STATUS.md`. Its model card names
`benign_1159-1208.pcapng`, `bot_1320-1336.pcapng`, `bot_1336-1350.pcapng`,
`bot_1350-1400.pcapng`, `ddos_1856-1859.pcapng` and `portscan_1751-1756.pcapng`;
the split has 139,248 training, 48,004 validation and 50,665 test flows. It uses
Platt calibration fitted with its validation split and remains shadow here. Raw
NF-ToN-IoT-v3 and NF-CICIDS2018-v3 files being present does not establish that the
active artifacts were trained on them. These calibration references are benchmark
validation traffic, not verified benign traffic from this computer. Neither the
live capture nor an analyst-labelled local calibration set was used to establish
these thresholds. Separate lab-baselined Tier D artifacts exist but were not
loaded by this native run.

Benchmark metrics and validation false-positive budgets do not establish local
accuracy. The existing cross-dataset evaluation already reports UNSW-trained
Tier A false-positive rates of 50.87% on NF-ToN-IoT-v3 and 89.33% on
NF-CICIDS2018-v3; those are documented transfer tests, not this PC's error rates.
This run alerted on 162/168 complete flow records (96.4%); the high
share and DNS/HTTPS feature patterns make false positives/domain shift a serious
concern. No ground truth or corroboration currently supports declaring all these
records attacks, or declaring all of them legitimate. Review endpoint processes,
DNS names and independent signature/host evidence before assigning incidents or
using this local baseline for automated response.

The sensor finished at 00:49:21 and its flow file has a `.done` marker. The launcher
logged that capture did not stop cleanly; a staging ETL remains. Its stop markers
and historical dashboard count do not prove the pktmon driver stopped. The
read-only `pktmon status` check returned `Failed to communicate with the PktMon
driver: Access is denied.` No current packet ingestion was verified in this
review. Capture-window restarts can leave gaps and truncate flows.

## Sysmon verification and installation instructions

The repository's `Sysmon64.exe` has a valid Microsoft Windows Publisher signature
and reports v15.22. `sc.exe query Sysmon64`, `Sysmon` and `SysmonDrv` returned
1060 (service absent); the Sysmon service and Operational-channel registry keys
were absent. No Sysmon Operational channel was listed. The existing `WazuhSvc`
is installed and was verified `STOPPED`. No software was installed by this review.

Sysmon is a command-line service installer, so double-clicking the executable
does not open a monitoring dashboard. The binary reports current schema 4.91;
`Sysmon64.exe -s 4.50` successfully prints schema 4.50, matching the well-formed
repository configuration. This checks schema availability and XML structure;
installation remains the final configuration-validation step. The configuration
records process creation and selected network connections, so it will not provide
every process-to-connection mapping, and it disables DNS-query events.

To install this configuration, open PowerShell **as administrator** and run:

```powershell
Set-Location -LiteralPath 'D:\intrusion detection system'
.\Sysmon64.exe -accepteula -i '.\sensors\sysmon\sysmonconfig.xml'
Get-Service -Name Sysmon64
sc.exe query SysmonDrv
.\Sysmon64.exe -c
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' |
    Select-Object LogName, IsEnabled, RecordCount
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1, 3
} -MaxEvents 10 | Select-Object TimeCreated, Id, Message
```

If Sysmon is already installed, update with
`.\Sysmon64.exe -c '.\sensors\sysmon\sysmonconfig.xml'` instead of `-i`.
Successful verification means the service/driver run, the channel is enabled,
and qualifying events arrive; an empty Event 3 result alone can reflect the
configuration's filters. To forward to Wazuh, configure the provided
`sensors/sysmon/ossec-localfile.xml` stanza in the agent and enroll it with a
reachable manager, then restart the actual service name `WazuhSvc`. Sysmon
installation alone does not establish Wazuh ingestion or dashboard correlation.

Microsoft documents the install/configuration switches, event channel and
network-event behavior in [Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
