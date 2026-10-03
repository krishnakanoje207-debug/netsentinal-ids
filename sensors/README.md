# sensors

The live telemetry edge:

- the capture agent that feeds `netsentinel_core.features.extractor.FlowTracker`
  from a live interface and publishes flows to Redpanda,
- Suricata 8 rule configuration (ET Open),
- Zeek 7 + FoxIO JA4 scripts,
- Wazuh agent and Sysmon configuration.

Built on **D3** and **D8**. Depends on `netsentinel-core` only, because it has to
stay installable on a constrained host.

## Capturing on Windows

Windows' built-in `pktmon` captures only to files, so the agent cannot read a live
pipe there as it reads `tcpdump` on Linux. Instead an elevated loop writes
consecutive capture windows into a folder, each as `<name>.pcapng.part` renamed to
`<name>.pcapng` once complete, and the agent reads that folder:

    python -m netsentinel_sensor.agent --pcap-dir D:/capture --drop-repeats \
        --models ... --out flows.jsonl

The windows are read in name order as one packet stream, so a connection that
spans two windows is one flow; each window is deleted once read, since it holds
the host's real traffic. The second or so of traffic `pktmon` misses while it
restarts reads as a pause inside a flow, and a connection that opened in it is
seen without its SYN and, unlike one under way when capture began, can alert.
The run ends on Ctrl+C or, once every window is read, when the loop leaves a
file named `stop` in the folder; either way flows still open are marked cut
short. `--drop-repeats` removes the copies `pktmon` logs of each packet.
