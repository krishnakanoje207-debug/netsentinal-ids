# sensors

The live telemetry edge:

- the capture agent that feeds `netsentinel_core.features.extractor.FlowTracker`
  from a live interface and publishes flows to Redpanda,
- Suricata 8 rule configuration (ET Open),
- Zeek 7 + FoxIO JA4 scripts,
- Wazuh agent and Sysmon configuration.

Built on **D3** and **D8**. Depends on `netsentinel-core` only, because it has to
stay installable on a constrained host.
