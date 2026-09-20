# infra

Deployment, not application code:

- `docker-compose` files with resource profiles, so one service group can be
  brought up at a time when memory is tight,
- the ClickHouse DDL for `network_flows`, `suricata_events`, `zeek_logs`,
- Grafana dashboards and provisioning,
- Vector pipeline configuration.

Built from **D2** onwards, once the cloud VM exists. Nothing here runs on the
laptop.
