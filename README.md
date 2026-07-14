# FlowGuard Lite

FlowGuard Lite is a lightweight network visibility, anomaly detection, and DDoS detection product for homelabs, prosumer networks, small offices, clinics, shops, and small technical teams.

It is built for people who need to understand suspicious network behavior without running a full SOC stack, Kafka, ClickHouse, Elasticsearch, or a heavyweight SIEM.

FlowGuard Lite receives router/firewall flow telemetry, optional passive capture metadata, optional Suricata events, and UniFi SIEM/syslog events. It builds device-level behavioral baselines, detects anomalies and flood patterns, and explains why a device looks suspicious.

## What It Does

| Area | Current support |
| --- | --- |
| Flow telemetry | NetFlow v5/v9, IPFIX, sFlow |
| Passive capture | Optional libpcap-based TCP/UDP metadata reduction |
| UniFi | IPFIX where available, plus SIEM/syslog Activity Logging event ingestion |
| IDS correlation | Optional Suricata `eve.json` ingestion |
| Detection | Device baselines, new destination/port/internal peer, traffic spikes, beaconing, fan-out, nighttime activity, profile changes, DDoS flood patterns |
| Evidence | Every anomaly includes an explanation and bounded evidence |
| Storage | SQLite daily shards by default, bounded by retention; optional DuckDB read acceleration |
| UI | Web console for Overview, Traffic, Devices, Alerts, Policies, Notifications, Audit, and Settings |
| Notifications | Slack/Discord webhook, generic webhook, and Telegram channel targets |
| Deployment | Docker Compose and native Go/Vite development workflows |

FlowGuard Lite is alert-only. It can generate firewall rule templates, but it does not automatically block traffic.

## Why This Exists

Small networks often have good routers and firewalls but poor visibility into device behavior. FlowGuard Lite focuses on:

- device-centric explanations instead of opaque scoring;
- bounded local storage instead of raw flow retention forever;
- small hardware such as Intel N100-class boxes with 2 GB RAM allocated;
- practical integrations for UniFi, MikroTik, OPNsense, pfSense, Suricata, Slack/Discord, Telegram, and generic webhooks;
- a single-node deployment model that stays understandable.

## Performance Snapshot

FlowGuard Lite has a repeatable benchmark harness and published capacity guide. The current measured baseline on N100-class hardware with 2 GB RAM is:

| Path | Measured result |
| --- | ---: |
| Flow aggregation | 4.53M flows/sec in Docker |
| NetFlow v9 decode | 1.72M packets/sec in Docker |
| UniFi syslog parse/classify | 511K lines/sec in Docker |
| Anomaly engine evaluation | 78.5K flows/sec in Docker |
| SQLite 1,000-flow batch write | 6.16 ms native baseline |
| Overview summary API | 48.4 us |
| Traffic records API | 325.1 us |

Recommended N100-class deployment ranges:

| Deployment | Active devices | Average flow rate | Recommended backend |
| --- | ---: | ---: | --- |
| Home lab / prosumer | 1-50 | 10-50 flows/sec | SQLite daily shards |
| Small office / clinic | 50-150 | 50-150 flows/sec | SQLite daily shards |
| Technical lab | 150-250 | 150-350 flows/sec | SQLite, optional DuckDB reads |

Details: [Capacity & Performance Guide](docs/capacity-guide.md) and [Performance Baselines](docs/performance-baselines.md).

## Quickstart

### Docker Compose

```bash
make docker-build
make docker-up
```

Open:

```txt
http://localhost:8080
```

On first run, create the local admin password in the setup screen. The UI then guides you through local subnets, storage, collectors, detection thresholds, and notification targets.

Default listener ports:

| Port | Protocol | Purpose |
| ---: | --- | --- |
| 8080 | TCP | REST API and web UI |
| 2055 | UDP | NetFlow v5/v9 and IPFIX |
| 6343 | UDP | sFlow |
| 5514 | UDP | UniFi SIEM/syslog app port, disabled by default |

UniFi devices that send SIEM/syslog to standard port `514/udp` should map host `514` to the app port `5514`; the normal container does not need privileged mode.

Export the production image for offline installs:

```bash
make docker-export
docker load -i dist/flowguard-image.tar
```

### Native Development

```bash
make setup
make build
make dev
```

For local demo data:

```bash
go run ./cmd/flowguard -config config-dev.yaml -seed
go run ./cmd/flowguard -config config-dev.yaml
```

Then open `http://localhost:8080`.

## Visual Preview

![FlowGuard Lite Overview dashboard with seeded demo data](docs/assets/screenshots/overview.png)

The seeded console includes populated Overview, Traffic, Devices, Alerts, Policies, Notifications, Audit, and Settings views so reviewers are not greeted by empty tables.

## Quality Gates

Run the product Go tests:

```bash
make test
```

Run formatting and vet checks:

```bash
make lint
```

Run frontend build/lint and Cypress smoke regression tests in Docker:

```bash
make docker-ui-test
make docker-ui-smoke
```

Run the full pre-release gate:

```bash
make pre-release-gate
```

The pre-release gate runs product Go tests, Dockerized Vite build/lint, Cypress smoke/workflow tests, the benchmark smoke test, and whitespace checks.

## Benchmarks

Run the lightweight performance regression smoke test:

```bash
make benchmark-smoke
```

Run local benchmark reports:

```bash
make benchmark-run
```

Run containerized benchmark profiles:

```bash
make docker-benchmark-run
make benchmark-matrix
```

Benchmark reports are written under `benchmark-results/`, which is intentionally ignored by Git.

## Documentation

Start here:

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [Architecture](docs/architecture.md)
- [REST API Reference](docs/api.md)
- [Capacity & Performance Guide](docs/capacity-guide.md)
- [Exporter Setup: UniFi](docs/setup/unifi.md)
- [Exporter Setup: MikroTik](docs/setup/mikrotik.md)
- [Exporter Setup: OPNsense and pfSense](docs/setup/opnsense.md)
- [Integrations and Webhooks](docs/features/integrations.md)

The `/docs` directory is Markdown-based and ready for GitHub Pages.

## Deployment Notes

- Do not expose FlowGuard Lite directly to the public internet.
- Use HTTPS, a reverse proxy, VPN, or firewall restrictions for remote access.
- Keep notification tokens, webhook headers, and session secrets out of logs and public config.
- Retention must stay bounded; FlowGuard Lite does not store raw flows or raw Suricata/UniFi logs indefinitely.
- Passive capture is opt-in and should use narrow Linux capabilities, not `privileged: true`.

## Project Status

FlowGuard Lite is in pre-release hardening. The core collector, storage, detection, UI, notifications, documentation, and performance benchmark paths are implemented and covered by automated gates. Remaining work should stay focused on release readiness, real-device validation, and public packaging.
