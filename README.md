# FlowGuard Lite

[![CI](https://github.com/miquelbar/flowguard-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/miquelbar/flowguard-lite/actions/workflows/ci.yml)
[![Docs](https://github.com/miquelbar/flowguard-lite/actions/workflows/deploy-docs.yml/badge.svg)](https://github.com/miquelbar/flowguard-lite/actions/workflows/deploy-docs.yml)
[![Container](https://img.shields.io/badge/GHCR-flowguard--lite-2f81f7)](https://github.com/miquelbar/flowguard-lite/pkgs/container/flowguard-lite)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Network anomaly detection for people who do not have a SOC.**

FlowGuard Lite is a lightweight network visibility and anomaly detection product for homelabs, prosumer networks, small offices, clinics, shops, and small technical teams. It ingests NetFlow/IPFIX/sFlow, optional passive capture metadata, optional Suricata events, and UniFi SIEM/syslog events, then builds device-level baselines and explains why a device looks suspicious.

## Try It

Published multi-arch images are available on GitHub Container Registry:

```bash
docker pull ghcr.io/miquelbar/flowguard-lite:v0.1.0-alpha
```

Minimal Docker Compose deployment:

```yaml
services:
  flowguard:
    image: ghcr.io/miquelbar/flowguard-lite:v0.1.0-alpha
    container_name: flowguard
    restart: unless-stopped
    ports:
      - "8080:8080"        # Web UI and REST API
      - "2055:2055/udp"    # NetFlow v5/v9 and IPFIX
      - "6343:6343/udp"    # sFlow
      - "514:5514/udp"     # UniFi SIEM/syslog host port mapping
    volumes:
      - flowguard_data:/data

volumes:
  flowguard_data:
```

Then open:

```text
http://localhost:8080
```

For the newest `main` build:

```bash
docker pull ghcr.io/miquelbar/flowguard-lite:edge
```

## Visual Preview

![FlowGuard Lite Overview dashboard with seeded demo data](docs/assets/screenshots/overview.png)

The seeded console includes populated Overview, Traffic, Devices, Alerts, Policies, Notifications, Audit, and Settings views so reviewers are not greeted by empty tables.

## Why Use It

Small networks often have capable routers and firewalls but poor visibility into device behavior. FlowGuard Lite focuses on:

- **Device-level explanations:** every anomaly explains what happened, why it is unusual, the baseline used, and the next check.
- **Practical collectors:** NetFlow/IPFIX/sFlow, UniFi SIEM/syslog, passive capture, and optional Suricata evidence.
- **Small hardware:** designed for Intel N100-class boxes and bounded local storage.
- **Noise controls:** suppress noisy detector types, subnets, or notification targets without losing all evidence.
- **Simple deployment:** one Docker container, SQLite daily shards by default, no external data platform.
- **Operator workflow:** alerts, devices, policies, notifications, audit logs, Telegram/webhook tests, and configuration backup from the UI.

FlowGuard Lite is alert-only. It can generate firewall rule templates, but it does not automatically block traffic.

## Current Support

| Area | Support |
| --- | --- |
| Flow telemetry | NetFlow v5/v9, IPFIX, sFlow |
| UniFi | Validated with UniFi NetFlow/IPFIX; supports SIEM/syslog Activity Logging events |
| Passive capture | Optional libpcap TCP/UDP metadata reduction |
| IDS evidence | Optional Suricata `eve.json` ingest |
| Detection | New destination/port/internal peer, traffic spikes, beaconing, fan-out, nighttime activity, profile changes, DDoS flood patterns |
| Notifications | Telegram, Slack/Discord-compatible webhook, generic webhook |
| Storage | SQLite daily shards by default; optional DuckDB query acceleration |
| Images | `ghcr.io/miquelbar/flowguard-lite:v0.1.0-alpha` and `:edge` |

## Documentation

- [Documentation site](https://miquelbar.github.io/flowguard-lite/)
- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [Capacity & Performance Guide](docs/capacity-guide.md)
- [Exporter Setup: UniFi](docs/setup/unifi.md)
- [Integrations and Webhooks](docs/features/integrations.md)

## Performance Snapshot

FlowGuard Lite has a repeatable benchmark harness and published capacity guide. The current measured baseline in a constrained Docker container (1 CPU Core, 2 GB RAM Limit) is:

| Path | Measured result |
| --- | ---: |
| Flow aggregation | 8.13M flows/sec in Docker |
| NetFlow v9 decode | 1.16M packets/sec in Docker |
| UniFi syslog parse/classify | 576K lines/sec in Docker |
| SQLite 1,000-flow batch write | 9.06 ms in Docker |
| Overview summary API | 51.7 us |
| Traffic records API | 356.2 us |

Recommended N100-class deployment ranges:

| Deployment | Active devices | Average flow rate | Recommended backend |
| --- | ---: | ---: | --- |
| Home lab / prosumer | 1-50 | 10-50 flows/sec | SQLite daily shards |
| Small office / clinic | 50-150 | 50-150 flows/sec | SQLite daily shards |
| Technical lab | 150-250 | 150-350 flows/sec | SQLite, optional DuckDB reads |

Details: [Capacity & Performance Guide](docs/capacity-guide.md) and [Performance Baselines](docs/performance-baselines.md).

## Local Development

```bash
make setup
make docker-build
make docker-up
```

Export the production image for offline installs:

```bash
make docker-export
docker load -i dist/flowguard-image.tar
```

For local demo data:

```bash
cp config.example.yaml config-dev.yaml
go run ./cmd/flowguard -config config-dev.yaml -seed
go run ./cmd/flowguard -config config-dev.yaml
```

Then open `http://localhost:8080`.

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

## Deployment Notes

- Do not expose FlowGuard Lite directly to the public internet.
- Use HTTPS, a reverse proxy, VPN, or firewall restrictions for remote access.
- Keep notification tokens, webhook headers, and session secrets out of logs and public config.
- Retention must stay bounded; FlowGuard Lite does not store raw flows or raw Suricata/UniFi logs indefinitely.
- Passive capture is opt-in and should use narrow Linux capabilities, not `privileged: true`.

## Project Status

FlowGuard Lite is in pre-release hardening. The core collector, storage, detection, UI, notifications, documentation, and performance benchmark paths are implemented and covered by automated gates. Remaining work should stay focused on release readiness, real-device validation, and public packaging.
