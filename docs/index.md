# FlowGuard Lite Documentation

🛡️ Welcome to the FlowGuard Lite documentation site. FlowGuard Lite is an experimental, self-hosted network visibility and anomaly-detection tool primarily tested on a UniFi home network.

It acts as a lightweight flow collector and correlates router/firewall telemetry (NetFlow, IPFIX, sFlow, or passive capture) with optional Suricata IDS events to build device-centric behavioral baselines and explain anomalies. UniFi gateways may expose IPFIX, SIEM/syslog, SNMP, or only internal Traffic Flows depending on model and firmware; those paths are documented separately.

---

## 📖 Table of Contents

### Getting Started
*   [**Installation Guide**](installation.md) - Learn how to deploy FlowGuard Lite using Docker Compose or host-native binaries.
*   [**Passive Network Capture**](features/passive-capture.md) - Opt-in libpcap deployment, minimum Linux capabilities, filters, and verification.
*   [**Configuration Reference**](configuration.md) - Complete schema details for `config.yaml` and environment variables.

### Exporter Setup Guides
Configure your routers and firewalls to export supported telemetry:
*   [**Ubiquiti UniFi Gateways**](setup/unifi.md) - IPFIX when available, SIEM/syslog Activity Logging ingest, passive capture fallback.
*   [**MikroTik RouterOS**](setup/mikrotik.md)
*   [**OPNsense & pfSense Firewalls**](setup/opnsense.md)

### Core Features
*   [**Anomaly Detection & Risk Heuristics**](features/anomaly-detection.md) - Deep dive into statistical baselines, DDoS thresholds, and device risk indexing.
*   [**Overview Dashboard**](features/overview-dashboard.md) - Default visibility dashboard, event timeline, risk distribution, and network operations panels.
*   [**Operator Workflows & UI Architecture**](features/operator-workflows.md) - Target operator workflows, page model, Risk Index explanation requirements, and UI implementation order.
*   [**Integrations & Webhooks**](features/integrations.md) - How to set up Suricata ingestion, configure Slack/Telegram/webhook notifications, and export firewall rule templates.

### Reference & Development
*   [**System Architecture**](architecture.md) - Internal design, collector worker pools, memory aggregation, and sharded storage engines.
*   [**Frontend Architecture**](frontend-architecture.md) - Vite module boundaries, feature-first structure, and UI refactor rules.
*   [**REST API Reference**](api.md) - Endpoints, request/response models, and example payloads.
*   [**Performance Baselines**](performance-baselines.md) - Standard metrics, publishable profiles, N100 hardware targets, and pass/fail thresholds.
*   [**Capacity & Performance Guide**](capacity-guide.md) - Ingestion limits, tested hardware profiles, overload mechanics, and router-specific tradeoffs.

## Benchmark and Quality Gates

The benchmark suite is part of the validation gate. Use these commands to reproduce the preliminary performance estimates:

```bash
make benchmark-smoke
make benchmark-run
make docker-benchmark-run
make benchmark-matrix
make pre-release-gate
```

What they cover:

| Command | Purpose |
| --- | --- |
| `make benchmark-smoke` | Fast regression check for processing rate and parser performance. |
| `make benchmark-run` | Native benchmark report generation under `benchmark-results/`. |
| `make docker-benchmark-run` | Containerized 2 GB benchmark profile. |
| `make benchmark-matrix` | Docker benchmark profiles for 2 GB, 4 GB, and 8 GB memory limits. |
| `make pre-release-gate` | Backend Go tests, frontend build/lint, Cypress smoke, benchmark smoke, and whitespace checks. |

Preliminary capacity numbers are documented in the [Capacity & Performance Guide](capacity-guide.md).
