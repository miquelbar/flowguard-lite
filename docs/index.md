# FlowGuard Lite Documentation

🛡️ Welcome to the FlowGuard Lite documentation site. FlowGuard Lite is a lightweight, low-footprint network visibility, anomaly detection, and DDoS detection product designed for homelabs, prosumer networks, small offices, and technical teams.

It acts as a lightweight flow collector and correlates router/firewall telemetry (NetFlow, IPFIX, sFlow, or passive capture) with optional Suricata IDS events to build device-centric behavioral baselines and explain security anomalies. UniFi gateways may expose IPFIX, SIEM/syslog, SNMP, or only internal Traffic Flows depending on model and firmware; those paths are documented separately.

---

## 📖 Table of Contents

### Getting Started
*   [**Installation Guide**](installation.md) - Learn how to deploy FlowGuard Lite using Docker Compose or host-native binaries.
*   [**Passive Network Capture**](features/passive-capture.md) - Opt-in libpcap deployment, minimum Linux capabilities, filters, and verification.
*   [**Configuration Reference**](configuration.md) - Complete schema details for `config.yaml` and environment variables.

### Exporter Setup Guides
Configure your routers and firewalls to export supported telemetry:
*   [**Ubiquiti UniFi Gateways**](setup/unifi.md) - IPFIX when available, SIEM/syslog planned, passive capture fallback.
*   [**MikroTik RouterOS**](setup/mikrotik.md)
*   [**OPNsense & pfSense Firewalls**](setup/opnsense.md)

### Core Features
*   [**Anomaly Detection & Risk Scoring**](features/anomaly-detection.md) - Deep dive into statistical baselines, DDoS thresholds, and device risk indexing.
*   [**Overview Dashboard**](features/overview-dashboard.md) - Default security posture dashboard, attack timeline, risk distribution, and remaining M26 dashboard work.
*   [**Analyst Workflows & UI Architecture**](features/analyst-workflows.md) - Target operator workflows, page model, Risk Index explanation requirements, and UI implementation order.
*   [**Integrations & Webhooks**](features/integrations.md) - How to setup Suricata ingestion, configure Slack/Telegram webhooks, and block IPs.

### Reference & Development
*   [**System Architecture**](architecture.md) - Internal design, collector worker pools, memory aggregation, and sharded storage engines.
*   [**Frontend Architecture**](frontend-architecture.md) - Vite module boundaries, feature-first structure, and UI refactor rules.
*   [**REST API Reference**](api.md) - Endpoints, request/response models, and example payloads.
*   [**Performance Baselines**](performance-baselines.md) - Standard metrics, publishable profiles, N100 hardware targets, and pass/fail thresholds.
*   [**Capacity & Performance Guide**](capacity-guide.md) - Ingestion limits, tested hardware profiles, overload mechanics, and router-specific tradeoffs.
