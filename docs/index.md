# FlowGuard Lite Documentation

🛡️ Welcome to the FlowGuard Lite documentation site. FlowGuard Lite is a lightweight, low-footprint network visibility, anomaly detection, and DDoS detection product designed for homelabs, prosumer networks, small offices, and technical teams.

It acts as a lightweight flow collector and correlates router/firewall telemetry (NetFlow, sFlow) with optional Suricata IDS events to build device-centric behavioral baselines and explain security anomalies.

---

## 📖 Table of Contents

### Getting Started
*   [**Installation Guide**](installation.md) - Learn how to deploy FlowGuard Lite using Docker Compose or host-native binaries.
*   [**Configuration Reference**](configuration.md) - Complete schema details for `config.yaml` and environment variables.

### Exporter Setup Guides
Configure your routers and firewalls to export flow telemetry:
*   [**Ubiquiti UniFi Gateways**](setup/unifi.md)
*   [**MikroTik RouterOS**](setup/mikrotik.md)
*   [**OPNsense & pfSense Firewalls**](setup/opnsense.md)

### Core Features
*   [**Anomaly Detection & Risk Scoring**](features/anomaly-detection.md) - Deep dive into statistical baselines, DDoS thresholds, and device risk indexing.
*   [**Analyst Workflows & UI IA**](features/analyst-workflows.md) - Target operator workflows, page model, Risk Index explanation requirements, and UI implementation order.
*   [**Integrations & Webhooks**](features/integrations.md) - How to setup Suricata ingestion, configure Slack/Telegram webhooks, and block IPs.

### Reference & Development
*   [**System Architecture**](architecture.md) - Internal design, collector worker pools, memory aggregation, and sharded storage engines.
*   [**REST API Reference**](api.md) - Endpoints, request/response models, and example payloads.
