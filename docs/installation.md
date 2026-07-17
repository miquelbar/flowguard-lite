# Installation Guide

FlowGuard Lite is designed to run efficiently on small hardware. This guide covers how to deploy it using Docker (recommended) or natively on your host machine.

---

## System Requirements

*   **Processor:** Intel N100, Raspberry Pi 4/5, or equivalent x86_64 / arm64 CPU.
*   **Memory:** 500 MB minimum (runs comfortably under 2 GB for typical environments).
*   **Storage:** Local SSD or NVMe for database shards. Bounded by configured retention policies.
*   **Operating System:** Linux (Kernel 5.4+ recommended), macOS, or Windows (via WSL2).

---

## Option 1: Docker Compose Deployment (Recommended)

Docker is the easiest way to run FlowGuard Lite. It isolates the collectors, keeps the telemetry ports open, and handles database volume storage out of the box.

### 1. Create Deployment Directory
```bash
mkdir -p /opt/flowguard && cd /opt/flowguard
```

### 2. Create the Compose Configuration File
Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  flowguard:
    image: ghcr.io/miquelbar/flowguard-lite:edge
    container_name: flowguard
    restart: unless-stopped
    ports:
      - "8080:8080"        # REST API & Web UI Dashboard
      - "2055:2055/udp"    # NetFlow v5/v9 & IPFIX collector port
      - "6343:6343/udp"    # sFlow collector port
      - "514:5514/udp"     # Optional UniFi SIEM/syslog host port mapping
    volumes:
      - flowguard_data:/data
    environment:
      - FLOWGUARD_LOG_LEVEL=info
      - FLOWGUARD_STORAGE_BACKEND=sqlite

volumes:
  flowguard_data:
```

### 3. Launch the Daemon
Run the following command to download and start the service in the background:
```bash
docker compose up -d
```

Release images are published to GitHub Container Registry. Use version tags for repeatable deployments:

```bash
docker pull ghcr.io/miquelbar/flowguard-lite:v0.1.0-alpha
```

Use `edge` only when you explicitly want the latest `main` build:

```bash
docker pull ghcr.io/miquelbar/flowguard-lite:edge
```

### 4. Verify Containers
Verify that FlowGuard Lite is running and listening on the designated ports:
```bash
docker compose ps
```

Passive capture requires a separate opt-in Linux deployment using host networking and narrowly scoped packet capabilities. The normal Compose file remains unprivileged. See [Passive Network Capture](features/passive-capture.md) before enabling it; never substitute `privileged: true`.

---

## Option 2: Host-Native Installation

If you prefer to run the binary directly on your system without virtualization, follow these steps to compile and execute natively.

### Prerequisites
*   Go **1.25** or higher.
*   A C/C++ compiler (`gcc` or `clang`) and standard headers (required for CGO-based DuckDB integration).
*   `make` utility.

### 1. Clone and Prepare the Workspace
```bash
git clone https://github.com/miquelbar/flowguard-lite.git
cd flowguard-lite
```

### 2. Configure Git Exclusions
Configure local Git exclusions for private developer workspace files:
```bash
make setup
```

### 3. Build the Binary
Compile the Go backend:
```bash
make build
```
This produces the statically and dynamically linked execution binary at `./bin/flowguard`.

### 4. Run the Daemon
Start the collector using your configuration file:
```bash
./bin/flowguard -config /path/to/config.yaml
```

### Development Demo Data
Non-production builds expose a `-seed` flag for local demos:
```bash
cp config.example.yaml config-dev.yaml
go run ./cmd/flowguard -config config-dev.yaml -seed
```

The seed is deterministic and resets existing demo devices, flow aggregates, anomalies, policies, notification logs, and audit logs before repopulating them. It also marks first-run setup complete. Flow history remains bounded by `retention_days`; for example, the default `retention_days: 7` keeps roughly the latest week of seeded flow shards visible after startup retention cleanup.

The reset is bounded rather than globally transactional: SQLite metadata reset is transactional, but a full development seed spans metadata tables, daily flow shard files, and the YAML config file. If the final setup-bypass config write fails, the command reports an error instead of claiming complete success; already populated demo database rows are not rolled back across shard files.

---

## Verifying the Installation

Open your browser and navigate to `http://localhost:8080`.
*   If this is the first run, FlowGuard Lite prompts you to create the local admin password before protected API data is available.
*   The setup wizard then guides you through local subnet range and storage preferences.
*   Once configured, the analyst console unlocks.

## Frontend Regression Checks

Frontend changes should pass both the static UI check and the Cypress smoke suite:

```bash
make docker-ui-test
make docker-ui-smoke
```

`make docker-ui-test` builds and lints the Vite application in Docker. `make docker-ui-smoke` runs Cypress against the Vite UI with mocked API responses, covering route rendering, mobile detail close controls, retention-aware time ranges, device/subnet drilldowns, Notifications editor behavior, and sortable tables without requiring a live FlowGuard daemon or local login state.

## Public Exposure and Reverse Proxies

Do not expose FlowGuard Lite directly to the public internet. It contains internal network metadata, device names, destinations, alert evidence, and notification credentials.

If you publish the UI through a reverse proxy:

*   use HTTPS;
*   preserve `X-Forwarded-Proto: https` so secure cookies are set correctly;
*   restrict access with firewall rules or VPN where possible;
*   treat `admin_password_hash`, `session_secret`, webhook headers, and Telegram tokens as secrets.
