# FlowGuard Lite

🛡️ **FlowGuard Lite** is a lightweight network visibility, anomaly detection, and DDoS detection product designed for homelabs, prosumer networks, small offices, and technical teams who do not have a dedicated Security Operations Center (SOC).

It receives NetFlow v5/v9, IPFIX, or sFlow telemetry from your routers (e.g. UniFi, MikroTik, OPNsense, pfSense) and correlates it with optional Suricata IDS events to build device behavioral baselines, identify flood patterns, and explain security anomalies.

---

## ⚡ Quickstart

### 📦 1. Containerized Run (Docker Compose)
To launch FlowGuard Lite in a containerized environment:
```bash
# Build the production image
make docker-build

# Launch the service with docker-compose
make docker-up
```
The REST API and Web Dashboard will be available at [http://localhost:8080](http://localhost:8080).
NetFlow/IPFIX will listen on UDP port `2055` and sFlow on UDP port `6343`.

### 🖥️ 2. Host-Native Run
To run FlowGuard Lite directly on your host machine:
```bash
# Configure local developer exclusions
make setup

# Build the native binary
make build

# Run the backend natively
make dev
```

### 🚢 3. Image Exporting
If you need to deploy the image on offline systems or environments without direct registry access:
```bash
make docker-export
```
This builds and saves the production container image as a tar archive at `dist/flowguard-image.tar`, which can be imported elsewhere using `docker load -i flowguard-image.tar`.

---

## 🧪 Development & Testing

Run the full verification suite natively:
```bash
# Run Go unit and integration tests
make test

# Format and vet code
make lint
```

---

## 📖 Documentation & GitHub Pages
The project documentation is located inside the `/docs` directory. It is configured to automatically compile and deploy to **GitHub Pages** via GitHub Actions on pushes to the `main` branch.

To view or host documentation locally, view the [docs/index.md](docs/index.md) documentation root file.
