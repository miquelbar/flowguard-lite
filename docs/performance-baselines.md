# Performance Baselines & Benchmark Contract

This document defines the metrics contract, test profiles, and resource limits for FlowGuard Lite. Benchmark results must be measured using these criteria on standard target hardware.

## Target Platform & Hardware Profile
FlowGuard Lite is designed to run efficiently on small/low-power hardware:
- **CPU**: Intel N100 (or equivalent low-power x86-64 / ARM64 processor).
- **RAM**: 2 GB allocated/available to FlowGuard Lite (the application itself must operate within a 500 MB heap ceiling under typical workloads).
- **Storage**: Local SSD or NVMe drive (for sharded SQLite and DuckDB writes).
- **Runtime Environment**: Docker-based containerized setup or host-native execution.

---

## 1. Metrics Contract
Standard performance measurements must report the following metrics:

### Collector & Ingest Invariants
- **Incoming Datagrams/Sec (Ingest Rate)**: Bounded UDP packets received per second by each collector type (NetFlow, sFlow, syslog).
- **Decoded Flow Records/Sec**: Flow records successfully parsed and extracted from collector UDP packet payloads.
- **Normalized Events/Sec**: Normalized `FlowEvent` structs successfully emitted through internal Go channels.
- **Queue Depth & Drop Rates**: Bounded channel depths, queue-full drop counts, parse errors, and sender-rejected events.

### Aggregator & Database Performance
- **Aggregate Records Per Flush**: Number of compressed aggregate rows flushed to disk every 15/30 seconds.
- **Aggregate Flush Duration (p50/p95/p99)**: Latency of batch transactional writes to SQLite/DuckDB.
- **Database Write Throughput (B/s)**: Disk write volume and WAL (Write-Ahead Log) checkpoint duration.
- **Evidence/Event Storage Rate**: Save/list latency and index lookup efficiency for Suricata and UniFi SIEM events.

### Detection Engine Metrics
- **Anomaly Callback Duration**: Processing latency of the callback queue (e.g. alerts evaluation, webhook, and Telegram dispatcher worker pools).
- **Alert Queue Drops**: Alerts dropped due to worker pool saturation or repository-lock queues.

### API & User Interface Latency
- **API Response Latency (p50/p95/p99)**: REST API request-to-response duration under ingest loads, specifically for:
  - `GET /api/security/summary`
  - `GET /api/security/timeline`
  - `GET /api/traffic/records`
  - `GET /api/devices`
- **UI Responsiveness & Layout Refreshes**: Render times and client-side sorting/filtering durations.

### System Metrics
- **CPU Utilization (%)**: CPU time consumed by the FlowGuard daemon and Docker stack.
- **Resident Set Size (RSS)**: Operating system memory usage.
- **Go Heap Allocation (Alloc)**: Active in-use heap memory.
- **Goroutine Count**: Bounded thread/goroutine count (to ensure no leaks in workers/dispatchers).
- **Disk Write Volume & Retention growth**: Bounded database size growth per day and cleanup efficiency.

---

## 2. Publishable Benchmark Profiles
Tests must utilize these standardized profiles to evaluate capacity and establish performance baselines:

### Profile A: Idle Baseline
- **Devices**: 0
- **Incoming traffic**: 0 PPS
- **Goal**: Establish background daemon memory, CPU idle usage, and telemetry channel stability.

### Profile B: Home Lab / Prosumer
- **Devices**: 25 active local devices.
- **Incoming Traffic**: ~1,000 flow records per minute (~15-20 flows/sec).
- **Syslog Events**: ~10 events per hour.
- **Goal**: Verify typical consumer/homelab behavior under negligible CPU/RAM load.

### Profile C: Busy Home Network
- **Devices**: 100 active local devices.
- **Incoming Traffic**: ~5,000 flow records per minute (~80-100 flows/sec).
- **Syslog Events**: ~100 events per hour.
- **Goal**: Validate typical busy network profile stability under telemetry load.

### Profile D: High-Flow Lab (Extreme/Stress)
- **Devices**: 200 active local devices.
- **Incoming Traffic**: ~20,000 flow records per minute (~300-350 flows/sec).
- **Syslog Events**: ~1,000 events per hour.
- **Goal**: Push database batching, aggregation, write serialization, and index lookups to their limits.

### Profile E: Volumetric Burst / DDoS Load
- **Devices**: 200 devices.
- **Incoming Traffic**: Volumetric spike of 50,000 packets per second (PPS) targeting a specific local IP.
- **Goal**: Verify collector queues handle overload gracefully, trigger DDoS alarms with explainable evidence, and drop excess frames without crashing the application.

### Profile F: Query-under-Ingest Load
- **Description**: Active flow ingestion at 5,000 flows/min (Profile C) while simulating 5 concurrent API requests/sec (simulating multiple active dashboard operator sessions).
- **Goal**: Verify SQLite read/write lock contention and DuckDB read performance under ingestion load.

---

## 3. Pass/Fail Thresholds & Supported Range Criteria

FlowGuard Lite must satisfy the following thresholds under test profiles to be certified for release:

| Profile | Max CPU (N100 Core %) | Max RSS Memory | Packet Loss / Queue Drops | API Latency (p95) |
|---|---|---|---|---|
| **Profile A (Idle)** | < 1% | < 50 MB | 0% | < 10ms |
| **Profile B (Home Lab)** | < 5% | < 150 MB | 0% | < 50ms |
| **Profile C (Busy Home Network)** | < 10% | < 250 MB | 0% | < 100ms |
| **Profile D (High-Flow Lab)** | < 25% | < 500 MB | < 0.1% | < 250ms |
| **Profile E (DDoS Burst)** | < 50% | < 500 MB | Allowed (controlled drop) | < 500ms |
| **Profile F (Query/Ingest)** | < 20% | < 350 MB | 0% | < 150ms |

### Hard Resource Constraints
- **RAM Ceiling**: RSS Memory must never exceed **2 GB** at any point. Go Heap Alloc must remain under **500 MB** under all profiles.
- **ACID Integrity**: Multi-step writes and settings updates must commit atomically or roll back completely even under maximum system load.
- **Bounded Retention**: Shard cleanup and database prunes must execute successfully without raising write-lock timeouts.
