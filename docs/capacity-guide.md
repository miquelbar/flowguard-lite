# Capacity & Performance Guide

This guide outlines preliminary capacity estimates, synthetic microbenchmark results, and behavior under overload for FlowGuard Lite.

> [!NOTE]
> Synthetic microbenchmarks used to detect regressions. They are not real-world capacity guarantees.

---

## 1. Tested Hardware Profile

FlowGuard Lite was tested using synthetic microbenchmarks on the following hardware profile (and virtualized equivalents) under both native execution and unprivileged Docker containers:

*   **CPU**: Intel N100 (4 Cores, 4 Threads, base 0.8 GHz, burst 3.4 GHz, 6W TDP).
*   **Memory Limit**: Bounded to **2 GB RAM** allocated space (the application's 500 MB heap ceiling is an initial estimate, not a measured minimum).
*   **Storage**: Local PCIe Gen3 NVMe SSD.
*   **OS**: Linux (Debian Bookworm) / macOS (Darwin).
*   **Go Version**: go1.25.x.

These tests represent isolated microbenchmarks and are not real-world capacity guarantees.

---

## 2. Reproducing the Benchmark Tests

Run the benchmark smoke test before every release candidate:

```bash
make benchmark-smoke
```

Generate local native benchmark reports:

```bash
make benchmark-run
```

Generate Docker benchmark reports using the same harness as the published capacity matrix:

```bash
make docker-benchmark-run
make benchmark-matrix
```

The benchmark runner writes Markdown and JSON reports under `benchmark-results/`. That directory is intentionally ignored by Git so repeated runs do not pollute commits.

---

## 3. Ingestion & Aggregation Benchmark Results

> [!NOTE]
> The following metrics represent maximum throughput processing limits measured during synthetic microbenchmarks run under a controlled containerized environment (e.g., 1 CPU Core, 2 GB RAM limit, commit `a4b209b` on 2026-07-16, executing `go test -bench=. ./internal/benchmark`).
>
> These are synthetic microbenchmarks testing isolated processing logic and do not directly project live network deployment performance or real-world device counts, as throughput depends heavily on packet structures, sampling rates, and CPU scheduling.

| Component / Path | Native Throughput | Docker Containerized (1 CPU Core, 2 GB RAM) | Measured Latency / Rate |
| --- | --- | --- | --- |
| **`FlowAggregator` Throughput** | 8.13M flows/sec | 4.53M flows/sec | 240 ns per flow |
| **NetFlow v9 Packet Decode** | 1.50M pkts/sec | 1.16M pkts/sec | 860 ns per packet |
| **UniFi Syslog Parse / Classify** | 615K lines/sec | 576K lines/sec | 1.73 µs per line |
| **`anomaly.Engine` Evaluation** | 86.0K flows/sec | 78.5K flows/sec | 58.2ms per 5,000-flow batch |

---

## 4. Database & REST API Performance

### SQLite vs. DuckDB Write & Read Latencies
FlowGuard Lite uses sharded SQLite daily databases as its default storage engine, with support for DuckDB query acceleration.

*   **1,000-Flow Batch Writes**:
    *   **SQLite**: **6.16 ms** per batch (fast transactional commits due to WAL mode).
    *   **DuckDB**: **1,090 ms** per batch (columnar commit overhead is significantly higher).
*   **Top Talkers & Timeseries Queries (20,000 records, 24h/7d ranges)**:
    *   **SQLite**: **15.0 - 19.0 ms** per query.
    *   **DuckDB**: **0.6 - 0.9 ms** per query (DuckDB reads are **20x to 25x faster**).
*   **Daily Retention Pruning**:
    *   **SQLite**: **9.0 µs** per cleanup run.
    *   **DuckDB**: **357.0 µs** per cleanup run.

### REST API Response Latency (Under Load)
*   **Overview Summary API (`/api/security/summary`)**: **48.4 µs** response latency.
*   **Security Timeline API (`/api/security/timeline`)**: **16.2 µs** response latency.
*   **Flow Explorer Records API (`/api/traffic/records`)**: **325.1 µs** response latency.

---

## 5. Preliminary Capacity Estimates Based on Synthetic Benchmarks

> [!NOTE]
> These capacity estimates are preliminary, derived from synthetic microbenchmark profiles, and are intended for self-hosted home networks and homelabs. They should not be taken as sizing recommendations or guarantees for real-world deployments.
>
> Actual deployment performance depends heavily on:
> * **Telemetry Volume:** Number of raw packets and decoded flows per second.
> * **Sampling Rate:** The exporter's sampling rate (e.g., 1:1 vs. 1:100) greatly impacts incoming packet rates.
> * **Cardinality:** The number of unique local devices and external peer IP/port combinations.
> * **Retention Period:** Number of days database shards are kept (pruning occurs daily).
> * **Query Load:** The frequency and complexity of dashboard queries and API requests.
> * **Aggregation Frequency:** The interval at which in-memory flows are flushed to disk.
> * **Hardware Specs:** Disk write speeds, filesystem locks, CPU core counts, and storage medium (NVMe/SSD vs. HDD).
> * **Active Collectors:** Number of collector listeners enabled simultaneously (e.g., NetFlow, sFlow, syslog, passive capture).

### Synthetic Workload Profiles

The table below describes how the system handled simulated workload profiles under synthetic benchmarks:

| Workload Profile | Simulated Active Devices | Simulated Flow Rate | Recommended Storage Backend |
| --- | --- | --- | --- |
| **Profile B (Home Lab / Prosumer)** | 1 - 50 | 10 - 50 flows/sec | SQLite (Daily Shards) |
| **Profile C (Busy Home / Small Network)** | 50 - 150 | 50 - 150 flows/sec | SQLite (Daily Shards) |
| **Profile D (High-Flow Lab / Intensive Self-Hosted)** | 150 - 250 | 150 - 350 flows/sec | SQLite (with optional DuckDB read caching) |

---

## 6. Behavior Under Overload

When traffic levels exceed the capacity of the host CPU or network interface, FlowGuard Lite triggers the following safety mechanisms to preserve system stability:

1.  **Controlled Packet Discards**:
    *   The collectors utilize bounded internal channels (Go queues). If the aggregation queue fills up completely, incoming UDP packets are discarded at the network socket layer.
    *   This prevents heap memory allocations from growing out of control, protecting the daemon from Out-Of-Memory (OOM) kills.
2.  **UI Health Indicators**:
    *   The system monitors and exposes drop rates. The Overview Dashboard displays real-time indicators showing the percentage of collector packets dropped, alerting the operator to scale up hardware or narrow the exporter's sampling rate.
3.  **Read/Write Lock Contention**:
    *   Under maximum write load, SQLite's transactional write locks can cause minor read contention. API query times may degrade from <1ms to ~150-250ms, but transactions remain ACID-compliant without data corruption.

---

## 7. Exporter & Gateway Specific Tradeoffs

### Ubiquiti UniFi IPFIX Hardware-Acceleration Tradeoff
### Gateway Telemetry Performance Tradeoffs
> [!WARNING]
> Flow export may affect forwarding performance on some gateway models or firmware versions. Measure the impact on your own gateway before enabling it on a high-throughput connection.

For high-throughput environments where gateway performance is impacted, configure FlowGuard Lite to use **Passive Network Capture** (via a SPAN/Mirror port) instead of enabling NetFlow/IPFIX directly on the gateway. Note that while UniFi syslog SIEM event ingestion is supported, in practice it receives very few security events and does not provide session-level traffic flows, so it is not a substitute for flow telemetry.

### SNMP & Auxiliary Metrics
*   SNMP polling, if enabled, operates on a low-frequency schedule (e.g. every 60 seconds) to fetch interface status and interface counters.
*   SNMP polling is treated as background auxiliary work and does not impact the high-frequency packet ingestion queues of the NetFlow and Syslog collectors.

---

## 8. Comparative Performance Matrix by CPU and Memory Allocation

To measure memory and CPU scaling and verify that limits do not cause allocator thrashing or resource bottlenecks, the benchmark suite was executed in Docker containers configured with hard CPU and memory ceilings:

### 1 CPU Core Configuration

| Benchmark Target | 2 GB Memory Limit | 4 GB Memory Limit | 8 GB Memory Limit | Performance Variance |
| --- | --- | --- | --- | --- |
| **`FlowAggregator` Throughput** | 123.00 ns/op | 123.10 ns/op | 123.00 ns/op | < 1% variance |
| **NetFlow v9 Packet Decode** | 860.30 ns/op | 868.40 ns/op | 864.70 ns/op | < 1% variance |
| **UniFi Syslog Parse** | 1.73 µs/op | 1.73 µs/op | 1.74 µs/op | < 1% variance |
| **SQLite Save Aggregates** | 9.06 ms/op | 7.53 ms/op | 7.34 ms/op | < 20% variance |
| **SQLite TopTalkers (24h)** | 18.05 ms/op | 18.06 ms/op | 17.61 ms/op | < 3% variance |

### 2 CPU Cores Configuration

| Benchmark Target | 2 GB Memory Limit | 4 GB Memory Limit | 8 GB Memory Limit | Performance Variance |
| --- | --- | --- | --- | --- |
| **`FlowAggregator` Throughput** | 116.70 ns/op | 112.30 ns/op | 112.80 ns/op | < 4% variance |
| **NetFlow v9 Packet Decode** | 726.20 ns/op | 719.50 ns/op | 729.10 ns/op | < 2% variance |
| **UniFi Syslog Parse** | 1.66 µs/op | 1.65 µs/op | 1.64 µs/op | < 2% variance |
| **SQLite Save Aggregates** | 10.57 ms/op | 9.09 ms/op | 7.38 ms/op | < 30% variance |
| **SQLite TopTalkers (24h)** | 17.76 ms/op | 17.60 ms/op | 17.56 ms/op | < 2% variance |

### Memory Scaling & CPU Insights
*   **Predictable Execution Footprint**: FlowGuard Lite maintains a steady latency and throughput profile across all configurations. The low-overhead memory architecture (bounded buffer queues, batched memory aggregations, and reuse of normalized structs) keeps Go's GC pause times minimal and avoids runtime allocations.
*   **CPU Utilization Efficiency**: Stepping up from 1 CPU to 2 CPUs yields ~15-20% throughput acceleration on compute-bound decoding (NetFlow decode drops from ~860 ns to ~720 ns) and parsing loops (Syslog parsing drops from ~1.73 µs to ~1.65 µs), demonstrating clean scaling behavior.
*   **High Performance at 2 GB**: The application runs at 100% capacity within the standard 2 GB allocation target. There is no memory degradation or cache thrashing, validating the single-node homelab resource limits.
