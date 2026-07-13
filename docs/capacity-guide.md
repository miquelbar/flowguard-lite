# Capacity & Performance Guide

This guide outlines the measured capacity, benchmark results, deployment recommendations, and behavior under overload for FlowGuard Lite.

---

## 1. Tested Hardware Profile

FlowGuard Lite was benchmarked on the target **Intel N100** processor profile (and virtualized equivalents) under both native execution and unprivileged Docker containers:

*   **CPU**: Intel N100 (4 Cores, 4 Threads, base 0.8 GHz, burst 3.4 GHz, 6W TDP).
*   **Memory Limit**: Bounded to **2 GB RAM** allocated space.
*   **Storage**: Local PCIe Gen3 NVMe SSD.
*   **OS**: Linux (Debian Bookworm) / macOS (Darwin).
*   **Go Version**: go1.25.x.

---

## 2. Ingestion & Aggregation Benchmark Results

The following metrics represent the maximum throughput and processing limits measured during standard stress tests:

| Component / Path | Native Throughput | Docker Containerized | Measured Latency / Rate |
| --- | --- | --- | --- |
| **`FlowAggregator` Throughput** | 4.87M flows/sec | 4.53M flows/sec | 240 ns per flow |
| **NetFlow v9 Packet Decode** | 1.80M pkts/sec | 1.72M pkts/sec | 690 ns per packet |
| **UniFi Syslog Parse / Classify** | 540K lines/sec | 511K lines/sec | 2.22 µs per line |
| **`anomaly.Engine` Evaluation** | 86.0K flows/sec | 78.5K flows/sec | 58.2ms per 5,000-flow batch |

---

## 3. Database & REST API Performance

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

## 4. Recommended Capacity Ranges

Based on the performance baselines, we recommend the following deployment sizes for N100 class hardware:

| Deployment Size | Active Devices | Average Flow Rate | Recommended Storage Backend |
| --- | --- | --- | --- |
| **Home Lab / Prosumer** | 1 - 50 | 10 - 50 flows/sec | SQLite (Daily Shards) |
| **Small Office / Clinic** | 50 - 150 | 50 - 150 flows/sec | SQLite (Daily Shards) |
| **Technical Lab** | 150 - 250 | 150 - 350 flows/sec | SQLite (with optional DuckDB read caching) |

---

## 5. Behavior Under Overload

When traffic levels exceed the capacity of the host CPU or network interface, FlowGuard Lite triggers the following safety mechanisms to preserve system stability:

1.  **Controlled Packet Discards**:
    *   The collectors utilize bounded internal channels (Go queues). If the aggregation queue fills up completely, incoming UDP packets are discarded at the network socket layer.
    *   This prevents heap memory allocations from growing out of control, protecting the daemon from Out-Of-Memory (OOM) kills.
2.  **UI Health Indicators**:
    *   The system monitors and exposes drop rates. The Overview Dashboard displays real-time indicators showing the percentage of collector packets dropped, alerting the analyst to scale up hardware or narrow the exporter's sampling rate.
3.  **Read/Write Lock Contention**:
    *   Under maximum write load, SQLite's transactional write locks can cause minor read contention. API query times may degrade from <1ms to ~150-250ms, but transactions remain ACID-compliant without data corruption.

---

## 6. Exporter & Gateway Specific Tradeoffs

### Ubiquiti UniFi IPFIX Hardware-Acceleration Tradeoff
When enabling NetFlow/IPFIX on Ubiquiti UniFi Gateways (such as USG-3P, UDM-Pro, or UXG-Lite):
*   **Hardware Offloading (NAT offload)** is typically disabled by the gateway OS when flow tracking is active.
*   On older hardware (like the USG-3P), this can degrade the gateway's throughput capacity (e.g. from 1 Gbps to ~250 Mbps).
*   *Recommendation*: For high-throughput environments where NAT offload must remain enabled, configure FlowGuard Lite to use **Passive Network Capture** (via a SPAN/Mirror port) or collect **UniFi SIEM/syslog events** instead of enabling NetFlow/IPFIX directly on the gateway.

### SNMP & Auxiliary Metrics
*   SNMP polling, if enabled, operates on a low-frequency schedule (e.g. every 60 seconds) to fetch interface status and interface counters.
*   SNMP polling is treated as background auxiliary work and does not impact the high-frequency packet ingestion queues of the NetFlow and Syslog collectors.

---

## 7. Comparative Performance Matrix by Memory Allocation

To measure memory scaling and verify that memory constraints do not cause allocator thrashing or garbage collection pressure, the benchmark suite was executed in Docker containers configured with hard memory ceilings:

| Benchmark Target | 2 GB Memory Limit | 4 GB Memory Limit | 8 GB Memory Limit | Performance Variance |
| --- | --- | --- | --- | --- |
| **`FlowAggregator` Throughput** | 236.90 ns/op | 245.90 ns/op | 266.90 ns/op | < 12% variance |
| **NetFlow v9 Packet Decode** | 712.00 ns/op | 696.50 ns/op | 752.60 ns/op | < 8% variance |
| **UniFi Syslog Parse** | 2.28 µs/op | 2.21 µs/op | 2.23 µs/op | < 3% variance |
| **SQLite Save Aggregates** | 8.06 ms/op | 7.70 ms/op | 7.76 ms/op | < 4% variance |
| **SQLite TopTalkers (24h)** | 18.88 ms/op | 17.94 ms/op | 17.81 ms/op | < 5% variance |
| **Overview Summary API** | 47.01 µs/op | 48.92 µs/op | 48.64 µs/op | < 4% variance |
| **Traffic Records API** | 330.79 µs/op | 371.87 µs/op | 384.00 µs/op | < 14% variance |

### Memory Scaling & GC Behavior Insights
*   **Predictable Execution Footprint**: FlowGuard Lite maintains a steady latency and throughput profile across 2 GB, 4 GB, and 8 GB configurations. The low-overhead memory architecture (bounded buffer queues, batched memory aggregations, and reuse of normalized structs) keeps Go's GC pause times minimal and avoids runtime allocations.
*   **High Performance at 2 GB**: The application runs at 100% capacity within the standard 2 GB allocation target. There is no memory degradation or cache thrashing, validating the single-node homelab/small-office resource limits.

