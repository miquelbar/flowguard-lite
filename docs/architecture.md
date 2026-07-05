# Architecture & System Design

FlowGuard Lite is built with an efficient, asynchronous pipeline to process UDP flow packets under very low CPU/memory footprints.

---

## High-Level Data Flow

```text
   +---------------------------------------------+
   |            Router / Exporter Gateway        |
   +----------------------+----------------------+
                          | (NetFlow / sFlow)
                          v (UDP packets)
   +----------------------+----------------------+
   |        Flow Collector (Worker Pool)         |
   +----------------------+----------------------+
                          | (Normalized Events)
                          v (Go Channels)
   +----------------------+----------------------+
   |             Memory Aggregator               |
   +----------------------+----------------------+
                          | (Buffer flushing - 15s)
                          v (Repository Interface)
   +----------------------+----------------------+
   |         Repository Database Driver          |
   +----------------------+----------------------+
        |                                  |
        v                                  v
   +----+----------------+            +----+----------------+
   |  SQLite Shard Engine |            |  DuckDB Engine      |
   |  (Daily db shards)  |            |  (Columnar file)    |
   +---------------------+            +---------------------+
```

---

## 1. Flow Collector

The collector handles high packet arrival rates via a decoupled worker queue:

*   **UDP Sockets:** Listens on port `2055` (NetFlow/IPFIX) and `6343` (sFlow).
*   **Worker Pool:** A pool of goroutines consumes raw UDP payloads, avoiding socket buffer overflows.
*   **Parser Libs:** Uses standard parsing drivers (like `goflow2` structures) to decode packet headers.
*   **Queueing:** Decoded events are pushed to a buffered Go channel (`chan flow.FlowEvent`).

---

## 2. Memory Aggregator

To minimize disk I/O, events are aggregated in memory before database insertion:

*   **Buffering:** Group events by local device IP and destination details over 15-second windows.
*   **Concurrency Locks:** Uses mutex read/write locks to ensure thread safety during writes.
*   **Flush Loop:** An asynchronous ticker flushes the memory buffer every 15 seconds, writing batched records to the database repository.

---

## 3. Repository Pattern

FlowGuard Lite uses the Repository Pattern, keeping core logic database-agnostic.

### Daily SQLite Sharding (Default)
*   **Daily Files:** Instead of a single large SQLite file, FlowGuard Lite writes data into daily shard databases (`flowguard_YYYY-MM-DD.db`).
*   **Benefits:** Deleting expired data is as simple as deleting an old file, avoiding heavy `VACUUM` locks or CPU overhead.
*   **Retention Engine:** Runs nightly, removing database files older than the configured retention days limit.

### DuckDB Analytic Engine (Optional Acceleration)
*   **Columnar Store:** Processes queries over millions of rows in milliseconds.
*   **Dynamic Linking:** Links natively to the DuckDB C++ library via CGO bindings.
