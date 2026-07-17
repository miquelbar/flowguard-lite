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
*   **Bounded Flush Lifecycle:** Flush work is serialized through a bounded internal queue. Proactive flushes do not spawn unbounded goroutines, and explicit `Flush()`/shutdown paths wait for accepted flushes before continuing.

---

## 3. Repository Pattern

FlowGuard Lite uses the Repository Pattern, keeping core logic database-agnostic.

### Daily SQLite Sharding (Default)
*   **Daily Files:** Instead of a single large SQLite file, FlowGuard Lite writes data into daily shard databases (`flowguard_YYYY-MM-DD.db`).
*   **Benefits:** Deleting expired data is as simple as deleting an old file, avoiding heavy `VACUUM` locks or CPU overhead.
*   **Retention Engine:** Runs nightly, removing database files older than the configured retention days limit.

### DuckDB Engine (Experimental)
*   **Columnar Store:** Processes queries over millions of rows in milliseconds.
*   **Dynamic Linking:** Links natively to the DuckDB C++ library via CGO bindings.
*   **Status:** DuckDB query acceleration support is experimental and has limited real-world validation.


---

## 4. Repository Contracts and ACID Boundaries

Detection code depends on narrow repository contracts instead of concrete storage implementations:

*   `FlowRepository` handles retained aggregate queries for UI and traffic views.
*   `BaselineSampleRepository` exposes bounded baseline samples for baseline calculation.
*   `FlowHistoryRepository` exposes retained-history existence checks for anomaly detection.
*   `DeviceRepository` handles device metadata, baselines, policies, notifications, audit logs, and anomalies.

This keeps SQLite and DuckDB behavior aligned and prevents detection logic from casting to a specific backend.

Storage contracts and backend-independent types live in `internal/storage`. Concrete persistence implementations live in backend subpackages:

*   `internal/storage/sqlite` contains SQLite lifecycle, shard, schema, aggregate, policy, notification, audit, device, baseline, and anomaly persistence.
*   `internal/storage/duckdb` contains the equivalent DuckDB implementation.
*   `internal/storage/callbacks`, `internal/storage/codec`, and `internal/storage/flowquery` contain small shared helpers used by those implementations.

Write paths that persist batches use database transactions. Callback side effects are dispatched after persistence through bounded dispatchers, so alert notification hooks cannot create unbounded goroutines or block the storage lock indefinitely. Repository close waits for in-flight anomaly callbacks before closing database connections, and webhook dispatch has an explicit shutdown path before repository close.

Development seeding has a deliberately bounded consistency boundary. SQLite metadata reset is transactional, and config writes use atomic write/rename, but a full `-seed` run spans metadata tables, daily flow shard files, and the YAML config file. FlowGuard Lite does not claim one global transaction across those stores. If the final setup-bypass config write fails, the seed reports an error instead of claiming success; already populated demo database rows are not rolled back across shards.

---

## 5. Configuration Validation

Configuration is validated before daemon startup and before saving settings from the UI. Invalid ports, unsupported storage backends, malformed local CIDRs, unsafe retention windows, invalid webhook formats, and malformed environment overrides fail fast with explicit errors.

Retention remains bounded by design. The default is 7 days and the maximum accepted configuration value is 60 days.

---

## 6. UI Architecture and Regression Gates

The UI is split into feature-specific views under `web/src/features`, view data loading under `web/src/loaders`, shell services under `web/src/services`, shared infrastructure under `web/src/lib`, reusable UI under `web/src/components/ui`, routes under `web/src/routes`, and app-shell state/orchestration under `web/src/app`. `web/src/app/main.js` is kept as the app-shell bootstrap instead of owning view-specific API loading or render state.

Required UI gates:

*   `make docker-ui-test` builds and lints the Vite application in Docker.
*   `make docker-ui-smoke` runs Cypress smoke regressions against mocked APIs.

The Cypress smoke suite covers route rendering, scoped global time controls, mobile detail close controls, retention-aware ranges, device/subnet links, notification editor behavior, and sortable tables.
