package storage_test

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
	duckdbstore "github.com/miquelbar/flowguard-lite/internal/storage/duckdb"
	sqlitestore "github.com/miquelbar/flowguard-lite/internal/storage/sqlite"

	_ "modernc.org/sqlite"
)

func TestStressProfile(t *testing.T) {
	// Initialize logger to discard to not spam output
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// 1. Setup temporary directories
	tmpSQLite, err := os.MkdirTemp("", "stress_sqlite")
	if err != nil {
		t.Fatalf("failed temp dir: %v", err)
	}
	defer os.RemoveAll(tmpSQLite)

	tmpDuckDB, err := os.MkdirTemp("", "stress_duckdb")
	if err != nil {
		t.Fatalf("failed temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDuckDB)

	ctx := context.Background()
	now := time.Now()

	// 2. Initialize repositories
	sqliteRepo, err := sqlitestore.NewRepository(tmpSQLite, logger)
	if err != nil {
		t.Fatalf("sqlite init: %v", err)
	}
	defer sqliteRepo.Close()

	duckRepo, err := duckdbstore.NewRepository(tmpDuckDB, logger)
	if err != nil {
		t.Fatalf("duckdb init: %v", err)
	}
	defer duckRepo.Close()

	// 3. Generate 100,000 mock flow events
	eventsCount := 100000
	mockEvents := make([]flow.FlowEvent, eventsCount)
	for i := 0; i < eventsCount; i++ {
		mockEvents[i] = flow.FlowEvent{
			Timestamp: now.Add(time.Duration(i) * time.Millisecond),
			SrcIP:     fmt.Sprintf("192.168.1.%d", (i%250)+1),
			DstIP:     "8.8.8.8",
			DstPort:   443,
			Protocol:  6,
			Bytes:     1024,
			Packets:   10,
		}
	}

	// 4. Benchmark SQLite insertion
	start := time.Now()
	// Split in chunks of 5000 (just like actual aggregator flushes in batches)
	chunkSize := 5000
	for i := 0; i < eventsCount; i += chunkSize {
		endIdx := i + chunkSize
		if endIdx > eventsCount {
			endIdx = eventsCount
		}
		err = sqliteRepo.SaveAggregates(ctx, now, mockEvents[i:endIdx])
		if err != nil {
			t.Fatalf("sqlite save error: %v", err)
		}
	}
	sqliteDur := time.Since(start)
	t.Logf("SQLite stress insert: %d events in %v (%d events/sec)", eventsCount, sqliteDur, int(float64(eventsCount)/sqliteDur.Seconds()))

	// 5. Benchmark DuckDB insertion
	start = time.Now()
	for i := 0; i < eventsCount; i += chunkSize {
		endIdx := i + chunkSize
		if endIdx > eventsCount {
			endIdx = eventsCount
		}
		err = duckRepo.SaveAggregates(ctx, now, mockEvents[i:endIdx])
		if err != nil {
			t.Fatalf("duckdb save error: %v", err)
		}
	}
	duckDur := time.Since(start)
	t.Logf("DuckDB stress insert: %d events in %v (%d events/sec)", eventsCount, duckDur, int(float64(eventsCount)/duckDur.Seconds()))

	// 6. Profile RAM usage (Target: under 500MB)
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	memMB := float64(m.Alloc) / 1024 / 1024
	t.Logf("Go Heap Alloc memory usage after stress inserts: %.2f MB", memMB)
	if memMB > 500 {
		t.Errorf("Heap Alloc exceeded 500MB ceiling limit: %.2f MB", memMB)
	}

	// 7. Verify disk retention cleanup runs successfully
	// We prune with retention 1 day. Prune should execute without errors.
	if err := sqliteRepo.CleanupRetention(1); err != nil {
		t.Errorf("SQLite CleanupRetention failed: %v", err)
	}
	if err := duckRepo.CleanupRetention(1); err != nil {
		t.Errorf("DuckDB CleanupRetention failed: %v", err)
	}

	// 8. Verify no raw packet payload fields (like payload bytes, headers, PCAPs) are stored
	// We check the schema and ensure columns do not contain names like "payload", "pcap", "raw_data".
	checkRawPayloadTable(t, tmpSQLite, now)
}

func checkRawPayloadTable(t *testing.T, dataDir string, timestamp time.Time) {
	db, err := sql.Open("sqlite", filepath.Join(dataDir, timestamp.Format("2006-01-02")+".sqlite"))
	if err != nil {
		t.Fatalf("failed to open SQLite shard: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("PRAGMA table_info(flow_aggregates)")
	if err != nil {
		t.Fatalf("failed to query table info: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, pk int
		var dfltVal interface{}
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &dfltVal, &pk); err != nil {
			t.Fatalf("scan table info: %v", err)
		}
		// Strict check: no raw packets or payload bytes columns allowed!
		if name == "payload" || name == "packet_data" || name == "pcap" || name == "raw" {
			t.Errorf("forbidden raw payload storage column detected in schema: %s", name)
		}
	}
}
