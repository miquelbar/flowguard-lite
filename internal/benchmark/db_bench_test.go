package benchmark

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
	duckdbstore "github.com/miquelbar/flowguard-lite/internal/storage/duckdb"
	sqlitestore "github.com/miquelbar/flowguard-lite/internal/storage/sqlite"
)

// Helper to pre-populate repository with loaded aggregates for query benchmarks
func populateRepository(repo interface {
	SaveAggregates(ctx context.Context, ts time.Time, aggregates []flow.FlowEvent) error
}, gen *FlowEventGenerator, count int, start time.Time) {
	events := gen.GenerateBusyOffice(count, start)
	chunkSize := 1000
	ctx := context.Background()
	for i := 0; i < len(events); i += chunkSize {
		end := i + chunkSize
		if end > len(events) {
			end = len(events)
		}
		_ = repo.SaveAggregates(ctx, start, events[i:end])
	}
}

// 1. SQLite SaveAggregates Benchmark
func BenchmarkSQLite_SaveAggregates(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "bench_sqlite_save")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := sqlitestore.NewRepository(tmpDir, logger)
	if err != nil {
		b.Fatalf("failed to create sqlite repo: %v", err)
	}
	defer repo.Close()

	gen := NewFlowEventGenerator(42)
	now := time.Now()
	batch := gen.GenerateBusyOffice(1000, now)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Use a shifting timestamp per write loop to write into SQLite shards
		ts := now.Add(time.Duration(i) * time.Minute)
		err = repo.SaveAggregates(ctx, ts, batch)
		if err != nil {
			b.Fatalf("sqlite save aggregates failed: %v", err)
		}
	}
}

// 2. DuckDB SaveAggregates Benchmark
func BenchmarkDuckDB_SaveAggregates(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "bench_duckdb_save")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := duckdbstore.NewRepository(tmpDir, logger)
	if err != nil {
		b.Fatalf("failed to create duckdb repo: %v", err)
	}
	defer repo.Close()

	gen := NewFlowEventGenerator(42)
	now := time.Now()
	batch := gen.GenerateBusyOffice(1000, now)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ts := now.Add(time.Duration(i) * time.Minute)
		err = repo.SaveAggregates(ctx, ts, batch)
		if err != nil {
			b.Fatalf("duckdb save aggregates failed: %v", err)
		}
	}
}

// 3. SQLite Query Benchmarks
func BenchmarkSQLite_Queries(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "bench_sqlite_query")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := sqlitestore.NewRepository(tmpDir, logger)
	if err != nil {
		b.Fatalf("failed to create sqlite repo: %v", err)
	}
	defer repo.Close()

	// Seed 20,000 aggregates into the database
	gen := NewFlowEventGenerator(42)
	now := time.Now()
	populateRepository(repo, gen, 20000, now)
	ctx := context.Background()

	b.Run("TopSources_24h", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err = repo.GetTopSources(ctx, now.Add(-24*time.Hour), now.Add(24*time.Hour), 10)
			if err != nil {
				b.Fatalf("query failed: %v", err)
			}
		}
	})

	b.Run("TopPorts_7d", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err = repo.GetTopPorts(ctx, now.Add(-7*24*time.Hour), now.Add(7*24*time.Hour), 10)
			if err != nil {
				b.Fatalf("query failed: %v", err)
			}
		}
	})

	b.Run("TrafficTimeSeries_6h", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err = repo.GetTrafficTimeSeries(ctx, now.Add(-6*time.Hour), now.Add(6*time.Hour), 60)
			if err != nil {
				b.Fatalf("query failed: %v", err)
			}
		}
	})
}

// 4. DuckDB Query Benchmarks
func BenchmarkDuckDB_Queries(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "bench_duckdb_query")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := duckdbstore.NewRepository(tmpDir, logger)
	if err != nil {
		b.Fatalf("failed to create duckdb repo: %v", err)
	}
	defer repo.Close()

	// Seed 20,000 aggregates into the database
	gen := NewFlowEventGenerator(42)
	now := time.Now()
	populateRepository(repo, gen, 20000, now)
	ctx := context.Background()

	b.Run("TopSources_24h", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err = repo.GetTopSources(ctx, now.Add(-24*time.Hour), now.Add(24*time.Hour), 10)
			if err != nil {
				b.Fatalf("query failed: %v", err)
			}
		}
	})

	b.Run("TopPorts_7d", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err = repo.GetTopPorts(ctx, now.Add(-7*24*time.Hour), now.Add(7*24*time.Hour), 10)
			if err != nil {
				b.Fatalf("query failed: %v", err)
			}
		}
	})

	b.Run("TrafficTimeSeries_6h", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err = repo.GetTrafficTimeSeries(ctx, now.Add(-6*time.Hour), now.Add(6*time.Hour), 60)
			if err != nil {
				b.Fatalf("query failed: %v", err)
			}
		}
	})
}

// 5. Shard Retention Pruning Benchmark
func BenchmarkStorage_Pruning(b *testing.B) {
	// SQLite
	b.Run("SQLite_Cleanup", func(b *testing.B) {
		tmpDir, err := os.MkdirTemp("", "bench_sqlite_prune")
		if err != nil {
			b.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		repo, err := sqlitestore.NewRepository(tmpDir, logger)
		if err != nil {
			b.Fatalf("failed to create sqlite repo: %v", err)
		}
		defer repo.Close()

		// Write some dummy aggregates in multiple daily shards
		gen := NewFlowEventGenerator(42)
		now := time.Now()
		ctx := context.Background()
		batch := gen.GenerateBusyOffice(100, now)

		for i := 0; i < 5; i++ {
			ts := now.AddDate(0, 0, -i)
			_ = repo.SaveAggregates(ctx, ts, batch)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err = repo.CleanupRetention(2)
			if err != nil {
				b.Fatalf("prune failed: %v", err)
			}
		}
	})

	// DuckDB
	b.Run("DuckDB_Cleanup", func(b *testing.B) {
		tmpDir, err := os.MkdirTemp("", "bench_duckdb_prune")
		if err != nil {
			b.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		repo, err := duckdbstore.NewRepository(tmpDir, logger)
		if err != nil {
			b.Fatalf("failed to create duckdb repo: %v", err)
		}
		defer repo.Close()

		gen := NewFlowEventGenerator(42)
		now := time.Now()
		ctx := context.Background()
		batch := gen.GenerateBusyOffice(100, now)

		for i := 0; i < 5; i++ {
			ts := now.AddDate(0, 0, -i)
			_ = repo.SaveAggregates(ctx, ts, batch)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err = repo.CleanupRetention(2)
			if err != nil {
				b.Fatalf("prune failed: %v", err)
			}
		}
	})
}
