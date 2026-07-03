package storage

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/flowguard/flowguard/internal/flow"
)

func TestSQLiteRepository_SaveAndQuery(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewSQLiteRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}
	defer repo.Close()

	now := time.Now()
	// Minute aggregator simulation
	aggregates := []flow.FlowEvent{
		{
			Timestamp:  now,
			SrcIP:      "192.168.1.10",
			DstIP:      "8.8.8.8",
			DstPort:    53,
			Protocol:   17,
			Bytes:      500,
			Packets:    5,
			ExporterIP: "192.168.1.1",
		},
		{
			Timestamp:  now,
			SrcIP:      "192.168.1.10",
			DstIP:      "1.1.1.1",
			DstPort:    53,
			Protocol:   17,
			Bytes:      1500,
			Packets:    15,
			ExporterIP: "192.168.1.1",
		},
		{
			Timestamp:  now,
			SrcIP:      "192.168.1.20",
			DstIP:      "8.8.8.8",
			DstPort:    443,
			Protocol:   6,
			Bytes:      10000,
			Packets:    20,
			ExporterIP: "192.168.1.1",
		},
	}

	ctx := context.Background()
	if err := repo.SaveAggregates(ctx, now, aggregates); err != nil {
		t.Fatalf("failed to save aggregates: %v", err)
	}

	// Verify database shard file was created on disk
	dateStr := now.Format("2006-01-02")
	dbPath := filepath.Join(tmpDir, "flows", dateStr+".sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("expected shard database file to exist at %s, but got err: %v", dbPath, err)
	}

	// 1. Query Top Sources
	start := now.Add(-1 * time.Hour)
	end := now.Add(1 * time.Hour)
	sources, err := repo.GetTopSources(ctx, start, end, 10)
	if err != nil {
		t.Fatalf("failed to query top sources: %v", err)
	}

	if len(sources) != 2 {
		t.Fatalf("expected 2 source keys, got %d", len(sources))
	}
	// Sorted by bytes desc: 192.168.1.20 (10000) then 192.168.1.10 (2000 total)
	if sources[0].Key != "192.168.1.20" || sources[0].Bytes != 10000 {
		t.Errorf("expected top source key 192.168.1.20 with 10000 bytes, got %s with %d", sources[0].Key, sources[0].Bytes)
	}
	if sources[1].Key != "192.168.1.10" || sources[1].Bytes != 2000 {
		t.Errorf("expected second source key 192.168.1.10 with 2000 bytes, got %s with %d", sources[1].Key, sources[1].Bytes)
	}

	// 2. Query Top Destinations
	dests, err := repo.GetTopDestinations(ctx, start, end, 1)
	if err != nil {
		t.Fatalf("failed to query top destinations: %v", err)
	}
	if len(dests) != 1 {
		t.Fatalf("expected limit of 1 destination key, got %d", len(dests))
	}
	// Sorted by bytes: 8.8.8.8 has 10500 bytes (500 + 10000)
	if dests[0].Key != "8.8.8.8" || dests[0].Bytes != 10500 {
		t.Errorf("expected top destination 8.8.8.8 with 10500 bytes, got %s with %d", dests[0].Key, dests[0].Bytes)
	}

	// 3. Query Top Ports
	ports, err := repo.GetTopPorts(ctx, start, end, 10)
	if err != nil {
		t.Fatalf("failed to query top ports: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("expected 2 port keys, got %d", len(ports))
	}
	if ports[0].Key != "443" || ports[0].Bytes != 10000 {
		t.Errorf("expected top port 443 with 10000 bytes, got %s with %d", ports[0].Key, ports[0].Bytes)
	}
}

func TestSQLiteRepository_Retention(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_retention_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewSQLiteRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}

	ctx := context.Background()

	// 1. Save aggregates for today
	today := time.Now()
	if err := repo.SaveAggregates(ctx, today, []flow.FlowEvent{
		{Timestamp: today, SrcIP: "192.168.1.10", DstIP: "8.8.8.8", Bytes: 100},
	}); err != nil {
		t.Fatalf("failed to save today's data: %v", err)
	}

	// 2. Save aggregates for 10 days ago (expired shard)
	tenDaysAgo := today.AddDate(0, 0, -10)
	if err := repo.SaveAggregates(ctx, tenDaysAgo, []flow.FlowEvent{
		{Timestamp: tenDaysAgo, SrcIP: "192.168.1.10", DstIP: "8.8.8.8", Bytes: 100},
	}); err != nil {
		t.Fatalf("failed to save historical data: %v", err)
	}

	// Verify both exist
	todayPath := filepath.Join(tmpDir, "flows", today.Format("2006-01-02")+".sqlite")
	oldPath := filepath.Join(tmpDir, "flows", tenDaysAgo.Format("2006-01-02")+".sqlite")

	if _, err := os.Stat(todayPath); err != nil {
		t.Errorf("today's shard not found: %v", err)
	}
	if _, err := os.Stat(oldPath); err != nil {
		t.Errorf("historical shard not found: %v", err)
	}

	// Run retention cleanup for 7 days
	if err := repo.CleanupRetention(7); err != nil {
		t.Fatalf("retention run failed: %v", err)
	}

	// Verify today's file still exists, but old file is deleted
	if _, err := os.Stat(todayPath); err != nil {
		t.Errorf("today's shard was incorrectly deleted: %v", err)
	}
	if _, err := os.Stat(oldPath); err == nil {
		t.Errorf("historical shard was not deleted by retention policy")
	}

	repo.Close()
}

func BenchmarkSQLiteRepository_SaveAggregates(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "sqlite_bench")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewSQLiteRepository(tmpDir, logger)
	if err != nil {
		b.Fatalf("failed to create repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	now := time.Now()

	// 1000 synthetic flow events
	batch := make([]flow.FlowEvent, 1000)
	for i := 0; i < 1000; i++ {
		batch[i] = flow.FlowEvent{
			Timestamp: now,
			SrcIP:     "192.168.1.10",
			DstIP:     "8.8.8.8",
			DstPort:   80,
			Protocol:  6,
			Bytes:     100,
			Packets:   1,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := repo.SaveAggregates(ctx, now, batch); err != nil {
			b.Fatalf("failed to save: %v", err)
		}
	}
}
