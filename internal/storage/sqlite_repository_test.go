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

func TestSQLiteRepository_Devices(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_devices_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewSQLiteRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	now := time.Now().Truncate(time.Second) // SQLite string conversion accuracy

	// 1. Upsert a new device
	err = repo.UpsertDevice(ctx, "192.168.1.50", "printer.local", now)
	if err != nil {
		t.Fatalf("failed to upsert: %v", err)
	}

	// 2. Fetch it
	dev, err := repo.GetDevice(ctx, "192.168.1.50")
	if err != nil {
		t.Fatalf("failed to get: %v", err)
	}
	if dev == nil {
		t.Fatal("expected device to be found, got nil")
	}
	if dev.IP != "192.168.1.50" || dev.Hostname != "printer.local" || dev.Label != "" {
		t.Errorf("unexpected device values: %+v", dev)
	}

	// 3. Update manual label
	err = repo.UpdateDeviceLabel(ctx, "192.168.1.50", "Office Printer")
	if err != nil {
		t.Fatalf("failed to update label: %v", err)
	}

	// 4. Verify update
	dev, err = repo.GetDevice(ctx, "192.168.1.50")
	if err != nil {
		t.Fatalf("failed to get: %v", err)
	}
	if dev.Label != "Office Printer" {
		t.Errorf("expected label 'Office Printer', got '%s'", dev.Label)
	}

	// 5. List devices
	devices, err := repo.ListDevices(ctx)
	if err != nil {
		t.Fatalf("failed to list: %v", err)
	}
	if len(devices) != 1 || devices[0].IP != "192.168.1.50" {
		t.Errorf("unexpected devices list: %v", devices)
	}
}

func TestSQLiteRepository_Baselines(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_baselines_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewSQLiteRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	// Save parent device first to satisfy foreign key constraint
	err = repo.UpsertDevice(ctx, "192.168.1.100", "", now)
	if err != nil {
		t.Fatalf("failed to setup device: %v", err)
	}

	b := &DeviceBaseline{
		IP:            "192.168.1.100",
		MeanBytes:     50000.5,
		StdDevBytes:   1000.2,
		MeanPackets:   100.1,
		StdDevPackets: 5.4,
		MeanPeers:     12.0,
		StdDevPeers:   1.1,
		UpdatedAt:     now,
	}

	// 1. Save baseline
	err = repo.SaveBaseline(ctx, b)
	if err != nil {
		t.Fatalf("failed to save baseline: %v", err)
	}

	// 2. Load and verify
	loaded, err := repo.GetBaseline(ctx, "192.168.1.100")
	if err != nil {
		t.Fatalf("failed to query baseline: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected baseline to be found, got nil")
	}

	if loaded.MeanBytes != 50000.5 || loaded.StdDevBytes != 1000.2 || loaded.MeanPackets != 100.1 || loaded.MeanPeers != 12.0 {
		t.Errorf("unexpected baseline values: %+v", loaded)
	}
}

func TestSQLiteRepository_Anomalies(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_anomalies_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewSQLiteRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	// Save parent device first to satisfy foreign key constraint
	err = repo.UpsertDevice(ctx, "192.168.1.100", "", now)
	if err != nil {
		t.Fatalf("failed setup: %v", err)
	}

	anom := &Anomaly{
		IP:          "192.168.1.100",
		Type:        "TRAFFIC_SPIKE",
		Description: "Abnormal volume spike",
		Severity:    "high",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// 1. Save Anomaly
	err = repo.SaveAnomaly(ctx, anom)
	if err != nil {
		t.Fatalf("failed to save anomaly: %v", err)
	}
	if anom.ID == 0 {
		t.Error("expected populated auto-increment anomaly ID, got 0")
	}

	// 2. List anomalies
	list, err := repo.ListAnomalies(ctx, 10)
	if err != nil {
		t.Fatalf("failed listing anomalies: %v", err)
	}
	if len(list) != 1 || list[0].IP != "192.168.1.100" || list[0].Status != "active" {
		t.Errorf("unexpected anomalies list output: %v", list)
	}

	// 3. Update status
	err = repo.UpdateAnomalyStatus(ctx, anom.ID, "acknowledged")
	if err != nil {
		t.Fatalf("failed to update anomaly status: %v", err)
	}

	// 4. Verify update
	list, _ = repo.ListAnomalies(ctx, 10)
	if len(list) != 1 || list[0].Status != "acknowledged" {
		t.Errorf("expected status 'acknowledged', got '%s'", list[0].Status)
	}

	// 5. Save another active anomaly and verify GetActiveAnomalies
	anom2 := &Anomaly{
		IP:          "192.168.1.100",
		Type:        "NEW_PORT",
		Description: "New port query",
		Severity:    "low",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	_ = repo.SaveAnomaly(ctx, anom2)

	activeList, err := repo.GetActiveAnomalies(ctx, now.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("failed query active anomalies: %v", err)
	}
	if len(activeList) != 1 || activeList[0].Type != "NEW_PORT" {
		t.Errorf("expected 1 active anomaly (NEW_PORT), got: %v", activeList)
	}
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
