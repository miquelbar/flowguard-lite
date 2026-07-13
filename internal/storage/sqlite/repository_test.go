package sqlite

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
)

func TestRepository_MigratesLegacyAnomaliesDestinationIP(t *testing.T) {
	tmpDir := t.TempDir()
	metaPath := filepath.Join(tmpDir, "metadata.sqlite")
	legacyDB, err := sql.Open("sqlite", metaPath)
	if err != nil {
		t.Fatalf("failed to open legacy metadata db: %v", err)
	}
	_, err = legacyDB.Exec(`
		CREATE TABLE anomalies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL,
			type TEXT NOT NULL,
			description TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'medium',
			status TEXT NOT NULL DEFAULT 'active',
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);
		CREATE INDEX idx_anomalies_created ON anomalies (created_at DESC);
		CREATE INDEX idx_anomalies_ip ON anomalies (ip);
	`)
	if closeErr := legacyDB.Close(); closeErr != nil {
		t.Fatalf("failed to close legacy metadata db: %v", closeErr)
	}
	if err != nil {
		t.Fatalf("failed to create legacy anomalies schema: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("expected legacy schema migration to succeed, got: %v", err)
	}
	defer repo.Close()

	anomaly := &Anomaly{
		IP:            "192.168.1.10",
		DestinationIP: "203.0.113.10",
		Type:          "NEW_DESTINATION",
		Description:   "legacy migration regression",
		Severity:      "medium",
		Status:        "active",
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	if err := repo.SaveAnomaly(context.Background(), anomaly); err != nil {
		t.Fatalf("failed to save anomaly after legacy migration: %v", err)
	}
	list, err := repo.ListAnomalies(context.Background(), 10)
	if err != nil {
		t.Fatalf("failed to list anomalies after legacy migration: %v", err)
	}
	if len(list) != 1 || list[0].DestinationIP != "203.0.113.10" {
		t.Fatalf("destination_ip was not migrated/read correctly: %+v", list)
	}
}

func TestRepository_SaveAndQuery(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewRepository(tmpDir, logger)
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
	if err := repo.UpsertDevice(ctx, "192.168.1.10", "workstation.local", now); err != nil {
		t.Fatalf("failed to upsert test device: %v", err)
	}
	if err := repo.UpsertDevice(ctx, "192.168.1.20", "camera.local", now); err != nil {
		t.Fatalf("failed to upsert test device: %v", err)
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

	topDevices, err := repo.GetTopDevicesByVolume(ctx, start, end, 5)
	if err != nil {
		t.Fatalf("failed to query top devices: %v", err)
	}
	if len(topDevices) != 2 {
		t.Fatalf("expected 2 top devices, got %d", len(topDevices))
	}
	if topDevices[0].Key != "192.168.1.20" || topDevices[0].Bytes != 10000 {
		t.Errorf("expected top device 192.168.1.20 with 10000 bytes, got %+v", topDevices[0])
	}

	heatmap, err := repo.GetDeviceActivityHeatmap(ctx, start, end, 5)
	if err != nil {
		t.Fatalf("failed to query device heatmap: %v", err)
	}
	if len(heatmap) != 2 {
		t.Fatalf("expected 2 heatmap cells, got %d: %+v", len(heatmap), heatmap)
	}
	if heatmap[0].Hour < 0 || heatmap[0].Hour > 23 {
		t.Fatalf("expected heatmap hour in range, got %+v", heatmap[0])
	}

	// 4. Query Top Protocols
	protocols, err := repo.GetTopProtocols(ctx, start, end, 10)
	if err != nil {
		t.Fatalf("failed to query top protocols: %v", err)
	}
	if len(protocols) != 2 {
		t.Fatalf("expected 2 protocol keys, got %d", len(protocols))
	}
	if protocols[0].Key != "6" || protocols[0].Bytes != 10000 {
		t.Errorf("expected top protocol 6 with 10000 bytes, got %s with %d", protocols[0].Key, protocols[0].Bytes)
	}

	// 5. Query traffic time-series with 5-minute buckets
	series, err := repo.GetTrafficTimeSeries(ctx, start, end, 300)
	if err != nil {
		t.Fatalf("failed to query traffic time series: %v", err)
	}
	if len(series) != 1 {
		t.Fatalf("expected 1 time-series bucket, got %d: %+v", len(series), series)
	}
	if series[0].Bytes != 12000 || series[0].Packets != 40 {
		t.Errorf("unexpected traffic time-series bucket: %+v", series[0])
	}
}

func TestRepository_AggregatesKeepCollectorSourcesSeparate(t *testing.T) {
	tmpDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}
	defer repo.Close()

	now := time.Now().UTC().Truncate(time.Minute)
	events := []flow.FlowEvent{
		{
			Timestamp:     now,
			CollectorKind: flow.CollectorKindNetFlow,
			CollectorID:   "unifi-gateway",
			ExporterIP:    "192.168.1.1",
			SrcIP:         "192.168.1.10",
			DstIP:         "8.8.8.8",
			DstPort:       53,
			Protocol:      17,
			Bytes:         500,
			Packets:       5,
		},
		{
			Timestamp:     now,
			CollectorKind: flow.CollectorKindPCAP,
			CollectorID:   "pcap:br0",
			ExporterIP:    "pcap:br0",
			SrcIP:         "192.168.1.10",
			DstIP:         "8.8.8.8",
			DstPort:       53,
			Protocol:      17,
			Bytes:         700,
			Packets:       7,
		},
	}
	if err := repo.SaveAggregates(context.Background(), now, events); err != nil {
		t.Fatalf("failed to save aggregates: %v", err)
	}
	records, err := repo.QueryFlowAggregateRecords(context.Background(), now.Add(-time.Minute), now.Add(time.Minute), "", 17, 53, 10)
	if err != nil {
		t.Fatalf("failed querying records: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records split by collector source, got %d: %+v", len(records), records)
	}
	seen := map[string]uint64{}
	for _, rec := range records {
		seen[rec.CollectorKind+"|"+rec.CollectorID] = rec.Bytes
	}
	if seen["netflow|unifi-gateway"] != 500 || seen["pcap|pcap:br0"] != 700 {
		t.Fatalf("unexpected collector split records: %+v", records)
	}
}

func TestRepository_MigratesLegacyFlowAggregateShard(t *testing.T) {
	tmpDir := t.TempDir()
	flowsDir := filepath.Join(tmpDir, "flows")
	if err := os.MkdirAll(flowsDir, 0755); err != nil {
		t.Fatalf("failed to create legacy flows dir: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	shardPath := filepath.Join(flowsDir, now.Format("2006-01-02")+".sqlite")
	legacyDB, err := sql.Open("sqlite", shardPath)
	if err != nil {
		t.Fatalf("failed to open legacy shard: %v", err)
	}
	_, err = legacyDB.Exec(`
		CREATE TABLE flow_aggregates (
			bucket_ts INTEGER NOT NULL,
			src_ip TEXT NOT NULL,
			dst_ip TEXT NOT NULL,
			dst_port INTEGER NOT NULL,
			protocol INTEGER NOT NULL,
			bytes INTEGER NOT NULL,
			packets INTEGER NOT NULL,
			flows INTEGER NOT NULL,
			PRIMARY KEY (bucket_ts, src_ip, dst_ip, dst_port, protocol)
		);
		INSERT INTO flow_aggregates (bucket_ts, src_ip, dst_ip, dst_port, protocol, bytes, packets, flows)
		VALUES (?, '192.168.1.10', '8.8.8.8', 53, 17, 500, 5, 1);
	`, now.Unix())
	if closeErr := legacyDB.Close(); closeErr != nil {
		t.Fatalf("failed to close legacy shard: %v", closeErr)
	}
	if err != nil {
		t.Fatalf("failed to create legacy shard: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}
	defer repo.Close()

	records, err := repo.QueryFlowAggregateRecords(context.Background(), now.Add(-time.Minute), now.Add(time.Minute), "", 17, 53, 10)
	if err != nil {
		t.Fatalf("failed querying migrated shard: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one migrated legacy record, got %d: %+v", len(records), records)
	}
	if records[0].CollectorKind != flow.CollectorKindUnknown || records[0].CollectorID != flow.CollectorKindUnknown {
		t.Fatalf("expected legacy record to default collector identity to unknown, got %+v", records[0])
	}
}

func TestRepository_Retention(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_retention_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewRepository(tmpDir, logger)
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

func BenchmarkRepository_SaveAggregates(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "sqlite_bench")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewRepository(tmpDir, logger)
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
