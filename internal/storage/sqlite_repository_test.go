package storage

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
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
	// 6. Test anomaly callbacks and audit logging
	var callbackTriggered int32
	repo.RegisterAnomalyCallback(func(a *Anomaly) {
		atomic.AddInt32(&callbackTriggered, 1)
	})

	anom3 := &Anomaly{
		IP:          "192.168.1.50",
		Type:        "NEW_DESTINATION",
		Description: "New peer query",
		Severity:    "low",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	_ = repo.SaveAnomaly(ctx, anom3)

	time.Sleep(50 * time.Millisecond) // Allow background goroutine to execute
	if atomic.LoadInt32(&callbackTriggered) != 1 {
		t.Error("expected anomaly save callback to trigger")
	}

	err = repo.SaveAuditLog(ctx, "update_label", "set ip 192.168.1.50 to Laptop")
	if err != nil {
		t.Fatalf("failed saving audit log: %v", err)
	}

	logs, err := repo.ListAuditLogs(ctx, 10)
	if err != nil {
		t.Fatalf("failed querying audit logs: %v", err)
	}
	if len(logs) != 1 || logs[0].Action != "update_label" {
		t.Errorf("unexpected audit logs list: %v", logs)
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

func TestSQLiteRepository_DeviceProfileQueries(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_profile_test")
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

	ctx := context.Background()
	now := time.Now().Truncate(time.Minute)

	// 1. Setup metadata
	err = repo.UpsertDevice(ctx, "192.168.1.100", "test-host", now)
	if err != nil {
		t.Fatalf("failed to upsert device: %v", err)
	}

	anom := &Anomaly{
		IP:          "192.168.1.100",
		Type:        "TRAFFIC_SPIKE",
		Description: "Anomaly 1",
		Severity:    "high",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	err = repo.SaveAnomaly(ctx, anom)
	if err != nil {
		t.Fatalf("failed to save anomaly: %v", err)
	}

	// 2. Setup flows
	flows := []flow.FlowEvent{
		{
			Timestamp: now,
			SrcIP:     "192.168.1.100",
			DstIP:     "8.8.8.8",
			DstPort:   53,
			Protocol:  17,
			Bytes:     1000,
			Packets:   10,
		},
		{
			Timestamp: now,
			SrcIP:     "1.1.1.1",
			DstIP:     "192.168.1.100",
			DstPort:   443,
			Protocol:  6,
			Bytes:     2000,
			Packets:   20,
		},
	}
	err = repo.SaveAggregates(ctx, now, flows)
	if err != nil {
		t.Fatalf("failed to save aggregates: %v", err)
	}

	start := now.Add(-1 * time.Hour)
	end := now.Add(1 * time.Hour)

	// Test GetAnomaliesForIP
	anoms, err := repo.GetAnomaliesForIP(ctx, "192.168.1.100", 10)
	if err != nil {
		t.Fatalf("failed to get anomalies for IP: %v", err)
	}
	if len(anoms) != 1 || anoms[0].Type != "TRAFFIC_SPIKE" {
		t.Errorf("expected 1 anomaly of type TRAFFIC_SPIKE, got %v", anoms)
	}

	// Test GetDeviceTrafficTimeSeries
	ts, err := repo.GetDeviceTrafficTimeSeries(ctx, "192.168.1.100", start, end, 60)
	if err != nil {
		t.Fatalf("failed to get device traffic time series: %v", err)
	}
	if len(ts) != 1 || ts[0].Bytes != 3000 {
		t.Errorf("expected 3000 bytes in time series, got %v", ts)
	}

	// Test GetDeviceTopPeers
	peers, err := repo.GetDeviceTopPeers(ctx, "192.168.1.100", start, end, 10)
	if err != nil {
		t.Fatalf("failed to get device top peers: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}
	if peers[0].Key != "1.1.1.1" || peers[0].Bytes != 2000 {
		t.Errorf("expected top peer to be 1.1.1.1 with 2000 bytes, got %v", peers[0])
	}
	if peers[1].Key != "8.8.8.8" || peers[1].Bytes != 1000 {
		t.Errorf("expected second peer to be 8.8.8.8 with 1000 bytes, got %v", peers[1])
	}

	// Test GetDeviceTopPorts
	ports, err := repo.GetDeviceTopPorts(ctx, "192.168.1.100", start, end, 10)
	if err != nil {
		t.Fatalf("failed to get device top ports: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(ports))
	}
	if ports[0].Key != "443" || ports[0].Bytes != 2000 {
		t.Errorf("expected top port to be 443 with 2000 bytes, got %v", ports[0])
	}
	if ports[1].Key != "53" || ports[1].Bytes != 1000 {
		t.Errorf("expected second port to be 53 with 1000 bytes, got %v", ports[1])
	}
}

func TestSQLitePolicies(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flowguard-sqlite-policies-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	repo, err := NewSQLiteRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to initialize SQLite repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()

	// Register device
	now := time.Now()
	_ = repo.UpsertDevice(ctx, "192.168.1.15", "test-host", now)

	// 1. Test CRUD
	p1 := &Policy{
		Name:                 "Silence Port Scans",
		Scope:                "alert_type",
		Target:               "port_scan",
		SeverityThreshold:    "medium",
		Suppressed:           true,
		CooldownSeconds:      60,
		QuietHoursStart:      "22:00",
		QuietHoursEnd:        "06:00",
		NotificationChannels: []string{"slack", "telegram"},
	}

	err = repo.SavePolicy(ctx, p1)
	if err != nil {
		t.Fatalf("failed to save policy: %v", err)
	}
	if p1.ID == 0 {
		t.Error("expected generated policy ID, got 0")
	}

	// List policies
	list, err := repo.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to list policies: %v", err)
	}
	if len(list) != 1 || list[0].Name != "Silence Port Scans" {
		t.Errorf("unexpected list result: %v", list)
	}

	// Get policy
	retrieved, err := repo.GetPolicy(ctx, p1.ID)
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if retrieved.CooldownSeconds != 60 || !retrieved.Suppressed || len(retrieved.NotificationChannels) != 2 {
		t.Errorf("retrieved policy properties mismatch: %v", retrieved)
	}

	// 2. Test Input Validation
	invalidP := &Policy{
		Name:   "Invalid IP Target",
		Scope:  "ip",
		Target: "not-an-ip",
	}
	err = repo.SavePolicy(ctx, invalidP)
	if err == nil {
		t.Error("expected error validating policy with invalid target IP, got nil")
	}

	invalidSubnet := &Policy{
		Name:   "Invalid Subnet Target",
		Scope:  "subnet",
		Target: "192.168.1.0/50",
	}
	err = repo.SavePolicy(ctx, invalidSubnet)
	if err == nil {
		t.Error("expected error validating policy with invalid target CIDR subnet, got nil")
	}

	invalidHours := &Policy{
		Name:            "Invalid Quiet Hours",
		Scope:           "global",
		QuietHoursStart: "25:00",
		QuietHoursEnd:   "09:99",
	}
	err = repo.SavePolicy(ctx, invalidHours)
	if err == nil {
		t.Error("expected error validating policy with invalid quiet hours, got nil")
	}

	// 3. Test Policy Suppression Rules on SaveAnomaly
	// A. Silence / Suppression toggle
	anomMatch1 := &Anomaly{
		IP:          "192.168.1.15",
		Type:        "port_scan",
		Description: "Port scan activity",
		Severity:    "high",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	err = repo.SaveAnomaly(ctx, anomMatch1)
	if err != nil {
		t.Fatalf("failed to save anomaly: %v", err)
	}
	if anomMatch1.Status != "silenced" {
		t.Errorf("expected anomaly status to be 'silenced' by policy, got '%s'", anomMatch1.Status)
	}

	// B. Severity Threshold suppression
	p2 := &Policy{
		Name:              "Ignore Low/Medium Volumetric",
		Scope:             "alert_type",
		Target:            "volume_anomaly",
		SeverityThreshold: "high",
	}
	_ = repo.SavePolicy(ctx, p2)

	anomMatch2 := &Anomaly{
		IP:          "192.168.1.15",
		Type:        "volume_anomaly",
		Description: "Moderate traffic jump",
		Severity:    "medium",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	_ = repo.SaveAnomaly(ctx, anomMatch2)
	if anomMatch2.Status != "silenced" {
		t.Errorf("expected anomaly status to be 'silenced' by severity threshold, got '%s'", anomMatch2.Status)
	}

	// C. Cooldown deduplication suppression
	p3 := &Policy{
		Name:            "DDoS Cooldown",
		Scope:           "alert_type",
		Target:          "ddos_source",
		CooldownSeconds: 300,
	}
	_ = repo.SavePolicy(ctx, p3)

	anomMatch3a := &Anomaly{
		IP:          "192.168.1.15",
		Type:        "ddos_source",
		Description: "DDoS source flood",
		Severity:    "high",
		Status:      "active",
		CreatedAt:   now.Add(-10 * time.Second),
		UpdatedAt:   now.Add(-10 * time.Second),
	}
	_ = repo.SaveAnomaly(ctx, anomMatch3a)
	if anomMatch3a.Status != "active" {
		t.Errorf("expected first ddos anomaly to be 'active', got '%s'", anomMatch3a.Status)
	}

	anomMatch3b := &Anomaly{
		IP:          "192.168.1.15",
		Type:        "ddos_source",
		Description: "DDoS source flood repeat",
		Severity:    "high",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	_ = repo.SaveAnomaly(ctx, anomMatch3b)
	if anomMatch3b.Status != "silenced" {
		t.Errorf("expected repeated ddos anomaly within cooldown to be 'silenced', got '%s'", anomMatch3b.Status)
	}

	// D. Precedence Order Test (IP > Global)
	pGlobalSilence := &Policy{
		Name:       "Silence Everything Globally",
		Scope:      "global",
		Suppressed: true,
	}
	_ = repo.SavePolicy(ctx, pGlobalSilence)

	pIPActive := &Policy{
		Name:       "Keep This IP Active",
		Scope:      "ip",
		Target:     "192.168.1.15",
		Suppressed: false,
	}
	_ = repo.SavePolicy(ctx, pIPActive)

	anomPrecedence := &Anomaly{
		IP:          "192.168.1.15",
		Type:        "unknown_alert_type",
		Description: "Some alert",
		Severity:    "high",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	_ = repo.SaveAnomaly(ctx, anomPrecedence)
	if anomPrecedence.Status != "active" {
		t.Errorf("expected IP precedence rule (active) to win over global rule (silenced), got status: '%s'", anomPrecedence.Status)
	}

	// 4. Test Delete
	err = repo.DeletePolicy(ctx, p1.ID)
	if err != nil {
		t.Fatalf("failed to delete policy: %v", err)
	}
	_, err = repo.GetPolicy(ctx, p1.ID)
	if err == nil {
		t.Error("expected error fetching deleted policy, got nil")
	}
}
