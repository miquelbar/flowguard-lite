package storage

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flowguard/flowguard/internal/flow"
)

func TestDuckDBRepository_SaveAndQuery(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "duckdb_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewDuckDBRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create DuckDB repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	now := time.Now()

	// 1. Insert aggregates
	aggregates := []flow.FlowEvent{
		{SrcIP: "192.168.1.10", DstIP: "8.8.8.8", DstPort: 53, Protocol: 17, Bytes: 1024, Packets: 10},
		{SrcIP: "192.168.1.10", DstIP: "8.8.8.8", DstPort: 53, Protocol: 17, Bytes: 512, Packets: 5},
	}
	err = repo.SaveAggregates(ctx, now, aggregates)
	if err != nil {
		t.Fatalf("failed saving aggregates: %v", err)
	}

	// 2. Query top sources
	sources, err := repo.GetTopSources(ctx, now.Add(-1*time.Minute), now.Add(1*time.Minute), 5)
	if err != nil {
		t.Fatalf("failed querying top sources: %v", err)
	}
	if len(sources) != 1 || sources[0].Key != "192.168.1.10" || sources[0].Bytes != 1536 || sources[0].Packets != 15 {
		t.Errorf("unexpected top sources result: %v", sources)
	}

	// 3. Query top destinations
	dests, err := repo.GetTopDestinations(ctx, now.Add(-1*time.Minute), now.Add(1*time.Minute), 5)
	if err != nil {
		t.Fatalf("failed querying top destinations: %v", err)
	}
	if len(dests) != 1 || dests[0].Key != "8.8.8.8" {
		t.Errorf("unexpected top destinations result: %v", dests)
	}

	// 4. Query top protocols
	protocols, err := repo.GetTopProtocols(ctx, now.Add(-1*time.Minute), now.Add(1*time.Minute), 5)
	if err != nil {
		t.Fatalf("failed querying top protocols: %v", err)
	}
	if len(protocols) != 1 || protocols[0].Key != "17" || protocols[0].Bytes != 1536 || protocols[0].Packets != 15 {
		t.Errorf("unexpected top protocols result: %v", protocols)
	}

	// 5. Query traffic time-series with 5-minute buckets
	series, err := repo.GetTrafficTimeSeries(ctx, now.Add(-1*time.Minute), now.Add(1*time.Minute), 300)
	if err != nil {
		t.Fatalf("failed querying traffic time series: %v", err)
	}
	if len(series) != 1 || series[0].Bytes != 1536 || series[0].Packets != 15 || series[0].Flows != 2 {
		t.Errorf("unexpected traffic time series result: %+v", series)
	}
}

func TestDuckDBRepository_DevicesAndAnomalies(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "duckdb_test_devs")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewDuckDBRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create DuckDB repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	now := time.Now()

	// 1. Upsert device
	err = repo.UpsertDevice(ctx, "192.168.1.50", "laptop.local", now)
	if err != nil {
		t.Fatalf("failed to upsert device: %v", err)
	}

	// 2. Update label
	err = repo.UpdateDeviceLabel(ctx, "192.168.1.50", "Work Laptop")
	if err != nil {
		t.Fatalf("failed to update label: %v", err)
	}

	// 3. List devices
	devs, err := repo.ListDevices(ctx)
	if err != nil {
		t.Fatalf("failed listing devices: %v", err)
	}
	if len(devs) != 1 || devs[0].Label != "Work Laptop" || devs[0].Hostname != "laptop.local" {
		t.Errorf("unexpected listed devices: %v", devs)
	}

	// 3b. Get device details
	deviceDetails, err := repo.GetDevice(ctx, "192.168.1.50")
	if err != nil {
		t.Fatalf("failed getting device: %v", err)
	}
	if deviceDetails == nil || deviceDetails.Label != "Work Laptop" {
		t.Errorf("unexpected device details: %v", deviceDetails)
	}

	// 4. Save and query baseline
	baseline := &DeviceBaseline{
		IP:        "192.168.1.50",
		MeanBytes: 2000,
		UpdatedAt: now,
	}
	err = repo.SaveBaseline(ctx, baseline)
	if err != nil {
		t.Fatalf("failed saving baseline: %v", err)
	}
	bFetched, err := repo.GetBaseline(ctx, "192.168.1.50")
	if err != nil {
		t.Fatalf("failed fetching baseline: %v", err)
	}
	if bFetched.MeanBytes != 2000 {
		t.Errorf("unexpected mean bytes in baseline: %v", bFetched)
	}

	// 5. Save anomaly and callbacks
	var callbackTriggered int32
	repo.RegisterAnomalyCallback(func(a *Anomaly) {
		atomic.AddInt32(&callbackTriggered, 1)
	})

	anom := &Anomaly{
		IP:          "192.168.1.50",
		Type:        "TRAFFIC_SPIKE",
		Description: "High bytes",
		Severity:    "high",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	err = repo.SaveAnomaly(ctx, anom)
	if err != nil {
		t.Fatalf("failed saving anomaly: %v", err)
	}

	time.Sleep(50 * time.Millisecond) // Allow callback to run
	if atomic.LoadInt32(&callbackTriggered) != 1 {
		t.Error("expected anomaly save callback to be triggered")
	}

	// 6. List and update anomaly
	anoms, err := repo.ListAnomalies(ctx, 10)
	if err != nil {
		t.Fatalf("failed querying anomalies: %v", err)
	}
	if len(anoms) != 1 || anoms[0].Type != "TRAFFIC_SPIKE" {
		t.Errorf("unexpected listed anomalies: %v", anoms)
	}

	err = repo.UpdateAnomalyStatus(ctx, anom.ID, "acknowledged")
	if err != nil {
		t.Fatalf("failed to update status: %v", err)
	}

	// 7. Audit logging
	err = repo.SaveAuditLog(ctx, "block_ip", "blocked 10.0.0.5")
	if err != nil {
		t.Fatalf("failed saving audit log: %v", err)
	}
	logs, err := repo.ListAuditLogs(ctx, 10)
	if err != nil {
		t.Fatalf("failed listing audit logs: %v", err)
	}
	if len(logs) != 1 || logs[0].Action != "block_ip" {
		t.Errorf("unexpected audit logs result: %v", logs)
	}
}

func TestDuckDBRepository_DeviceProfileQueries(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "duckdb_profile_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewDuckDBRepository(tmpDir, logger)
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
