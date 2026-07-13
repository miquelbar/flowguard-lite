package sqlite

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
)

func TestRepository_Devices(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_devices_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewRepository(tmpDir, logger)
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

func TestRepository_Baselines(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_baselines_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewRepository(tmpDir, logger)
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

func TestRepository_DeviceProfileQueries(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_profile_test")
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
