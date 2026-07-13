package baseline

import (
	"context"
	"io"
	"log/slog"
	"math"
	"os"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/storage"
	duckdbstore "github.com/miquelbar/flowguard-lite/internal/storage/duckdb"
	sqlitestore "github.com/miquelbar/flowguard-lite/internal/storage/sqlite"
)

type MockDeviceRepository struct {
	storage.DeviceRepository
	Device    *storage.Device
	Baseline  *storage.DeviceBaseline
	SavedBas  *storage.DeviceBaseline
	UpsertErr error
}

func (m *MockDeviceRepository) UpsertDevice(ctx context.Context, ip string, hostname string, lastSeen time.Time) error {
	return nil
}

func (m *MockDeviceRepository) UpdateDeviceLabel(ctx context.Context, ip string, label string) error {
	return nil
}

func (m *MockDeviceRepository) GetDevice(ctx context.Context, ip string) (*storage.Device, error) {
	return m.Device, nil
}

func (m *MockDeviceRepository) ListDevices(ctx context.Context) ([]storage.Device, error) {
	if m.Device != nil {
		return []storage.Device{*m.Device}, nil
	}
	return []storage.Device{}, nil
}

func (m *MockDeviceRepository) SaveBaseline(ctx context.Context, b *storage.DeviceBaseline) error {
	m.SavedBas = b
	return nil
}

func (m *MockDeviceRepository) GetBaseline(ctx context.Context, ip string) (*storage.DeviceBaseline, error) {
	return m.Baseline, nil
}

func (m *MockDeviceRepository) SaveAnomaly(ctx context.Context, a *storage.Anomaly) error {
	return nil
}

func (m *MockDeviceRepository) UpdateAnomalyStatus(ctx context.Context, id int64, status string) error {
	return nil
}

func (m *MockDeviceRepository) ListAnomalies(ctx context.Context, limit int) ([]storage.Anomaly, error) {
	return []storage.Anomaly{}, nil
}

func (m *MockDeviceRepository) GetActiveAnomalies(ctx context.Context, since time.Time) ([]storage.Anomaly, error) {
	return []storage.Anomaly{}, nil
}

func (m *MockDeviceRepository) SaveAuditLog(ctx context.Context, action string, details string) error {
	return nil
}

func (m *MockDeviceRepository) ListAuditLogs(ctx context.Context, limit int) ([]storage.AuditLog, error) {
	return []storage.AuditLog{}, nil
}

func (m *MockDeviceRepository) GetAnomaliesForIP(ctx context.Context, ip string, limit int) ([]storage.Anomaly, error) {
	return []storage.Anomaly{}, nil
}

func TestCalcMeanAndStdDev(t *testing.T) {
	samples := []float64{10, 12, 23, 23, 16, 23, 21, 16}
	mean := calcMean(samples)
	if math.Abs(mean-18.0) > 0.001 {
		t.Errorf("expected mean 18.0, got %f", mean)
	}

	stdDev := calcStdDev(samples, mean)
	// Expected variance: (64 + 36 + 25 + 25 + 4 + 25 + 9 + 4) / 8 = 192 / 8 = 24
	// Expected StdDev: sqrt(24) = 4.8989
	if math.Abs(stdDev-4.8989) > 0.001 {
		t.Errorf("expected stddev 4.8989, got %f", stdDev)
	}
}

func TestBaselineEngine_IsAnomaly(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo := &MockDeviceRepository{}
	engine := NewBaselineEngine(repo, logger)

	// Set custom lower threshold bounds to test anomaly check easily
	engine.minBytesThreshold = 1000
	engine.minPacketsThreshold = 100
	engine.minPeersThreshold = 5

	ip := "192.168.1.10"
	engine.cachedBaselines[ip] = &storage.DeviceBaseline{
		IP:            ip,
		MeanBytes:     2000,
		StdDevBytes:   500,
		MeanPackets:   200,
		StdDevPackets: 50,
		MeanPeers:     10,
		StdDevPeers:   2,
	}

	testCases := []struct {
		bytes     uint64
		packets   uint64
		peers     int
		isAnomaly bool
	}{
		{2500, 200, 10, false}, // normal bytes (2500 < Mean + 3xStdDev = 3500)
		{4000, 200, 10, true},  // bytes anomaly (> 3500)
		{2500, 400, 10, true},  // packets anomaly (> 350)
		{2500, 200, 18, true},  // peers anomaly (> 16)
		{800, 200, 10, false},  // bytes value is below minBytesThreshold (800 < 1000)
	}

	for i, tc := range testCases {
		anom, _ := engine.IsAnomaly(ip, tc.bytes, tc.packets, tc.peers)
		if anom != tc.isAnomaly {
			t.Errorf("case %d: expected IsAnomaly to be %v, got %v", i, tc.isAnomaly, anom)
		}
	}
}

func TestBaselineEngine_CalculateBaselines(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "baseline_calc_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sqliteRepo, err := sqlitestore.NewRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}
	defer sqliteRepo.Close()

	ctx := context.Background()
	now := time.Now()

	// Insert device into persistent inventory
	err = sqliteRepo.UpsertDevice(ctx, "192.168.1.50", "printer.local", now)
	if err != nil {
		t.Fatalf("failed setup: %v", err)
	}

	// Insert 6 flow aggregates (need at least 5 for baseline)
	for i := 0; i < 6; i++ {
		ts := now.Add(time.Duration(-i) * time.Minute)
		err := sqliteRepo.SaveAggregates(ctx, ts, []flow.FlowEvent{
			{
				Timestamp:  ts,
				SrcIP:      "192.168.1.50",
				DstIP:      "8.8.8.8",
				DstPort:    53,
				Protocol:   17,
				Bytes:      1000 + uint64(i*100),
				Packets:    10,
				ExporterIP: "192.168.1.1",
			},
		})
		if err != nil {
			t.Fatalf("failed saving flow data: %v", err)
		}
	}

	engine := NewBaselineEngine(sqliteRepo, logger)

	// Trigger calculation
	err = engine.CalculateBaselines(ctx, sqliteRepo)
	if err != nil {
		t.Fatalf("baseline calculation failed: %v", err)
	}

	// Load and verify
	baseline := engine.GetCachedBaseline("192.168.1.50")
	if baseline == nil {
		t.Fatal("expected baseline to be calculated and cached, got nil")
	}

	// Expected mean bytes: (1000 + 1100 + 1200 + 1300 + 1400 + 1500) / 6 = 1250
	if baseline.MeanBytes != 1250 {
		t.Errorf("expected MeanBytes 1250, got %f", baseline.MeanBytes)
	}
}

func TestBaselineEngine_CalculateBaselinesUsesFlowRepositoryContract(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	duckRepo, err := duckdbstore.NewRepository(t.TempDir(), logger)
	if err != nil {
		t.Fatalf("failed to create DuckDB repository: %v", err)
	}
	defer duckRepo.Close()

	ctx := context.Background()
	now := time.Now()
	const ip = "192.168.1.51"
	if err := duckRepo.UpsertDevice(ctx, ip, "printer-duck.local", now); err != nil {
		t.Fatalf("failed to upsert DuckDB device: %v", err)
	}

	for i := 0; i < 6; i++ {
		ts := now.Add(time.Duration(-i) * time.Minute)
		if err := duckRepo.SaveAggregates(ctx, ts, []flow.FlowEvent{{
			Timestamp:  ts,
			SrcIP:      ip,
			DstIP:      "8.8.4.4",
			DstPort:    53,
			Protocol:   17,
			Bytes:      2000 + uint64(i*100),
			Packets:    20,
			ExporterIP: "192.168.1.1",
		}}); err != nil {
			t.Fatalf("failed saving DuckDB flow data: %v", err)
		}
	}

	engine := NewBaselineEngine(duckRepo, logger)
	if err := engine.CalculateBaselines(ctx, duckRepo); err != nil {
		t.Fatalf("DuckDB baseline calculation failed: %v", err)
	}

	baseline := engine.GetCachedBaseline(ip)
	if baseline == nil {
		t.Fatal("expected DuckDB-backed baseline to be calculated and cached, got nil")
	}
	if baseline.MeanBytes != 2250 {
		t.Errorf("expected DuckDB MeanBytes 2250, got %f", baseline.MeanBytes)
	}
}
