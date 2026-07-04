package anomaly

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/flowguard/flowguard/internal/baseline"
	"github.com/flowguard/flowguard/internal/flow"
	"github.com/flowguard/flowguard/internal/storage"
)

type MockDeviceRepository struct {
	Anomalies []storage.Anomaly
	mu        sync.Mutex
}

func (m *MockDeviceRepository) UpsertDevice(ctx context.Context, ip string, hostname string, lastSeen time.Time) error {
	return nil
}

func (m *MockDeviceRepository) UpdateDeviceLabel(ctx context.Context, ip string, label string) error {
	return nil
}

func (m *MockDeviceRepository) GetDevice(ctx context.Context, ip string) (*storage.Device, error) {
	return nil, nil
}

func (m *MockDeviceRepository) ListDevices(ctx context.Context) ([]storage.Device, error) {
	return []storage.Device{}, nil
}

func (m *MockDeviceRepository) SaveBaseline(ctx context.Context, b *storage.DeviceBaseline) error {
	return nil
}

func (m *MockDeviceRepository) GetBaseline(ctx context.Context, ip string) (*storage.DeviceBaseline, error) {
	return nil, nil
}

func (m *MockDeviceRepository) SaveAnomaly(ctx context.Context, a *storage.Anomaly) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Anomalies = append(m.Anomalies, *a)
	return nil
}

func (m *MockDeviceRepository) UpdateAnomalyStatus(ctx context.Context, id int64, status string) error {
	return nil
}

func (m *MockDeviceRepository) ListAnomalies(ctx context.Context, limit int) ([]storage.Anomaly, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Anomalies, nil
}

func (m *MockDeviceRepository) GetActiveAnomalies(ctx context.Context, since time.Time) ([]storage.Anomaly, error) {
	return []storage.Anomaly{}, nil
}

func TestAnomalyEngine_DeduplicationAndVolume(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "anomaly_engine_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sqliteRepo, err := storage.NewSQLiteRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}
	defer sqliteRepo.Close()

	mockRepo := &MockDeviceRepository{}
	baseEngine := baseline.NewBaselineEngine(sqliteRepo, logger)
	subnets := []string{"192.168.1.0/24"}

	engine := NewAnomalyEngine(mockRepo, logger, baseEngine, subnets)

	// Set baseline statistics for target device
	ip := "192.168.1.100"
	_ = sqliteRepo.UpsertDevice(context.Background(), ip, "test-device", time.Now())
	_ = sqliteRepo.SaveBaseline(context.Background(), &storage.DeviceBaseline{
		IP:            ip,
		MeanBytes:     2000,
		StdDevBytes:   500,
		MeanPackets:   200,
		StdDevPackets: 50,
		MeanPeers:     5,
		StdDevPeers:   1,
	})
	_ = baseEngine.LoadBaselines(context.Background())

	// 1. Process batch with normal traffic
	batch1 := []flow.FlowEvent{
		{
			Timestamp: time.Now(),
			SrcIP:     ip,
			DstIP:     "8.8.8.8",
			DstPort:   53,
			Protocol:  17,
			Bytes:     2100,
			Packets:   10,
		},
	}
	engine.AnalyzeBatch(context.Background(), sqliteRepo, batch1)
	time.Sleep(50 * time.Millisecond) // wait for async goroutine save

	mockRepo.mu.Lock()
	if len(mockRepo.Anomalies) != 0 {
		t.Errorf("expected 0 anomalies for normal traffic, got %d", len(mockRepo.Anomalies))
	}
	mockRepo.mu.Unlock()

	// 2. Process batch with high bytes (Traffic Spike Anomaly)
	batch2 := []flow.FlowEvent{
		{
			Timestamp: time.Now(),
			SrcIP:     ip,
			DstIP:     "8.8.8.8",
			DstPort:   53,
			Protocol:  17,
			Bytes:     2000000, // 2MB (> minBytesThreshold (1MB) and > Mean+3StdDev (3500))
			Packets:   10,
		},
	}
	engine.AnalyzeBatch(context.Background(), sqliteRepo, batch2)
	time.Sleep(50 * time.Millisecond)

	mockRepo.mu.Lock()
	if len(mockRepo.Anomalies) != 1 {
		t.Fatalf("expected 1 anomaly for traffic spike, got %d", len(mockRepo.Anomalies))
	}
	if mockRepo.Anomalies[0].Type != "TRAFFIC_SPIKE" {
		t.Errorf("expected anomaly type TRAFFIC_SPIKE, got %s", mockRepo.Anomalies[0].Type)
	}
	mockRepo.mu.Unlock()

	// 3. Process another spike batch (should be deduplicated/ignored)
	engine.AnalyzeBatch(context.Background(), sqliteRepo, batch2)
	time.Sleep(50 * time.Millisecond)

	mockRepo.mu.Lock()
	if len(mockRepo.Anomalies) != 1 {
		t.Errorf("expected anomaly to be deduplicated (still 1), got %d", len(mockRepo.Anomalies))
	}
	mockRepo.mu.Unlock()
}
