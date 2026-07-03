package ddos

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/flowguard/flowguard/internal/config"
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

func TestDDoSDetector_DetectionAndDeduplication(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo := &MockDeviceRepository{}
	
	cfg := config.DefaultConfig()
	cfg.LocalSubnets = []string{"192.168.1.0/24"}
	cfg.DDoSThresholdPPS = 100
	cfg.SYNFloodThresholdPPS = 50
	cfg.UDPFloodThresholdPPS = 50
	cfg.ICMPFloodThresholdPPS = 10

	detector := NewDDoSDetector(repo, logger, cfg, nil)

	ip := "192.168.1.50"

	// 1. Accumulate normal traffic
	detector.Process(&flow.FlowEvent{
		DstIP:    ip,
		Packets:  10,
		Bytes:    1000,
		Protocol: 6, // TCP
	})

	detector.evaluateRates()
	time.Sleep(50 * time.Millisecond) // wait for async write

	repo.mu.Lock()
	if len(repo.Anomalies) != 0 {
		t.Errorf("expected 0 DDoS anomalies for normal traffic, got %d", len(repo.Anomalies))
	}
	repo.mu.Unlock()

	// 2. Accumulate high traffic rate (UDP Flood: 300 packets -> 60 PPS > threshold 50)
	detector.Process(&flow.FlowEvent{
		DstIP:    ip,
		Packets:  300,
		Bytes:    30000,
		Protocol: 17, // UDP
	})

	detector.evaluateRates()
	time.Sleep(50 * time.Millisecond)

	repo.mu.Lock()
	if len(repo.Anomalies) != 1 {
		t.Fatalf("expected 1 anomaly triggered for UDP flood, got %d", len(repo.Anomalies))
	}
	if repo.Anomalies[0].Type != "DDOS_UDP_FLOOD" {
		t.Errorf("expected DDOS_UDP_FLOOD anomaly type, got %s", repo.Anomalies[0].Type)
	}
	repo.mu.Unlock()

	// 3. Repeat high traffic (should be deduplicated)
	detector.Process(&flow.FlowEvent{
		DstIP:    ip,
		Packets:  300,
		Bytes:    30000,
		Protocol: 17,
	})

	detector.evaluateRates()
	time.Sleep(50 * time.Millisecond)

	repo.mu.Lock()
	if len(repo.Anomalies) != 1 {
		t.Errorf("expected anomaly to be deduplicated (still 1), got %d", len(repo.Anomalies))
	}
	repo.mu.Unlock()
}
