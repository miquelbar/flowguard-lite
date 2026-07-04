package risk

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/flowguard/flowguard/internal/storage"
)

type MockDeviceRepository struct {
	Devices   []storage.Device
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
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Devices, nil
}

func (m *MockDeviceRepository) SaveBaseline(ctx context.Context, b *storage.DeviceBaseline) error {
	return nil
}

func (m *MockDeviceRepository) GetBaseline(ctx context.Context, ip string) (*storage.DeviceBaseline, error) {
	return nil, nil
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
	m.mu.Lock()
	defer m.mu.Unlock()
	var filtered []storage.Anomaly
	for _, a := range m.Anomalies {
		if a.Status == "active" && a.CreatedAt.After(since) {
			filtered = append(filtered, a)
		}
	}
	return filtered, nil
}

func TestRiskEngine_CalculateDeviceRisks(t *testing.T) {
	repo := &MockDeviceRepository{}
	engine := NewRiskEngine(repo)

	now := time.Now()

	// 1. Setup mock devices
	repo.Devices = []storage.Device{
		{IP: "192.168.1.100", Hostname: "target-1.local", Label: "Server"},
		{IP: "192.168.1.200", Hostname: "target-2.local", Label: "Smart TV"},
		{IP: "192.168.1.50", Hostname: "target-3.local", Label: "Laptop"},
	}

	// 2. Setup mock anomalies (varying severity and ages)
	repo.Anomalies = []storage.Anomaly{
		// Device 1: High severity triggered 6 hours ago (decay = 18/24 = 0.75 -> decayed weight = 40 * 0.75 = 30)
		{
			IP:        "192.168.1.100",
			Type:      "TRAFFIC_SPIKE",
			Severity:  "high",
			Status:    "active",
			CreatedAt: now.Add(-6 * time.Hour),
		},
		// Device 2: Medium severity triggered 12 hours ago (decay = 12/24 = 0.5 -> decayed weight = 20 * 0.5 = 10)
		// Plus Low severity triggered 2 hours ago (decay = 22/24 = 0.916 -> decayed weight = 10 * 0.916 = 9.16)
		// Total weight = 19.16 -> rounded to 19 (medium risk)
		{
			IP:        "192.168.1.200",
			Type:      "NEW_PORT",
			Severity:  "medium",
			Status:    "active",
			CreatedAt: now.Add(-12 * time.Hour),
		},
		{
			IP:        "192.168.1.200",
			Type:      "NEW_DESTINATION",
			Severity:  "low",
			Status:    "active",
			CreatedAt: now.Add(-2 * time.Hour),
		},
		// Device 3: No active anomalies or older than 24 hours (should be ignored)
		{
			IP:        "192.168.1.50",
			Type:      "TRAFFIC_SPIKE",
			Severity:  "high",
			Status:    "active",
			CreatedAt: now.Add(-30 * time.Hour),
		},
	}

	results, err := engine.CalculateDeviceRisks(context.Background())
	if err != nil {
		t.Fatalf("failed CalculateDeviceRisks: %v", err)
	}

	// Should return only 2 devices (Device 1 and Device 2)
	if len(results) != 2 {
		t.Fatalf("expected 2 risky devices, got %d", len(results))
	}

	// Sorted descending: Device 1 should be first (score 30 > score 19)
	if results[0].IP != "192.168.1.100" || results[0].RiskScore != 30 || results[0].RiskLevel != "medium" {
		t.Errorf("unexpected results[0]: %+v", results[0])
	}

	if results[1].IP != "192.168.1.200" || results[1].RiskScore != 19 || results[1].RiskLevel != "low" {
		t.Errorf("unexpected results[1]: %+v", results[1])
	}
}
