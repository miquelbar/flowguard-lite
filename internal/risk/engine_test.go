package risk

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/flowguard/flowguard/internal/storage"
)

type MockDeviceRepository struct {
	storage.DeviceRepository
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
		if a.CreatedAt.After(since) {
			filtered = append(filtered, a)
		}
	}
	return filtered, nil
}

func (m *MockDeviceRepository) SaveAuditLog(ctx context.Context, action string, details string) error {
	return nil
}

func (m *MockDeviceRepository) ListAuditLogs(ctx context.Context, limit int) ([]storage.AuditLog, error) {
	return []storage.AuditLog{}, nil
}

func (m *MockDeviceRepository) GetAnomaliesForIP(ctx context.Context, ip string, limit int) ([]storage.Anomaly, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var filtered []storage.Anomaly
	for _, a := range m.Anomalies {
		if a.IP == ip {
			filtered = append(filtered, a)
			if len(filtered) >= limit {
				break
			}
		}
	}
	return filtered, nil
}

func TestRiskEngine_CalculateDeviceRisks_DecayAndCapping(t *testing.T) {
	repo := &MockDeviceRepository{}
	engine := NewRiskEngine(repo)

	now := time.Now()

	repo.Devices = []storage.Device{
		{IP: "192.168.1.100", Hostname: "target-1.local", Label: "Server"},
		{IP: "192.168.1.50", Hostname: "target-3.local", Label: "Laptop"},
	}

	repo.Anomalies = []storage.Anomaly{
		// Device 1: High severity triggered 6 hours ago (decay = 18/24 = 0.75 -> decayed weight = 40 * 0.75 = 30)
		{
			IP:        "192.168.1.100",
			Type:      "TRAFFIC_SPIKE",
			Severity:  "high",
			Status:    "active",
			CreatedAt: now.Add(-6 * time.Hour),
		},
		// Device 2: Older than 24 hours (should be ignored)
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

	if len(results) != 1 {
		t.Fatalf("expected 1 risky device, got %d", len(results))
	}

	if results[0].IP != "192.168.1.100" || results[0].RiskScore != 30 || results[0].RiskLevel != "medium" {
		t.Errorf("unexpected results[0]: %+v", results[0])
	}
	if len(results[0].Evidence) != 1 || results[0].Evidence[0].Type != "TRAFFIC_SPIKE" {
		t.Errorf("expected 1 evidence item for TRAFFIC_SPIKE, got %+v", results[0].Evidence)
	}
}

func TestRiskEngine_CorrelationBooster(t *testing.T) {
	repo := &MockDeviceRepository{}
	engine := NewRiskEngine(repo)

	now := time.Now()

	repo.Devices = []storage.Device{
		{IP: "192.168.1.100", Hostname: "correlated.local"},
		{IP: "192.168.1.200", Hostname: "uncorrelated.local"},
	}

	repo.Anomalies = []storage.Anomaly{
		// Device 1 (correlated): Suricata alert + Traffic spike within 10 minutes
		// Both low severity (weight 10 + 10 = 20)
		// Triggered 0 hours ago (no decay)
		// +20 correlation booster = 40 (medium level)
		{
			IP:        "192.168.1.100",
			Type:      "SURICATA_ALERT",
			Severity:  "low",
			Status:    "active",
			CreatedAt: now,
		},
		{
			IP:        "192.168.1.100",
			Type:      "TRAFFIC_SPIKE",
			Severity:  "low",
			Status:    "active",
			CreatedAt: now.Add(-10 * time.Minute),
		},

		// Device 2 (uncorrelated): Suricata alert + Traffic spike spaced by 3 hours (no boost)
		// Both low severity (weight 10 + 10 = 20)
		// No boost = 20 (low level)
		{
			IP:        "192.168.1.200",
			Type:      "SURICATA_ALERT",
			Severity:  "low",
			Status:    "active",
			CreatedAt: now,
		},
		{
			IP:        "192.168.1.200",
			Type:      "TRAFFIC_SPIKE",
			Severity:  "low",
			Status:    "active",
			CreatedAt: now.Add(-3 * time.Hour),
		},
	}

	results, err := engine.CalculateDeviceRisks(context.Background())
	if err != nil {
		t.Fatalf("failed CalculateDeviceRisks: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(results))
	}

	// First element should be 192.168.1.100 (score 40 > 20)
	if results[0].IP != "192.168.1.100" || results[0].RiskScore != 40 || results[0].RiskLevel != "medium" {
		t.Errorf("expected device 192.168.1.100 to have score 40, got: %+v", results[0])
	}

	// Second element should be 192.168.1.200 (score 19 due to 3h decay)
	if results[1].IP != "192.168.1.200" || results[1].RiskScore != 19 || results[1].RiskLevel != "low" {
		t.Errorf("expected device 192.168.1.200 to have score 19, got: %+v", results[1])
	}
}

func TestRiskEngine_BreakdownCalculations(t *testing.T) {
	repo := &MockDeviceRepository{}
	engine := NewRiskEngine(repo)

	now := time.Now()

	repo.Devices = []storage.Device{
		{IP: "192.168.1.10", Hostname: "test-device.local"},
	}

	repo.Anomalies = []storage.Anomaly{
		{
			ID:        1,
			IP:        "192.168.1.10",
			Type:      "SURICATA_ALERT",
			Severity:  "high",
			Status:    "active",
			CreatedAt: now.Add(-12 * time.Hour), // ~12 hours ago -> decay ~0.5 -> decayed weight ~20
		},
		{
			ID:        2,
			IP:        "192.168.1.10",
			Type:      "TRAFFIC_SPIKE",
			Severity:  "medium",
			Status:    "active",
			CreatedAt: now.Add(-11 * time.Hour - 30 * time.Minute), // ~11.5 hours ago -> correlates with Suricata alert (0.5h difference)
		},
	}

	results, err := engine.CalculateDeviceRisks(context.Background())
	if err != nil {
		t.Fatalf("failed CalculateDeviceRisks: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	res := results[0]
	// High alert = 40 * ~0.5 = ~20
	// Medium alert = 20 * ~0.52 = ~10.4
	// Boost = 20
	// Total score should be around 50
	if res.RiskScore < 48 || res.RiskScore > 52 {
		t.Errorf("expected risk score around 50, got %d", res.RiskScore)
	}

	bd := res.Breakdown
	if bd.CorrelationBoost != 20.0 {
		t.Errorf("expected correlation boost 20, got %f", bd.CorrelationBoost)
	}

	if bd.ActiveAlertCount != 2 {
		t.Errorf("expected active alert count 2, got %d", bd.ActiveAlertCount)
	}

	if len(bd.AlertBreakdown) != 2 {
		t.Fatalf("expected 2 alert contributors, got %d", len(bd.AlertBreakdown))
	}

	c1 := bd.AlertBreakdown[0]
	if c1.Type != "SURICATA_ALERT" || c1.BaseWeight != 40.0 || c1.DecayFactor < 0.49 || c1.DecayFactor > 0.51 || c1.Contribution < 19.9 || c1.Contribution > 20.1 {
		t.Errorf("unexpected contributor 1: %+v", c1)
	}

	c2 := bd.AlertBreakdown[1]
	// 11.5h ago -> decay = 1 - 11.5/24 = 0.52083 -> weight = 20 -> contribution = 10.416
	if c2.Type != "TRAFFIC_SPIKE" || c2.BaseWeight != 20.0 || c2.DecayFactor < 0.51 || c2.DecayFactor > 0.53 || c2.Contribution < 10.3 || c2.Contribution > 10.5 {
		t.Errorf("unexpected contributor 2: %+v", c2)
	}
}
