package ddos

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

type MockDeviceRepository struct {
	storage.DeviceRepository
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

func (m *MockDeviceRepository) anomalyTypes() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	types := make([]string, 0, len(m.Anomalies))
	for _, anomaly := range m.Anomalies {
		types = append(types, anomaly.Type)
	}
	return types
}

func (m *MockDeviceRepository) anomalyCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.Anomalies)
}

func (m *MockDeviceRepository) anomalyAt(idx int) storage.Anomaly {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Anomalies[idx]
}

func waitForAnomalyCount(t *testing.T, repo *MockDeviceRepository, expected int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if repo.anomalyCount() == expected {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d anomalies, got %d (%v)", expected, repo.anomalyCount(), repo.anomalyTypes())
}

func testDetector(repo *MockDeviceRepository) *DDoSDetector {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.DefaultConfig()
	cfg.LocalSubnets = []string{"192.168.1.0/24"}
	cfg.DDoSThresholdPPS = 100
	cfg.DDoSThresholdBPS = 100_000
	cfg.DDoSThresholdFPS = 20
	cfg.SYNFloodThresholdPPS = 50
	cfg.UDPFloodThresholdPPS = 50
	cfg.ICMPFloodThresholdPPS = 10
	return NewDDoSDetector(repo, logger, cfg, nil)
}

func TestDDoSDetector_DetectionAndDeduplication(t *testing.T) {
	repo := &MockDeviceRepository{}
	detector := testDetector(repo)

	ip := "192.168.1.50"

	// 1. Accumulate normal traffic
	detector.Process(&flow.FlowEvent{
		DstIP:    ip,
		Packets:  10,
		Bytes:    1000,
		Protocol: 6, // TCP
	})

	detector.evaluateRates()

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
	waitForAnomalyCount(t, repo, 1)

	if got := repo.anomalyAt(0).Type; got != "DDOS_UDP_FLOOD" {
		t.Errorf("expected DDOS_UDP_FLOOD anomaly type, got %s", got)
	}

	// 3. Repeat high traffic (should be deduplicated)
	detector.Process(&flow.FlowEvent{
		DstIP:    ip,
		Packets:  300,
		Bytes:    30000,
		Protocol: 17,
	})

	detector.evaluateRates()

	if got := repo.anomalyCount(); got != 1 {
		t.Errorf("expected anomaly to be deduplicated (still 1), got %d", got)
	}
}

func TestDDoSDetector_ThresholdFloodTypes(t *testing.T) {
	tests := []struct {
		name         string
		events       []flow.FlowEvent
		expectedType string
		victimIP     string
	}{
		{
			name: "high packets per second",
			events: []flow.FlowEvent{{
				DstIP:    "192.168.1.50",
				Packets:  600,
				Bytes:    60_000,
				Protocol: 6,
			}},
			expectedType: "DDOS_ATTACK",
			victimIP:     "192.168.1.50",
		},
		{
			name: "high bytes per second",
			events: []flow.FlowEvent{{
				DstIP:    "192.168.1.51",
				Packets:  10,
				Bytes:    600_000,
				Protocol: 6,
			}},
			expectedType: "DDOS_ATTACK",
			victimIP:     "192.168.1.51",
		},
		{
			name:         "high flows per second",
			events:       repeatedFlowEvents(105, "192.168.1.55"),
			expectedType: "DDOS_FLOW_FLOOD",
			victimIP:     "192.168.1.55",
		},
		{
			name: "udp flood",
			events: []flow.FlowEvent{{
				DstIP:    "192.168.1.52",
				Packets:  300,
				Bytes:    30_000,
				Protocol: 17,
			}},
			expectedType: "DDOS_UDP_FLOOD",
			victimIP:     "192.168.1.52",
		},
		{
			name: "icmp flood",
			events: []flow.FlowEvent{{
				DstIP:    "192.168.1.53",
				Packets:  100,
				Bytes:    10_000,
				Protocol: 1,
			}},
			expectedType: "DDOS_ICMP_FLOOD",
			victimIP:     "192.168.1.53",
		},
		{
			name: "tcp syn flood",
			events: []flow.FlowEvent{{
				DstIP:    "192.168.1.54",
				Packets:  300,
				Bytes:    30_000,
				Protocol: 6,
				TCPFlags: 0x02,
			}},
			expectedType: "DDOS_SYN_FLOOD",
			victimIP:     "192.168.1.54",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &MockDeviceRepository{}
			detector := testDetector(repo)

			for i := range tt.events {
				detector.Process(&tt.events[i])
			}
			detector.evaluateRates()
			waitForAnomalyCount(t, repo, 1)

			types := repo.anomalyTypes()
			if !slices.Contains(types, tt.expectedType) {
				t.Fatalf("expected anomaly type %s, got %v", tt.expectedType, types)
			}
			anomaly := repo.anomalyAt(0)
			if anomaly.IP != tt.victimIP {
				t.Fatalf("expected victim IP %s, got %s", tt.victimIP, anomaly.IP)
			}
			if anomaly.Severity == "critical" {
				t.Fatalf("DDoS detector should not emit critical severity by default, got %+v", anomaly)
			}
			if anomaly.Description == "" {
				t.Fatal("expected explainable DDoS anomaly description")
			}
		})
	}
}

func repeatedFlowEvents(count int, dstIP string) []flow.FlowEvent {
	events := make([]flow.FlowEvent, count)
	for i := range events {
		events[i] = flow.FlowEvent{
			DstIP:    dstIP,
			Packets:  1,
			Bytes:    100,
			Protocol: 6,
		}
	}
	return events
}

func TestDDoSDetector_IgnoresNonLocalOrBelowThresholdTraffic(t *testing.T) {
	repo := &MockDeviceRepository{}
	detector := testDetector(repo)

	detector.Process(&flow.FlowEvent{
		DstIP:    "203.0.113.10",
		Packets:  10_000,
		Bytes:    10_000_000,
		Protocol: 17,
	})
	detector.Process(&flow.FlowEvent{
		DstIP:    "192.168.1.60",
		Packets:  100,
		Bytes:    10_000,
		Protocol: 6,
	})

	detector.evaluateRates()
	if got := repo.anomalyCount(); got != 0 {
		t.Fatalf("expected no DDoS anomalies for non-local or below-threshold traffic, got %d (%v)", got, repo.anomalyTypes())
	}
}
