package device

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/flowguard/flowguard/internal/flow"
	"github.com/flowguard/flowguard/internal/storage"
)

type MockDeviceRepository struct {
	storage.DeviceRepository
	mu      sync.Mutex
	Devices map[string]*storage.Device
}

func NewMockDeviceRepository() *MockDeviceRepository {
	return &MockDeviceRepository{
		Devices: make(map[string]*storage.Device),
	}
}

func (m *MockDeviceRepository) UpsertDevice(ctx context.Context, ip string, hostname string, lastSeen time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	d, ok := m.Devices[ip]
	if !ok {
		d = &storage.Device{
			IP:        ip,
			FirstSeen: lastSeen,
		}
		m.Devices[ip] = d
	}
	d.LastSeen = lastSeen
	if hostname != "" {
		d.Hostname = hostname
	}
	return nil
}

func (m *MockDeviceRepository) UpdateDeviceLabel(ctx context.Context, ip string, label string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d, ok := m.Devices[ip]; ok {
		d.Label = label
		return nil
	}
	return nil
}

func (m *MockDeviceRepository) GetDevice(ctx context.Context, ip string) (*storage.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.Devices[ip]
	if !ok {
		return nil, nil
	}
	return d, nil
}

func (m *MockDeviceRepository) ListDevices(ctx context.Context) ([]storage.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]storage.Device, 0, len(m.Devices))
	for _, d := range m.Devices {
		res = append(res, *d)
	}
	return res, nil
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

type MockFlowProcessor struct {
	mu     sync.Mutex
	Events []*flow.FlowEvent
}

func (m *MockFlowProcessor) Process(e *flow.FlowEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events = append(m.Events, e)
}

func TestDeviceProfiler_IsLocalIP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	subnets := []string{"192.168.1.0/24", "10.0.0.0/8"}
	p := NewDeviceProfiler(nil, logger, subnets, nil)

	testCases := []struct {
		ip      string
		isLocal bool
	}{
		{"192.168.1.50", true},
		{"192.168.2.50", false},
		{"10.0.0.1", true},
		{"8.8.8.8", false},
		{"127.0.0.1", false},
		{"224.0.0.1", false},
		{"invalid", false},
	}

	for _, tc := range testCases {
		res := p.isLocalIP(tc.ip)
		if res != tc.isLocal {
			t.Errorf("expected isLocalIP(%s) to be %v, got %v", tc.ip, tc.isLocal, res)
		}
	}
}

func TestDeviceProfiler_DiscoveryAndChaining(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo := NewMockDeviceRepository()
	next := &MockFlowProcessor{}
	subnets := []string{"192.168.1.0/24"}

	p := NewDeviceProfiler(repo, logger, subnets, next)
	p.Start()
	defer p.Shutdown()

	now := time.Now()
	// Process a flow event containing local source IP and external destination IP
	p.Process(&flow.FlowEvent{
		Timestamp: now,
		SrcIP:     "192.168.1.100",
		DstIP:     "8.8.8.8",
		Bytes:     100,
	})

	// Wait for async discovery upsert to database to run
	time.Sleep(50 * time.Millisecond)

	// 1. Verify device was added to inventory map
	dev, err := repo.GetDevice(context.Background(), "192.168.1.100")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dev == nil {
		t.Fatal("expected discovered device to exist in inventory, got nil")
	}
	if dev.IP != "192.168.1.100" {
		t.Errorf("expected IP 192.168.1.100, got %s", dev.IP)
	}

	// 2. Verify destination IP (8.8.8.8) was not discovered because it is external
	extDev, _ := repo.GetDevice(context.Background(), "8.8.8.8")
	if extDev != nil {
		t.Error("expected external destination IP not to be discovered")
	}

	// 3. Verify event was chained downstream
	next.mu.Lock()
	defer next.mu.Unlock()
	if len(next.Events) != 1 {
		t.Fatalf("expected 1 chained event, got %d", len(next.Events))
	}
	if next.Events[0].SrcIP != "192.168.1.100" {
		t.Errorf("expected chained event SrcIP to match, got %s", next.Events[0].SrcIP)
	}
}
