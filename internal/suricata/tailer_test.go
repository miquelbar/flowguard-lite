package suricata

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/flowguard/flowguard/internal/storage"
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

func TestTailer_AlertIngestAndDeduplication(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "eve_json_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo := &MockDeviceRepository{}
	subnets := []string{"192.168.1.0/24"}

	tailer := NewTailer(repo, logger, tmpFile.Name(), subnets)

	// 1. Process normal non-alert line
	normalLine := `{"timestamp":"2026-07-03T21:40:00Z","event_type":"dns","src_ip":"192.168.1.100","dest_ip":"8.8.8.8"}`
	tailer.processLine(normalLine)
	time.Sleep(50 * time.Millisecond)

	repo.mu.Lock()
	if len(repo.Anomalies) != 0 {
		t.Errorf("expected 0 anomalies for non-alert event, got %d", len(repo.Anomalies))
	}
	repo.mu.Unlock()

	// 2. Process valid Suricata alert line
	alertLine1 := `{"timestamp":"2026-07-03T21:40:00Z","event_type":"alert","src_ip":"192.168.1.100","dest_ip":"8.8.8.8","alert":{"signature_id":2018402,"signature":"ET POLICY Suspicious DNS Query","category":"Potentially Bad Traffic","severity":2}}`
	tailer.processLine(alertLine1)
	time.Sleep(50 * time.Millisecond)

	repo.mu.Lock()
	if len(repo.Anomalies) != 1 {
		t.Fatalf("expected 1 anomaly for Suricata alert, got %d", len(repo.Anomalies))
	}
	if repo.Anomalies[0].Type != "SURICATA_ALERT" || repo.Anomalies[0].Severity != "medium" {
		t.Errorf("unexpected anomaly triggered: %+v", repo.Anomalies[0])
	}
	repo.mu.Unlock()

	// 3. Process same alert line (should be deduplicated)
	tailer.processLine(alertLine1)
	time.Sleep(50 * time.Millisecond)

	repo.mu.Lock()
	if len(repo.Anomalies) != 1 {
		t.Errorf("expected duplicate alert to be deduplicated (still 1), got %d", len(repo.Anomalies))
	}
	repo.mu.Unlock()
}
