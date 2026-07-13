package anomaly

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/baseline"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

func newFanoutTestEngine(t *testing.T) (*AnomalyEngine, *MockDeviceRepository) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo := &MockDeviceRepository{}
	baseEngine := baseline.NewBaselineEngine(repo, logger)
	return NewAnomalyEngine(repo, logger, baseEngine, []string{"192.168.1.0/24"}), repo
}

func waitForAnomalies(t *testing.T, repo *MockDeviceRepository, count int) []storage.Anomaly {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		repo.mu.Lock()
		anomalies := append([]storage.Anomaly(nil), repo.Anomalies...)
		repo.mu.Unlock()
		if len(anomalies) >= count {
			return anomalies
		}
		time.Sleep(5 * time.Millisecond)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	t.Fatalf("timed out waiting for %d anomalies; got %d", count, len(repo.Anomalies))
	return nil
}

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
