package anomaly

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/baseline"
	"github.com/miquelbar/flowguard-lite/internal/flow"
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

func TestAnomalyEngineNewDestinationAndPort(t *testing.T) {
	tmpDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sqliteRepo, err := storage.NewSQLiteRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}
	defer sqliteRepo.Close()

	ctx := context.Background()
	sourceIP := "192.168.1.101"
	knownDestination := "198.51.100.10"
	historical := time.Now().Add(-time.Hour).UTC()
	if err := sqliteRepo.SaveAggregates(ctx, historical, []flow.FlowEvent{{
		Timestamp: historical, SrcIP: sourceIP, DstIP: knownDestination,
		DstPort: 53, Protocol: 17, Bytes: 512, Packets: 2,
	}}); err != nil {
		t.Fatalf("failed to seed historical aggregate: %v", err)
	}

	mockRepo := &MockDeviceRepository{}
	engine := NewAnomalyEngine(
		mockRepo,
		logger,
		baseline.NewBaselineEngine(sqliteRepo, logger),
		[]string{"192.168.1.0/24"},
	)

	engine.AnalyzeBatch(ctx, sqliteRepo, []flow.FlowEvent{{
		Timestamp: time.Now().UTC(), SrcIP: sourceIP, DstIP: "203.0.113.101",
		DstPort: 53, Protocol: 17, Bytes: 256, Packets: 1,
	}})
	anomalies := waitForAnomalies(t, mockRepo, 1)
	if anomalies[0].Type != "NEW_DESTINATION" ||
		anomalies[0].DestinationIP != "203.0.113.101" ||
		anomalies[0].Severity != "medium" {
		t.Fatalf("unexpected new destination anomaly: %+v", anomalies[0])
	}
	for _, field := range []string{
		"what happened:", "why unusual:", "baseline used:", "current value:",
		"expected value:", "confidence:", "recommended next check:",
	} {
		if !strings.Contains(anomalies[0].Description, field) {
			t.Errorf("new destination explanation missing %q: %s", field, anomalies[0].Description)
		}
	}

	engine.AnalyzeBatch(ctx, sqliteRepo, []flow.FlowEvent{{
		Timestamp: time.Now().UTC(), SrcIP: sourceIP, DstIP: knownDestination,
		DstPort: 8443, Protocol: 6, Bytes: 512, Packets: 2,
	}})
	anomalies = waitForAnomalies(t, mockRepo, 2)
	if anomalies[1].Type != "NEW_PORT" || anomalies[1].Severity != "low" {
		t.Fatalf("unexpected new port anomaly: %+v", anomalies[1])
	}
	for _, field := range []string{
		"what happened:", "why unusual:", "baseline used:", "current value:",
		"expected value:", "confidence:", "recommended next check:",
	} {
		if !strings.Contains(anomalies[1].Description, field) {
			t.Errorf("new port explanation missing %q: %s", field, anomalies[1].Description)
		}
	}
}

func TestAnomalyEnginePacketCountTrafficSpike(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sqliteRepo, err := storage.NewSQLiteRepository(t.TempDir(), logger)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}
	defer sqliteRepo.Close()

	const sourceIP = "192.168.1.102"
	if err := sqliteRepo.UpsertDevice(context.Background(), sourceIP, "packet-heavy", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := sqliteRepo.SaveBaseline(context.Background(), &storage.DeviceBaseline{
		IP: sourceIP, MeanBytes: 500_000, StdDevBytes: 100_000,
		MeanPackets: 200, StdDevPackets: 50,
	}); err != nil {
		t.Fatal(err)
	}
	baseEngine := baseline.NewBaselineEngine(sqliteRepo, logger)
	if err := baseEngine.LoadBaselines(context.Background()); err != nil {
		t.Fatal(err)
	}

	mockRepo := &MockDeviceRepository{}
	engine := NewAnomalyEngine(mockRepo, logger, baseEngine, []string{"192.168.1.0/24"})
	engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{{
		Timestamp: time.Now().UTC(), SrcIP: sourceIP, DstIP: "203.0.113.102",
		DstPort: 443, Protocol: 6, Bytes: 1000, Packets: 1500,
	}})

	anomalies := waitForAnomalies(t, mockRepo, 1)
	if anomalies[0].Type != "TRAFFIC_SPIKE" || anomalies[0].Severity != "high" {
		t.Fatalf("unexpected packet-count traffic spike anomaly: %+v", anomalies[0])
	}
	if !strings.Contains(anomalies[0].Description, "packet count") {
		t.Fatalf("expected packet-count explanation, got: %s", anomalies[0].Description)
	}
}

func TestAnomalyEngineDestinationFanout(t *testing.T) {
	engine, repo := newFanoutTestEngine(t)
	batch := make([]flow.FlowEvent, destinationFanoutMin)
	for i := range batch {
		batch[i] = flow.FlowEvent{
			SrcIP: "192.168.1.50", DstIP: fmt.Sprintf("198.51.100.%d", i+1),
			DstPort: 443, Protocol: 6, Bytes: 60, Packets: 1,
		}
	}

	engine.AnalyzeBatch(context.Background(), nil, batch)
	anomalies := waitForAnomalies(t, repo, 1)
	if anomalies[0].Type != "DESTINATION_FANOUT" || anomalies[0].Severity != "high" {
		t.Fatalf("unexpected destination fan-out anomaly: %+v", anomalies[0])
	}
	for _, field := range []string{
		"what happened:", "why unusual:", "baseline used:", "current value:",
		"expected value:", "confidence:", "recommended next check:",
	} {
		if !strings.Contains(anomalies[0].Description, field) {
			t.Errorf("destination fan-out explanation missing %q: %s", field, anomalies[0].Description)
		}
	}

	engine.AnalyzeBatch(context.Background(), nil, batch)
	time.Sleep(25 * time.Millisecond)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.Anomalies) != 1 {
		t.Fatalf("expected destination fan-out deduplication, got %d alerts", len(repo.Anomalies))
	}
}

func TestAnomalyEnginePortFanout(t *testing.T) {
	engine, repo := newFanoutTestEngine(t)
	batch := make([]flow.FlowEvent, portFanoutMin)
	for i := range batch {
		batch[i] = flow.FlowEvent{
			SrcIP: "192.168.1.60", DstIP: "203.0.113.20",
			DstPort: 1000 + i, Protocol: 6, Bytes: 60, Packets: 1,
		}
	}

	engine.AnalyzeBatch(context.Background(), nil, batch)
	anomalies := waitForAnomalies(t, repo, 1)
	if anomalies[0].Type != "PORT_FANOUT" || anomalies[0].Severity != "high" {
		t.Fatalf("unexpected port fan-out anomaly: %+v", anomalies[0])
	}
	if !strings.Contains(anomalies[0].Description, "16 unique destination ports on 203.0.113.20") {
		t.Fatalf("port fan-out explanation lacks deterministic target/count: %s", anomalies[0].Description)
	}
}

func TestAnomalyEngineFanoutFalsePositiveControls(t *testing.T) {
	t.Run("below thresholds", func(t *testing.T) {
		engine, repo := newFanoutTestEngine(t)
		var batch []flow.FlowEvent
		for i := 0; i < destinationFanoutMin-1; i++ {
			batch = append(batch, flow.FlowEvent{
				SrcIP: "192.168.1.70", DstIP: fmt.Sprintf("198.51.100.%d", i+1),
				DstPort: 443, Protocol: 6, Packets: 1,
			})
		}
		engine.AnalyzeBatch(context.Background(), nil, batch)
		time.Sleep(25 * time.Millisecond)
		repo.mu.Lock()
		defer repo.mu.Unlock()
		if len(repo.Anomalies) != 0 {
			t.Fatalf("expected no alert below fan-out thresholds, got %+v", repo.Anomalies)
		}
	})

	t.Run("high packet density", func(t *testing.T) {
		engine, repo := newFanoutTestEngine(t)
		batch := make([]flow.FlowEvent, destinationFanoutMin)
		for i := range batch {
			batch[i] = flow.FlowEvent{
				SrcIP: "192.168.1.71", DstIP: fmt.Sprintf("203.0.113.%d", i+1),
				DstPort: 443, Protocol: 6, Packets: maxScanPacketsPerTarget + 1,
			}
		}
		engine.AnalyzeBatch(context.Background(), nil, batch)
		time.Sleep(25 * time.Millisecond)
		repo.mu.Lock()
		defer repo.mu.Unlock()
		if len(repo.Anomalies) != 0 {
			t.Fatalf("expected dense traffic fan-out suppression, got %+v", repo.Anomalies)
		}
	})

	t.Run("device baseline raises destination threshold", func(t *testing.T) {
		tempDir := t.TempDir()
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		baselineRepo, err := storage.NewSQLiteRepository(tempDir, logger)
		if err != nil {
			t.Fatal(err)
		}
		defer baselineRepo.Close()

		const sourceIP = "192.168.1.73"
		if err := baselineRepo.UpsertDevice(context.Background(), sourceIP, "busy-resolver", time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := baselineRepo.SaveBaseline(context.Background(), &storage.DeviceBaseline{
			IP: sourceIP, MeanPeers: 40, StdDevPeers: 5,
		}); err != nil {
			t.Fatal(err)
		}
		baseEngine := baseline.NewBaselineEngine(baselineRepo, logger)
		if err := baseEngine.LoadBaselines(context.Background()); err != nil {
			t.Fatal(err)
		}
		anomalyRepo := &MockDeviceRepository{}
		engine := NewAnomalyEngine(anomalyRepo, logger, baseEngine, []string{"192.168.1.0/24"})

		buildBatch := func(count int) []flow.FlowEvent {
			batch := make([]flow.FlowEvent, count)
			for i := range batch {
				batch[i] = flow.FlowEvent{
					SrcIP: sourceIP, DstIP: fmt.Sprintf("198.18.%d.%d", i/256, i%256),
					DstPort: 443, Protocol: 6, Packets: 1,
				}
			}
			return batch
		}

		engine.AnalyzeBatch(context.Background(), nil, buildBatch(40))
		time.Sleep(25 * time.Millisecond)
		anomalyRepo.mu.Lock()
		if len(anomalyRepo.Anomalies) != 0 {
			t.Fatalf("expected learned baseline to suppress ordinary 40-peer fan-out, got %+v", anomalyRepo.Anomalies)
		}
		anomalyRepo.mu.Unlock()

		engine.AnalyzeBatch(context.Background(), nil, buildBatch(55))
		anomalies := waitForAnomalies(t, anomalyRepo, 1)
		if anomalies[0].Type != "DESTINATION_FANOUT" ||
			!strings.Contains(anomalies[0].Description, "confidence: high") ||
			!strings.Contains(anomalies[0].Description, "threshold 55") {
			t.Fatalf("unexpected baseline-aware fan-out alert: %+v", anomalies[0])
		}
	})

	t.Run("ports spread across destinations", func(t *testing.T) {
		engine, repo := newFanoutTestEngine(t)
		batch := make([]flow.FlowEvent, portFanoutMin)
		for i := range batch {
			batch[i] = flow.FlowEvent{
				SrcIP: "192.168.1.72", DstIP: fmt.Sprintf("192.0.2.%d", i+1),
				DstPort: 2000 + i, Protocol: 6, Packets: 1,
			}
		}
		engine.AnalyzeBatch(context.Background(), nil, batch)
		time.Sleep(25 * time.Millisecond)
		repo.mu.Lock()
		defer repo.mu.Unlock()
		if len(repo.Anomalies) != 0 {
			t.Fatalf("expected no vertical port alert across distinct targets, got %+v", repo.Anomalies)
		}
	})
}

func TestAnomalyEngineFanoutCardinalityIsBounded(t *testing.T) {
	engine, _ := newFanoutTestEngine(t)
	batch := make([]flow.FlowEvent, maxFanoutCardinality+500)
	for i := range batch {
		batch[i] = flow.FlowEvent{
			SrcIP:   "192.168.1.80",
			DstIP:   fmt.Sprintf("100.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256),
			DstPort: 1000 + (i % 5000), Protocol: 6, Packets: 1,
		}
	}
	metrics := engine.aggregateDeviceMetrics(batch)["192.168.1.80"]
	if len(metrics.dstIPs) != maxFanoutCardinality || !metrics.dstIPsTruncated {
		t.Fatalf("destination cardinality not bounded: count=%d truncated=%t", len(metrics.dstIPs), metrics.dstIPsTruncated)
	}
	if len(metrics.portsByDestination) > maxFanoutCardinality || len(metrics.dstPorts) > maxFanoutCardinality {
		t.Fatalf("port cardinality not bounded: destinations=%d ports=%d", len(metrics.portsByDestination), len(metrics.dstPorts))
	}
}

func TestAnomalyEngineFanoutHonorsAlertTypePolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := storage.NewSQLiteRepository(t.TempDir(), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	if err := repo.SavePolicy(context.Background(), &storage.Policy{
		Name: "Silence authorized port scans", Scope: "alert_type",
		Target: "PORT_FANOUT", Suppressed: true,
	}); err != nil {
		t.Fatal(err)
	}

	engine := NewAnomalyEngine(
		repo,
		logger,
		baseline.NewBaselineEngine(repo, logger),
		[]string{"192.168.1.0/24"},
	)
	batch := make([]flow.FlowEvent, portFanoutMin)
	for i := range batch {
		batch[i] = flow.FlowEvent{
			SrcIP: "192.168.1.90", DstIP: "203.0.113.90",
			DstPort: 3000 + i, Protocol: 6, Packets: 1,
		}
	}
	engine.AnalyzeBatch(context.Background(), nil, batch)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		anomalies, err := repo.ListAnomalies(context.Background(), 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(anomalies) == 1 {
			if anomalies[0].Type != "PORT_FANOUT" || anomalies[0].Status != "silenced" {
				t.Fatalf("expected silenced PORT_FANOUT anomaly, got %+v", anomalies[0])
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for policy-evaluated fan-out anomaly")
}

func analyzeBeaconSamples(engine *AnomalyEngine, source, destination string, port int, start time.Time, offsets []time.Duration, packets uint64) {
	for _, offset := range offsets {
		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{{
			Timestamp: start.Add(offset), SrcIP: source, DstIP: destination,
			DstPort: port, Protocol: 6, Bytes: 512, Packets: packets,
		}})
	}
}

func TestAnomalyEngineBeaconingWithJitter(t *testing.T) {
	engine, repo := newFanoutTestEngine(t)
	start := time.Date(2026, 7, 9, 10, 0, 0, 0, time.UTC)
	offsets := []time.Duration{
		0, 61 * time.Second, 119 * time.Second,
		181 * time.Second, 240 * time.Second, 301 * time.Second,
	}
	analyzeBeaconSamples(engine, "192.168.1.100", "203.0.113.100", 443, start, offsets, 1)

	anomalies := waitForAnomalies(t, repo, 1)
	if anomalies[0].Type != "BEACONING" || anomalies[0].Severity != "high" {
		t.Fatalf("unexpected beaconing anomaly: %+v", anomalies[0])
	}
	for _, field := range []string{
		"what happened:", "why unusual:", "baseline used:", "current value:",
		"expected value:", "confidence:", "recommended next check:",
	} {
		if !strings.Contains(anomalies[0].Description, field) {
			t.Errorf("beaconing explanation missing %q: %s", field, anomalies[0].Description)
		}
	}
	if !strings.Contains(anomalies[0].Description, "203.0.113.100:443") ||
		!strings.Contains(anomalies[0].Description, "6 observations") {
		t.Fatalf("beaconing explanation lacks deterministic evidence: %s", anomalies[0].Description)
	}

	analyzeBeaconSamples(engine, "192.168.1.100", "203.0.113.100", 443, start, []time.Duration{360 * time.Second}, 1)
	time.Sleep(25 * time.Millisecond)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.Anomalies) != 1 {
		t.Fatalf("expected beaconing deduplication, got %d alerts", len(repo.Anomalies))
	}
}

func TestAnomalyEngineBeaconingFalsePositiveControls(t *testing.T) {
	tests := []struct {
		name    string
		offsets []time.Duration
		packets uint64
		dstIP   string
	}{
		{
			name: "too few observations",
			offsets: []time.Duration{
				0, time.Minute, 2 * time.Minute, 3 * time.Minute, 4 * time.Minute,
			},
			packets: 1, dstIP: "203.0.113.110",
		},
		{
			name: "irregular intervals",
			offsets: []time.Duration{
				0, time.Minute, 3 * time.Minute, 4 * time.Minute, 7 * time.Minute, 8 * time.Minute,
			},
			packets: 1, dstIP: "203.0.113.111",
		},
		{
			name: "high volume communication",
			offsets: []time.Duration{
				0, time.Minute, 2 * time.Minute, 3 * time.Minute, 4 * time.Minute, 5 * time.Minute,
			},
			packets: beaconMaxPackets + 1, dstIP: "203.0.113.112",
		},
		{
			name: "internal scheduled service",
			offsets: []time.Duration{
				0, time.Minute, 2 * time.Minute, 3 * time.Minute, 4 * time.Minute, 5 * time.Minute,
			},
			packets: 1, dstIP: "192.168.1.200",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine, repo := newFanoutTestEngine(t)
			analyzeBeaconSamples(
				engine, "192.168.1.110", test.dstIP, 8443,
				time.Date(2026, 7, 9, 11, 0, 0, 0, time.UTC),
				test.offsets, test.packets,
			)
			time.Sleep(25 * time.Millisecond)
			repo.mu.Lock()
			defer repo.mu.Unlock()
			if len(repo.Anomalies) != 0 {
				t.Fatalf("expected no beaconing alert, got %+v", repo.Anomalies)
			}
		})
	}
}

func TestAnomalyEngineBeaconingStateIsBoundedAndPruned(t *testing.T) {
	engine, _ := newFanoutTestEngine(t)
	start := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	batch := make([]flow.FlowEvent, beaconMaxSeries+100)
	for i := range batch {
		batch[i] = flow.FlowEvent{
			Timestamp: start, SrcIP: "192.168.1.120",
			DstIP:   fmt.Sprintf("100.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256),
			DstPort: 443, Protocol: 6, Bytes: 100, Packets: 1,
		}
	}
	engine.AnalyzeBatch(context.Background(), nil, batch)
	engine.beaconMu.Lock()
	if len(engine.beacons) != beaconMaxSeries {
		t.Fatalf("beacon series exceeded bound: %d", len(engine.beacons))
	}
	engine.beaconMu.Unlock()

	// Advancing the watermark beyond retention removes all old series before
	// admitting the new observation.
	engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{{
		Timestamp: start.Add(beaconStateRetention + time.Minute),
		SrcIP:     "192.168.1.120", DstIP: "203.0.113.200",
		DstPort: 443, Protocol: 6, Bytes: 100, Packets: 1,
	}})
	engine.beaconMu.Lock()
	defer engine.beaconMu.Unlock()
	if len(engine.beacons) != 1 {
		t.Fatalf("expected stale beacon series pruning, got %d series", len(engine.beacons))
	}
}

func TestAnomalyEngineBeaconingHonorsAlertTypePolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := storage.NewSQLiteRepository(t.TempDir(), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()

	if err := repo.SavePolicy(context.Background(), &storage.Policy{
		Name: "Silence approved heartbeat", Scope: "alert_type",
		Target: "BEACONING", Suppressed: true,
	}); err != nil {
		t.Fatal(err)
	}
	engine := NewAnomalyEngine(
		repo, logger, baseline.NewBaselineEngine(repo, logger),
		[]string{"192.168.1.0/24"},
	)
	analyzeBeaconSamples(
		engine, "192.168.1.130", "203.0.113.130", 443,
		time.Date(2026, 7, 9, 13, 0, 0, 0, time.UTC),
		[]time.Duration{0, time.Minute, 2 * time.Minute, 3 * time.Minute, 4 * time.Minute, 5 * time.Minute},
		1,
	)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		anomalies, err := repo.ListAnomalies(context.Background(), 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(anomalies) == 1 {
			if anomalies[0].Type != "BEACONING" || anomalies[0].Status != "silenced" {
				t.Fatalf("expected silenced BEACONING anomaly, got %+v", anomalies[0])
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for policy-evaluated beaconing anomaly")
}

func significantActivity(timestamp time.Time, sourceIP string) flow.FlowEvent {
	return flow.FlowEvent{
		Timestamp: timestamp, SrcIP: sourceIP, DstIP: "203.0.113.210",
		DstPort: 443, Protocol: 6, Bytes: nightMinBytes, Packets: 10,
	}
}

func trainDaytimeProfile(engine *AnomalyEngine, sourceIP string, location *time.Location, day time.Time) {
	for i := 0; i < nightMinDaytimeWindows; i++ {
		timestamp := time.Date(day.Year(), day.Month(), day.Day(), 10, i, 0, 0, location)
		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
			significantActivity(timestamp.UTC(), sourceIP),
		})
	}
}

func TestAnomalyEngineUnexpectedNighttimeTraffic(t *testing.T) {
	engine, repo := newFanoutTestEngine(t)
	location := time.FixedZone("CEST", 2*60*60)
	engine.location = location
	const sourceIP = "192.168.1.140"
	day := time.Date(2026, 7, 9, 0, 0, 0, 0, location)
	trainDaytimeProfile(engine, sourceIP, location, day)

	// 23:30 UTC is 01:30 CEST and proves evaluation uses the configured
	// process timezone instead of UTC.
	night := time.Date(2026, 7, 9, 23, 30, 0, 0, time.UTC)
	engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
		significantActivity(night, sourceIP),
	})

	anomalies := waitForAnomalies(t, repo, 1)
	if anomalies[0].Type != "NIGHTTIME_TRAFFIC" || anomalies[0].Severity != "medium" {
		t.Fatalf("unexpected nighttime anomaly: %+v", anomalies[0])
	}
	for _, field := range []string{
		"what happened:", "why unusual:", "baseline used:", "current value:",
		"expected value:", "confidence:", "recommended next check:",
	} {
		if !strings.Contains(anomalies[0].Description, field) {
			t.Errorf("nighttime explanation missing %q: %s", field, anomalies[0].Description)
		}
	}
	if !strings.Contains(anomalies[0].Description, "01:30 CEST") ||
		!strings.Contains(anomalies[0].Description, "12 distinct daytime windows") {
		t.Fatalf("nighttime explanation lacks timezone/profile evidence: %s", anomalies[0].Description)
	}

	engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
		significantActivity(night.Add(time.Minute), sourceIP),
	})
	time.Sleep(25 * time.Millisecond)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.Anomalies) != 1 {
		t.Fatalf("expected nighttime alert deduplication, got %d", len(repo.Anomalies))
	}
}

func TestAnomalyEngineNighttimeFalsePositiveControls(t *testing.T) {
	location := time.FixedZone("CEST", 2*60*60)
	day := time.Date(2026, 7, 9, 0, 0, 0, 0, location)

	t.Run("insufficient learned profile", func(t *testing.T) {
		engine, repo := newFanoutTestEngine(t)
		engine.location = location
		for i := 0; i < nightMinDaytimeWindows-1; i++ {
			timestamp := time.Date(2026, 7, 9, 10, i, 0, 0, location)
			engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
				significantActivity(timestamp.UTC(), "192.168.1.141"),
			})
		}
		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
			significantActivity(time.Date(2026, 7, 10, 2, 0, 0, 0, location).UTC(), "192.168.1.141"),
		})
		time.Sleep(25 * time.Millisecond)
		repo.mu.Lock()
		defer repo.mu.Unlock()
		if len(repo.Anomalies) != 0 {
			t.Fatalf("expected no nighttime alert before learning, got %+v", repo.Anomalies)
		}
	})

	t.Run("insignificant nighttime keepalive", func(t *testing.T) {
		engine, repo := newFanoutTestEngine(t)
		engine.location = location
		trainDaytimeProfile(engine, "192.168.1.142", location, day)
		event := significantActivity(time.Date(2026, 7, 10, 2, 0, 0, 0, location).UTC(), "192.168.1.142")
		event.Bytes = 1024
		event.Packets = 1
		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{event})
		time.Sleep(25 * time.Millisecond)
		repo.mu.Lock()
		defer repo.mu.Unlock()
		if len(repo.Anomalies) != 0 {
			t.Fatalf("expected no alert for insignificant keepalive, got %+v", repo.Anomalies)
		}
	})

	t.Run("learned nighttime schedule", func(t *testing.T) {
		engine, repo := newFanoutTestEngine(t)
		engine.location = location
		const sourceIP = "192.168.1.143"
		trainDaytimeProfile(engine, sourceIP, location, day)
		for i := 0; i < nightExpectedWindows; i++ {
			engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
				significantActivity(time.Date(2026, 7, 10, 2, i, 0, 0, location).UTC(), sourceIP),
			})
		}
		_ = waitForAnomalies(t, repo, 1)
		repo.mu.Lock()
		repo.Anomalies = nil
		repo.mu.Unlock()
		engine.mu.Lock()
		delete(engine.alertDeduplicator, sourceIP+"|NIGHTTIME_TRAFFIC")
		engine.mu.Unlock()

		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
			significantActivity(time.Date(2026, 7, 10, 2, nightExpectedWindows, 0, 0, location).UTC(), sourceIP),
		})
		time.Sleep(25 * time.Millisecond)
		repo.mu.Lock()
		defer repo.mu.Unlock()
		if len(repo.Anomalies) != 0 {
			t.Fatalf("expected learned nighttime schedule suppression, got %+v", repo.Anomalies)
		}
	})
}

func TestAnomalyEngineActivityProfilesAreBoundedAndPruned(t *testing.T) {
	engine, _ := newFanoutTestEngine(t)
	start := time.Date(2026, 7, 9, 10, 0, 0, 0, time.UTC)
	for i := 0; i < nightMaxDevices+100; i++ {
		engine.observeActivity(fmt.Sprintf("10.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256), start, true, false)
	}
	engine.activityMu.Lock()
	if len(engine.activityProfiles) != nightMaxDevices {
		t.Fatalf("activity profile state exceeded bound: %d", len(engine.activityProfiles))
	}
	engine.activityMu.Unlock()

	engine.observeActivity("192.168.1.250", start.Add(nightStateRetention+time.Minute), true, false)
	engine.activityMu.Lock()
	defer engine.activityMu.Unlock()
	if len(engine.activityProfiles) != 1 {
		t.Fatalf("expected stale activity profile pruning, got %d profiles", len(engine.activityProfiles))
	}
}

func TestAnomalyEngineNighttimeHonorsAlertTypePolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := storage.NewSQLiteRepository(t.TempDir(), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := repo.SavePolicy(context.Background(), &storage.Policy{
		Name: "Silence approved overnight jobs", Scope: "alert_type",
		Target: "NIGHTTIME_TRAFFIC", Suppressed: true,
	}); err != nil {
		t.Fatal(err)
	}

	location := time.FixedZone("CEST", 2*60*60)
	engine := NewAnomalyEngine(
		repo, logger, baseline.NewBaselineEngine(repo, logger),
		[]string{"192.168.1.0/24"},
	)
	engine.location = location
	const sourceIP = "192.168.1.150"
	trainDaytimeProfile(engine, sourceIP, location, time.Date(2026, 7, 9, 0, 0, 0, 0, location))
	engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
		significantActivity(time.Date(2026, 7, 10, 2, 0, 0, 0, location).UTC(), sourceIP),
	})

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		anomalies, err := repo.ListAnomalies(context.Background(), 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(anomalies) == 1 {
			if anomalies[0].Type != "NIGHTTIME_TRAFFIC" || anomalies[0].Status != "silenced" {
				t.Fatalf("expected silenced NIGHTTIME_TRAFFIC anomaly, got %+v", anomalies[0])
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for policy-evaluated nighttime anomaly")
}

func profileEvent(timestamp time.Time, sourceIP string, protocol, port int, destination string) flow.FlowEvent {
	return flow.FlowEvent{
		Timestamp: timestamp, SrcIP: sourceIP, DstIP: destination,
		DstPort: port, Protocol: protocol, Bytes: nightMinBytes, Packets: 10,
	}
}

func trainDeviceFeatureProfile(engine *AnomalyEngine, sourceIP string, start time.Time) {
	for i := 0; i < profileLearningWindows; i++ {
		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
			profileEvent(start.Add(time.Duration(i)*time.Minute), sourceIP, 6, 443, "203.0.113.220"),
		})
	}
}

func TestAnomalyEngineDeviceProfileChange(t *testing.T) {
	engine, repo := newFanoutTestEngine(t)
	const sourceIP = "192.168.1.160"
	start := time.Date(2026, 7, 9, 10, 0, 0, 0, time.UTC)
	trainDeviceFeatureProfile(engine, sourceIP, start)

	for i := 0; i < profileConfirmWindows; i++ {
		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
			profileEvent(
				start.Add(time.Duration(profileLearningWindows+i)*time.Minute),
				sourceIP, 17, 53, "198.51.100.220",
			),
		})
	}
	anomalies := waitForAnomalies(t, repo, 1)
	if anomalies[0].Type != "DEVICE_PROFILE_CHANGE" || anomalies[0].Severity != "high" {
		t.Fatalf("unexpected device profile anomaly: %+v", anomalies[0])
	}
	for _, field := range []string{
		"what happened:", "why unusual:", "baseline used:", "current value:",
		"expected value:", "confidence:", "recommended next check:",
	} {
		if !strings.Contains(anomalies[0].Description, field) {
			t.Errorf("profile explanation missing %q: %s", field, anomalies[0].Description)
		}
	}
	if !strings.Contains(anomalies[0].Description, "protocols=tcp services=web peers=1-4") ||
		!strings.Contains(anomalies[0].Description, "protocols=udp services=dns peers=1-4") {
		t.Fatalf("profile explanation lacks deterministic old/new signatures: %s", anomalies[0].Description)
	}

	// The profile adapts to the confirmed change. A rapid confirmed reversal
	// is still suppressed by the existing per-device/type deduplicator.
	for i := 0; i < profileConfirmWindows; i++ {
		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
			profileEvent(
				start.Add(time.Duration(profileLearningWindows+profileConfirmWindows+i)*time.Minute),
				sourceIP, 6, 443, "203.0.113.220",
			),
		})
	}
	time.Sleep(25 * time.Millisecond)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.Anomalies) != 1 {
		t.Fatalf("expected profile-change deduplication, got %d alerts", len(repo.Anomalies))
	}
}

func TestAnomalyEngineDeviceProfileFalsePositiveControls(t *testing.T) {
	start := time.Date(2026, 7, 9, 10, 0, 0, 0, time.UTC)

	t.Run("insufficient learning", func(t *testing.T) {
		engine, repo := newFanoutTestEngine(t)
		for i := 0; i < profileLearningWindows-1; i++ {
			engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
				profileEvent(start.Add(time.Duration(i)*time.Minute), "192.168.1.161", 6, 443, "203.0.113.221"),
			})
		}
		for i := 0; i < profileConfirmWindows; i++ {
			engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
				profileEvent(start.Add(time.Duration(20+i)*time.Minute), "192.168.1.161", 17, 53, "198.51.100.221"),
			})
		}
		time.Sleep(25 * time.Millisecond)
		repo.mu.Lock()
		defer repo.mu.Unlock()
		if len(repo.Anomalies) != 0 {
			t.Fatalf("expected no profile alert before stable learning, got %+v", repo.Anomalies)
		}
	})

	t.Run("unstable learning", func(t *testing.T) {
		engine, repo := newFanoutTestEngine(t)
		for i := 0; i < profileLearningWindows; i++ {
			protocol, port, destination := 6, 443, "203.0.113.222"
			if i%2 == 1 {
				protocol, port, destination = 17, 53, "198.51.100.222"
			}
			engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
				profileEvent(start.Add(time.Duration(i)*time.Minute), "192.168.1.162", protocol, port, destination),
			})
		}
		time.Sleep(25 * time.Millisecond)
		repo.mu.Lock()
		defer repo.mu.Unlock()
		if len(repo.Anomalies) != 0 {
			t.Fatalf("expected no profile alert from unstable learning, got %+v", repo.Anomalies)
		}
		engine.profileMu.Lock()
		defer engine.profileMu.Unlock()
		if engine.deviceProfiles["192.168.1.162"].baseline != "" {
			t.Fatal("unstable 6/6 learning split must not establish a baseline")
		}
	})

	t.Run("transient change", func(t *testing.T) {
		engine, repo := newFanoutTestEngine(t)
		const sourceIP = "192.168.1.163"
		trainDeviceFeatureProfile(engine, sourceIP, start)
		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
			profileEvent(start.Add(20*time.Minute), sourceIP, 17, 53, "198.51.100.223"),
		})
		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
			profileEvent(start.Add(21*time.Minute), sourceIP, 6, 443, "203.0.113.223"),
		})
		for i := 0; i < profileConfirmWindows-1; i++ {
			engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
				profileEvent(start.Add(time.Duration(22+i)*time.Minute), sourceIP, 17, 53, "198.51.100.223"),
			})
		}
		time.Sleep(25 * time.Millisecond)
		repo.mu.Lock()
		defer repo.mu.Unlock()
		if len(repo.Anomalies) != 0 {
			t.Fatalf("expected transient profile changes to be suppressed, got %+v", repo.Anomalies)
		}
	})
}

func TestDeviceProfileSignatureIsDeterministic(t *testing.T) {
	engine, _ := newFanoutTestEngine(t)
	timestamp := time.Date(2026, 7, 9, 10, 0, 0, 0, time.UTC)
	first := engine.aggregateDeviceMetrics([]flow.FlowEvent{
		profileEvent(timestamp, "192.168.1.164", 17, 53, "198.51.100.224"),
		profileEvent(timestamp, "192.168.1.164", 6, 443, "203.0.113.224"),
	})["192.168.1.164"]
	second := engine.aggregateDeviceMetrics([]flow.FlowEvent{
		profileEvent(timestamp, "192.168.1.164", 6, 443, "203.0.113.224"),
		profileEvent(timestamp, "192.168.1.164", 17, 53, "198.51.100.224"),
	})["192.168.1.164"]
	if deviceProfileSignature(first) != deviceProfileSignature(second) {
		t.Fatalf("profile signature depends on flow ordering: %q != %q", deviceProfileSignature(first), deviceProfileSignature(second))
	}
}

func TestAnomalyEngineDeviceProfilesAreBoundedAndPruned(t *testing.T) {
	engine, _ := newFanoutTestEngine(t)
	start := time.Date(2026, 7, 9, 10, 0, 0, 0, time.UTC)
	for i := 0; i < profileMaxDevices+100; i++ {
		engine.observeDeviceProfile(
			fmt.Sprintf("10.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256),
			"protocols=tcp services=web peers=1-4", start,
		)
	}
	engine.profileMu.Lock()
	if len(engine.deviceProfiles) != profileMaxDevices {
		t.Fatalf("device profile state exceeded bound: %d", len(engine.deviceProfiles))
	}
	engine.profileMu.Unlock()

	engine.observeDeviceProfile(
		"192.168.1.250", "protocols=tcp services=web peers=1-4",
		start.Add(profileStateRetention+time.Minute),
	)
	engine.profileMu.Lock()
	defer engine.profileMu.Unlock()
	if len(engine.deviceProfiles) != 1 {
		t.Fatalf("expected stale device profile pruning, got %d profiles", len(engine.deviceProfiles))
	}
}

func TestAnomalyEngineDeviceProfileHonorsAlertTypePolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := storage.NewSQLiteRepository(t.TempDir(), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := repo.SavePolicy(context.Background(), &storage.Policy{
		Name: "Silence approved profile migration", Scope: "alert_type",
		Target: "DEVICE_PROFILE_CHANGE", Suppressed: true,
	}); err != nil {
		t.Fatal(err)
	}

	engine := NewAnomalyEngine(
		repo, logger, baseline.NewBaselineEngine(repo, logger),
		[]string{"192.168.1.0/24"},
	)
	const sourceIP = "192.168.1.170"
	start := time.Date(2026, 7, 9, 10, 0, 0, 0, time.UTC)
	trainDeviceFeatureProfile(engine, sourceIP, start)
	for i := 0; i < profileConfirmWindows; i++ {
		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
			profileEvent(start.Add(time.Duration(20+i)*time.Minute), sourceIP, 17, 53, "198.51.100.230"),
		})
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		anomalies, err := repo.ListAnomalies(context.Background(), 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(anomalies) == 1 {
			if anomalies[0].Type != "DEVICE_PROFILE_CHANGE" || anomalies[0].Status != "silenced" {
				t.Fatalf("expected silenced DEVICE_PROFILE_CHANGE anomaly, got %+v", anomalies[0])
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for policy-evaluated device profile anomaly")
}

func internalPeerEvent(timestamp time.Time, sourceIP, destinationIP string) flow.FlowEvent {
	return flow.FlowEvent{
		Timestamp: timestamp, SrcIP: sourceIP, DstIP: destinationIP,
		DstPort: 443, Protocol: 6, Bytes: 2048, Packets: 4,
	}
}

func trainInternalPeerProfile(engine *AnomalyEngine, sourceIP string, start time.Time) {
	for i := 0; i < internalPeerLearningWindows; i++ {
		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
			internalPeerEvent(start.Add(time.Duration(i)*time.Minute), sourceIP, "192.168.1.10"),
		})
	}
}

func TestAnomalyEngineNewInternalCommunication(t *testing.T) {
	engine, repo := newFanoutTestEngine(t)
	const sourceIP = "192.168.1.180"
	const newPeer = "192.168.1.25"
	start := time.Date(2026, 7, 9, 10, 0, 0, 0, time.UTC)
	trainInternalPeerProfile(engine, sourceIP, start)

	for i := 0; i < internalPeerConfirmWindows; i++ {
		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
			internalPeerEvent(start.Add(time.Duration(internalPeerLearningWindows+i)*time.Minute), sourceIP, newPeer),
		})
	}

	anomalies := waitForAnomalies(t, repo, 1)
	if anomalies[0].Type != "NEW_INTERNAL_COMMUNICATION" ||
		anomalies[0].Severity != "medium" ||
		anomalies[0].DestinationIP != newPeer {
		t.Fatalf("unexpected new internal communication anomaly: %+v", anomalies[0])
	}
	for _, field := range []string{
		"what happened:", "why unusual:", "baseline used:", "current value:",
		"expected value:", "confidence:", "recommended next check:",
	} {
		if !strings.Contains(anomalies[0].Description, field) {
			t.Errorf("new internal communication explanation missing %q: %s", field, anomalies[0].Description)
		}
	}
	if !strings.Contains(anomalies[0].Description, newPeer) {
		t.Fatalf("new internal communication explanation lacks destination evidence: %s", anomalies[0].Description)
	}

	// The new peer is added to the learned set after alerting, and repeated
	// traffic is also protected by the normal per-device/type deduplicator.
	engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
		internalPeerEvent(start.Add(30*time.Minute), sourceIP, newPeer),
	})
	time.Sleep(25 * time.Millisecond)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.Anomalies) != 1 {
		t.Fatalf("expected new internal communication deduplication/adaptation, got %d alerts", len(repo.Anomalies))
	}
}

func TestAnomalyEngineNewInternalCommunicationFalsePositiveControls(t *testing.T) {
	start := time.Date(2026, 7, 9, 10, 0, 0, 0, time.UTC)

	t.Run("no alert before learning completes", func(t *testing.T) {
		engine, repo := newFanoutTestEngine(t)
		for i := 0; i < internalPeerLearningWindows-1; i++ {
			engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
				internalPeerEvent(start.Add(time.Duration(i)*time.Minute), "192.168.1.181", "192.168.1.10"),
			})
		}
		for i := 0; i < internalPeerConfirmWindows; i++ {
			engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
				internalPeerEvent(start.Add(time.Duration(20+i)*time.Minute), "192.168.1.181", "192.168.1.50"),
			})
		}
		time.Sleep(25 * time.Millisecond)
		repo.mu.Lock()
		defer repo.mu.Unlock()
		if len(repo.Anomalies) != 0 {
			t.Fatalf("expected no internal-peer alert before learning, got %+v", repo.Anomalies)
		}
	})

	t.Run("transient new peer", func(t *testing.T) {
		engine, repo := newFanoutTestEngine(t)
		const sourceIP = "192.168.1.182"
		trainInternalPeerProfile(engine, sourceIP, start)
		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
			internalPeerEvent(start.Add(20*time.Minute), sourceIP, "192.168.1.60"),
		})
		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
			internalPeerEvent(start.Add(21*time.Minute), sourceIP, "192.168.1.10"),
		})
		time.Sleep(25 * time.Millisecond)
		repo.mu.Lock()
		defer repo.mu.Unlock()
		if len(repo.Anomalies) != 0 {
			t.Fatalf("expected transient internal peer to be suppressed, got %+v", repo.Anomalies)
		}
	})

	t.Run("external destinations are ignored", func(t *testing.T) {
		engine, repo := newFanoutTestEngine(t)
		const sourceIP = "192.168.1.183"
		trainInternalPeerProfile(engine, sourceIP, start)
		for i := 0; i < internalPeerConfirmWindows; i++ {
			engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{
				internalPeerEvent(start.Add(time.Duration(20+i)*time.Minute), sourceIP, "203.0.113.50"),
			})
		}
		time.Sleep(25 * time.Millisecond)
		repo.mu.Lock()
		defer repo.mu.Unlock()
		if len(repo.Anomalies) != 0 {
			t.Fatalf("expected external destination to be ignored by internal detector, got %+v", repo.Anomalies)
		}
	})
}

func TestAnomalyEngineInternalPeerProfilesAreBoundedAndPruned(t *testing.T) {
	engine, _ := newFanoutTestEngine(t)
	start := time.Date(2026, 7, 9, 10, 0, 0, 0, time.UTC)
	peers := map[string]bool{"192.168.1.10": true}
	for i := 0; i < internalPeerMaxDevices+100; i++ {
		engine.observeInternalPeer(
			fmt.Sprintf("10.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256),
			peers, start,
		)
	}
	engine.internalPeerMu.Lock()
	if len(engine.internalPeerProfiles) != internalPeerMaxDevices {
		t.Fatalf("internal peer state exceeded bound: %d", len(engine.internalPeerProfiles))
	}
	engine.internalPeerMu.Unlock()

	engine.observeInternalPeer(
		"192.168.1.250", peers,
		start.Add(internalPeerStateRetention+time.Minute),
	)
	engine.internalPeerMu.Lock()
	defer engine.internalPeerMu.Unlock()
	if len(engine.internalPeerProfiles) != 1 {
		t.Fatalf("expected stale internal peer pruning, got %d profiles", len(engine.internalPeerProfiles))
	}
}
