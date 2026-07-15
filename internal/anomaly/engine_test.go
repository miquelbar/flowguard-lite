package anomaly

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/baseline"
	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/storage"
	duckdbstore "github.com/miquelbar/flowguard-lite/internal/storage/duckdb"
	sqlitestore "github.com/miquelbar/flowguard-lite/internal/storage/sqlite"
)

func TestAnomalyEngine_DeduplicationAndVolume(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "anomaly_engine_test")
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
	sqliteRepo, err := sqlitestore.NewRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}
	defer sqliteRepo.Close()

	ctx := context.Background()
	sourceIP := "192.168.1.101"
	knownDestination := "198.51.100.10"
	seedMatureNewDestinationHistory(t, ctx, sqliteRepo, sourceIP, knownDestination, 53, time.Now().UTC())

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

func TestAnomalyEngineNewDestinationAndPortUsesFlowRepositoryContract(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	duckRepo, err := duckdbstore.NewRepository(t.TempDir(), logger)
	if err != nil {
		t.Fatalf("failed to create DuckDB repository: %v", err)
	}
	defer duckRepo.Close()

	ctx := context.Background()
	sourceIP := "192.168.1.111"
	knownDestination := "198.51.100.20"
	seedMatureNewDestinationHistory(t, ctx, duckRepo, sourceIP, knownDestination, 53, time.Now().UTC())

	mockRepo := &MockDeviceRepository{}
	engine := NewAnomalyEngine(
		mockRepo,
		logger,
		baseline.NewBaselineEngine(duckRepo, logger),
		[]string{"192.168.1.0/24"},
	)

	engine.AnalyzeBatch(ctx, duckRepo, []flow.FlowEvent{{
		Timestamp: time.Now().UTC(), SrcIP: sourceIP, DstIP: "203.0.113.111",
		DstPort: 53, Protocol: 17, Bytes: 256, Packets: 1,
	}})
	anomalies := waitForAnomalies(t, mockRepo, 1)
	if anomalies[0].Type != "NEW_DESTINATION" || anomalies[0].DestinationIP != "203.0.113.111" {
		t.Fatalf("expected DuckDB-backed new destination anomaly, got %+v", anomalies[0])
	}

	engine.AnalyzeBatch(ctx, duckRepo, []flow.FlowEvent{{
		Timestamp: time.Now().UTC(), SrcIP: sourceIP, DstIP: knownDestination,
		DstPort: 8443, Protocol: 6, Bytes: 512, Packets: 2,
	}})
	anomalies = waitForAnomalies(t, mockRepo, 2)
	if anomalies[1].Type != "NEW_PORT" {
		t.Fatalf("expected DuckDB-backed new port anomaly, got %+v", anomalies[1])
	}
}

func TestAnomalyEngineNewDestinationIgnoresCurrentPersistedBatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sqliteRepo, err := sqlitestore.NewRepository(t.TempDir(), logger)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}
	defer sqliteRepo.Close()

	ctx := context.Background()
	sourceIP := "192.168.1.112"
	seedMatureNewDestinationHistory(t, ctx, sqliteRepo, sourceIP, "198.51.100.112", 53, time.Now().UTC())

	current := time.Now().UTC()
	currentEvent := flow.FlowEvent{
		Timestamp: current, SrcIP: sourceIP, DstIP: "203.0.113.112",
		DstPort: 443, Protocol: 6, Bytes: 256, Packets: 1,
	}
	if err := sqliteRepo.SaveAggregates(ctx, current, []flow.FlowEvent{currentEvent}); err != nil {
		t.Fatalf("failed to persist current aggregate before callback: %v", err)
	}

	mockRepo := &MockDeviceRepository{}
	engine := NewAnomalyEngine(
		mockRepo,
		logger,
		baseline.NewBaselineEngine(sqliteRepo, logger),
		[]string{"192.168.1.0/24"},
	)

	engine.AnalyzeBatch(ctx, sqliteRepo, []flow.FlowEvent{currentEvent})
	anomalies := waitForAnomalies(t, mockRepo, 2)
	for _, anomaly := range anomalies {
		if anomaly.Type == "NEW_DESTINATION" && anomaly.DestinationIP == currentEvent.DstIP {
			return
		}
	}
	t.Fatalf("expected current persisted batch to be excluded from destination history check, got %+v", anomalies)
}

func TestAnomalyEngineNewDestinationWaitsForMatureSourceHistory(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sqliteRepo, err := sqlitestore.NewRepository(t.TempDir(), logger)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}
	defer sqliteRepo.Close()

	ctx := context.Background()
	sourceIP := "192.168.1.113"
	historical := time.Now().Add(-time.Hour).UTC()
	if err := sqliteRepo.SaveAggregates(ctx, historical, []flow.FlowEvent{{
		Timestamp: historical, SrcIP: sourceIP, DstIP: "198.51.100.113",
		DstPort: 53, Protocol: 17, Bytes: 512, Packets: 2,
	}}); err != nil {
		t.Fatalf("failed to seed immature historical aggregate: %v", err)
	}

	mockRepo := &MockDeviceRepository{}
	engine := NewAnomalyEngine(
		mockRepo,
		logger,
		baseline.NewBaselineEngine(sqliteRepo, logger),
		[]string{"192.168.1.0/24"},
	)

	engine.AnalyzeBatch(ctx, sqliteRepo, []flow.FlowEvent{{
		Timestamp: time.Now().UTC(), SrcIP: sourceIP, DstIP: "203.0.113.113",
		DstPort: 8443, Protocol: 6, Bytes: 256, Packets: 1,
	}})
	time.Sleep(50 * time.Millisecond)

	mockRepo.mu.Lock()
	defer mockRepo.mu.Unlock()
	if len(mockRepo.Anomalies) != 0 {
		t.Fatalf("expected immature source history to suppress new destination/port alerts, got %+v", mockRepo.Anomalies)
	}
}

type aggregateSaver interface {
	SaveAggregates(context.Context, time.Time, []flow.FlowEvent) error
}

func seedMatureNewDestinationHistory(t *testing.T, ctx context.Context, repo aggregateSaver, sourceIP, destinationIP string, destinationPort int, now time.Time) {
	t.Helper()

	for i := 0; i < minNewDestinationHistoryBuckets; i++ {
		ts := now.Add(time.Duration(i-minNewDestinationHistoryBuckets-1) * time.Minute).UTC()
		if err := repo.SaveAggregates(ctx, ts, []flow.FlowEvent{{
			Timestamp: ts, SrcIP: sourceIP, DstIP: destinationIP,
			DstPort: destinationPort, Protocol: 17, Bytes: 512, Packets: 2,
		}}); err != nil {
			t.Fatalf("failed to seed mature historical aggregate %d: %v", i, err)
		}
	}
}

func TestAnomalyEnginePacketCountTrafficSpike(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sqliteRepo, err := sqlitestore.NewRepository(t.TempDir(), logger)
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
		DstPort: 443, Protocol: 6, Bytes: 1000, Packets: 3000,
	}})

	anomalies := waitForAnomalies(t, mockRepo, 1)
	if anomalies[0].Type != "TRAFFIC_SPIKE" || anomalies[0].Severity != "high" {
		t.Fatalf("unexpected packet-count traffic spike anomaly: %+v", anomalies[0])
	}
	if !strings.Contains(anomalies[0].Description, "packet count") {
		t.Fatalf("expected packet-count explanation, got: %s", anomalies[0].Description)
	}
}
