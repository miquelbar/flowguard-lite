package anomaly

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/baseline"
	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/storage"
	sqlitestore "github.com/miquelbar/flowguard-lite/internal/storage/sqlite"
)

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
		baselineRepo, err := sqlitestore.NewRepository(tempDir, logger)
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
	repo, err := sqlitestore.NewRepository(t.TempDir(), logger)
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
