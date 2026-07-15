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

func analyzeBeaconSamples(engine *AnomalyEngine, source, destination string, port int, start time.Time, offsets []time.Duration, packets uint64) {
	for _, offset := range offsets {
		engine.AnalyzeBatch(context.Background(), nil, []flow.FlowEvent{{
			Timestamp: start.Add(offset), SrcIP: source, DstIP: destination,
			DstPort: port, Protocol: 6, Bytes: 512, Packets: packets,
		}})
	}
}

func beaconOffsets(interval time.Duration, count int) []time.Duration {
	offsets := make([]time.Duration, count)
	for i := range offsets {
		offsets[i] = time.Duration(i) * interval
	}
	return offsets
}

func TestAnomalyEngineBeaconingWithJitter(t *testing.T) {
	engine, repo := newFanoutTestEngine(t)
	start := time.Date(2026, 7, 9, 10, 0, 0, 0, time.UTC)
	offsets := []time.Duration{
		0, 121 * time.Second, 239 * time.Second, 361 * time.Second,
		480 * time.Second, 602 * time.Second, 720 * time.Second, 839 * time.Second,
		961 * time.Second, 1080 * time.Second, 1201 * time.Second, 1320 * time.Second,
	}
	analyzeBeaconSamples(engine, "192.168.1.100", "203.0.113.100", 443, start, offsets, 1)

	anomalies := waitForAnomalies(t, repo, 1)
	if anomalies[0].Type != "BEACONING" || anomalies[0].Severity != "medium" {
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
		!strings.Contains(anomalies[0].Description, "12 observations") {
		t.Fatalf("beaconing explanation lacks deterministic evidence: %s", anomalies[0].Description)
	}

	analyzeBeaconSamples(engine, "192.168.1.100", "203.0.113.100", 443, start, []time.Duration{1440 * time.Second}, 1)
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
			name:    "too few observations",
			offsets: beaconOffsets(2*time.Minute, beaconMinObservations-1),
			packets: 1, dstIP: "203.0.113.110",
		},
		{
			name: "irregular intervals",
			offsets: []time.Duration{
				0, 2 * time.Minute, 4 * time.Minute, 9 * time.Minute,
				11 * time.Minute, 13 * time.Minute, 15 * time.Minute, 18 * time.Minute,
				20 * time.Minute, 22 * time.Minute, 24 * time.Minute, 27 * time.Minute,
			},
			packets: 1, dstIP: "203.0.113.111",
		},
		{
			name:    "high volume communication",
			offsets: beaconOffsets(2*time.Minute, beaconMinObservations),
			packets: beaconMaxPackets + 1, dstIP: "203.0.113.112",
		},
		{
			name:    "internal scheduled service",
			offsets: beaconOffsets(2*time.Minute, beaconMinObservations),
			packets: 1, dstIP: "192.168.1.200",
		},
		{
			name:    "one minute cloud keepalive",
			offsets: beaconOffsets(time.Minute, beaconMinObservations),
			packets: 1, dstIP: "203.0.113.113",
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
	repo, err := sqlitestore.NewRepository(t.TempDir(), logger)
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
		beaconOffsets(2*time.Minute, beaconMinObservations),
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
