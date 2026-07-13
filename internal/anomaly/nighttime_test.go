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
	repo, err := sqlitestore.NewRepository(t.TempDir(), logger)
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
