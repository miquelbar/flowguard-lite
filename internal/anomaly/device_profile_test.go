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
	repo, err := sqlitestore.NewRepository(t.TempDir(), logger)
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
