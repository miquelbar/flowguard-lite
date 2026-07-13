package anomaly

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
)

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
