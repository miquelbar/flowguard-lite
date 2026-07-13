package benchmark

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/collector"
	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

type mockProcessor struct {
	mu     sync.Mutex
	Events []*flow.FlowEvent
}

func (m *mockProcessor) Process(event *flow.FlowEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events = append(m.Events, event)
}

func (m *mockProcessor) GetEvents() []*flow.FlowEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]*flow.FlowEvent, len(m.Events))
	copy(res, m.Events)
	return res
}

// Mock repository for syslog and aggregation testing
type mockRepository struct {
	mu          sync.Mutex
	unifiEvents []storage.UniFiEvent
}

func (m *mockRepository) SaveAggregates(ctx context.Context, ts time.Time, aggregates []flow.FlowEvent) error {
	return nil
}

func (m *mockRepository) SaveUniFiEvent(ctx context.Context, e *storage.UniFiEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unifiEvents = append(m.unifiEvents, *e)
	return nil
}

func (m *mockRepository) ListUniFiEvents(ctx context.Context, limit int) ([]storage.UniFiEvent, error) {
	return nil, nil
}

func (m *mockRepository) GetUniFiEventsForIP(ctx context.Context, clientIP string, limit int) ([]storage.UniFiEvent, error) {
	return nil, nil
}

func (m *mockRepository) UpsertDevice(ctx context.Context, ip string, hostname string, lastSeen time.Time) error {
	return nil
}

func (m *mockRepository) SaveAnomaly(ctx context.Context, a *storage.Anomaly) error {
	return nil
}

func (m *mockRepository) Close() error {
	return nil
}

func TestFlowEventGenerator(t *testing.T) {
	gen1 := NewFlowEventGenerator(42)
	gen2 := NewFlowEventGenerator(42)
	
	now := time.Now()
	
	// Test determinism
	small1 := gen1.GenerateSmallOffice(10, now)
	small2 := gen2.GenerateSmallOffice(10, now)
	
	if len(small1) != 10 || len(small2) != 10 {
		t.Fatalf("expected 10 events, got %d and %d", len(small1), len(small2))
	}
	
	for i := 0; i < 10; i++ {
		if small1[i].SrcIP != small2[i].SrcIP || small1[i].DstIP != small2[i].DstIP ||
			small1[i].SrcPort != small2[i].SrcPort || small1[i].DstPort != small2[i].DstPort {
			t.Errorf("determinism failed at index %d: %+v vs %+v", i, small1[i], small2[i])
		}
	}
	
	// Test different profiles
	busy := gen1.GenerateBusyOffice(20, now)
	if len(busy) != 20 {
		t.Errorf("expected 20 busy office events, got %d", len(busy))
	}
	
	lab := gen1.GenerateHighFlowLab(30, now)
	if len(lab) != 30 {
		t.Errorf("expected 30 high flow lab events, got %d", len(lab))
	}
	
	ddos := gen1.GenerateDDoSAttack(15, now, "192.168.1.100")
	if len(ddos) != 15 {
		t.Errorf("expected 15 DDoS events, got %d", len(ddos))
	}
	
	for _, e := range ddos {
		if e.DstIP != "192.168.1.100" {
			t.Errorf("expected target DstIP 192.168.1.100, got %s", e.DstIP)
		}
	}
}

type testRepoWrapper struct {
	storage.StorageRepository // embeds the interface to implement all other methods implicitly (panics if called, which is fine)
	*mockRepository
}

func (w *testRepoWrapper) SaveAggregates(ctx context.Context, ts time.Time, aggregates []flow.FlowEvent) error {
	return w.mockRepository.SaveAggregates(ctx, ts, aggregates)
}

func (w *testRepoWrapper) SaveUniFiEvent(ctx context.Context, e *storage.UniFiEvent) error {
	return w.mockRepository.SaveUniFiEvent(ctx, e)
}

func (w *testRepoWrapper) ListUniFiEvents(ctx context.Context, limit int) ([]storage.UniFiEvent, error) {
	return w.mockRepository.ListUniFiEvents(ctx, limit)
}

func (w *testRepoWrapper) GetUniFiEventsForIP(ctx context.Context, clientIP string, limit int) ([]storage.UniFiEvent, error) {
	return w.mockRepository.GetUniFiEventsForIP(ctx, clientIP, limit)
}

func (w *testRepoWrapper) UpsertDevice(ctx context.Context, ip string, hostname string, lastSeen time.Time) error {
	return w.mockRepository.UpsertDevice(ctx, ip, hostname, lastSeen)
}

func (w *testRepoWrapper) SaveAnomaly(ctx context.Context, a *storage.Anomaly) error {
	return w.mockRepository.SaveAnomaly(ctx, a)
}

func (w *testRepoWrapper) RegisterAnomalyCallback(cb func(a *storage.Anomaly)) {
	// Dummy
}

func (w *testRepoWrapper) Close() error {
	return w.mockRepository.Close()
}

func TestUDPGenerators_Integration(t *testing.T) {
	cfg := &config.Config{
		NetflowPort:           12075,
		SflowPort:             0,
		UniFiSyslogEnabled:   true,
		UniFiSyslogPort:       5534,
		UniFiSyslogAllowedIPs: []string{"127.0.0.1/32"},
		LogLevel:              "debug",
		Environment:           "test",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proc := &mockProcessor{}
	mockRepo := &mockRepository{}
	
	// Create the wrapper
	repoWrapper := &testRepoWrapper{
		mockRepository: mockRepo,
	}

	c := collector.NewFlowCollector(cfg, logger, proc, repoWrapper)
	if err := c.Start(); err != nil {
		t.Fatalf("failed to start collector: %v", err)
	}
	defer c.Shutdown()

	// 1. Send NetFlow v9 Packets
	err := SendNetFlowV9Packets("127.0.0.1:12075", 5, 42)
	if err != nil {
		t.Fatalf("failed to send NetFlow packets: %v", err)
	}

	// 2. Send Syslog Packets
	err = SendUniFiSyslogPackets("127.0.0.1:5534", 3, 42)
	if err != nil {
		t.Fatalf("failed to send Syslog packets: %v", err)
	}

	// Allow some time for processing
	time.Sleep(150 * time.Millisecond)

	stats := c.GetStats()
	if stats.PacketsReceived != 8 {
		t.Errorf("expected 8 packets received (5 netflow + 3 syslog), got %d", stats.PacketsReceived)
	}

	// NetFlow packets should decode successfully with 0 errors
	if stats.DecodeErrors != 0 {
		t.Errorf("expected 0 decode errors, got %d", stats.DecodeErrors)
	}

	// Verify mock processor received NetFlow events
	events := proc.GetEvents()
	if len(events) != 5 {
		t.Errorf("expected 5 normalized flow events processed, got %d", len(events))
	}

	for _, e := range events {
		if e.CollectorKind != flow.CollectorKindNetFlow {
			t.Errorf("expected CollectorKind netflow, got %s", e.CollectorKind)
		}
	}

	// Verify mock repo received Syslog events
	mockRepo.mu.Lock()
	syslogCount := len(mockRepo.unifiEvents)
	mockRepo.mu.Unlock()
	
	if syslogCount != 3 {
		t.Errorf("expected 3 syslog events saved to repo, got %d", syslogCount)
	}
}
