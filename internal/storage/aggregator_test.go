package storage

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
)

type MockFlowRepository struct {
	mu              sync.Mutex
	Batches         map[string][]flow.FlowEvent
	saveDelay       time.Duration
	activeSaves     int
	maxActiveSaves  int
	saveOrder       []string
	saveStartedHook func()
}

func NewMockFlowRepository() *MockFlowRepository {
	return &MockFlowRepository{
		Batches: make(map[string][]flow.FlowEvent),
	}
}

func (m *MockFlowRepository) SaveAggregates(ctx context.Context, ts time.Time, aggregates []flow.FlowEvent) error {
	m.mu.Lock()
	m.activeSaves++
	if m.activeSaves > m.maxActiveSaves {
		m.maxActiveSaves = m.activeSaves
	}
	if m.saveStartedHook != nil {
		m.saveStartedHook()
	}
	m.mu.Unlock()

	if m.saveDelay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.saveDelay):
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	key := ts.Format("2006-01-02 15:04")
	m.Batches[key] = append(m.Batches[key], aggregates...)
	m.saveOrder = append(m.saveOrder, key)
	m.activeSaves--
	return nil
}

func (m *MockFlowRepository) GetTopSources(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return nil, nil
}

func (m *MockFlowRepository) GetTopDestinations(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return nil, nil
}

func (m *MockFlowRepository) GetTopPorts(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return nil, nil
}

func (m *MockFlowRepository) GetTopProtocols(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return nil, nil
}

func (m *MockFlowRepository) GetTopDevicesByVolume(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return nil, nil
}

func (m *MockFlowRepository) GetTrafficTimeSeries(ctx context.Context, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error) {
	return nil, nil
}

func (m *MockFlowRepository) GetDeviceActivityHeatmap(ctx context.Context, start, end time.Time, limit int) ([]flow.DeviceHeatmapCell, error) {
	return nil, nil
}

func (m *MockFlowRepository) GetDeviceTrafficTimeSeries(ctx context.Context, ip string, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error) {
	return nil, nil
}

func (m *MockFlowRepository) GetDeviceTopPeers(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return nil, nil
}

func (m *MockFlowRepository) GetDeviceTopPorts(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return nil, nil
}

func TestFlowAggregator_Aggregation(t *testing.T) {
	repo := NewMockFlowRepository()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agg := NewFlowAggregator(repo, logger, 10*time.Second)
	defer agg.Shutdown()

	now := time.Date(2026, 7, 3, 21, 0, 10, 0, time.UTC)

	// Process multiple events in the same minute bucket
	agg.Process(&flow.FlowEvent{
		Timestamp: now,
		SrcIP:     "192.168.1.10",
		DstIP:     "8.8.8.8",
		DstPort:   53,
		Protocol:  17,
		Bytes:     100,
		Packets:   1,
	})

	agg.Process(&flow.FlowEvent{
		Timestamp: now.Add(5 * time.Second),
		SrcIP:     "192.168.1.10",
		DstIP:     "8.8.8.8",
		DstPort:   53,
		Protocol:  17,
		Bytes:     200,
		Packets:   2,
	})

	// Process event for a different IP
	agg.Process(&flow.FlowEvent{
		Timestamp: now.Add(10 * time.Second),
		SrcIP:     "192.168.1.20",
		DstIP:     "8.8.8.8",
		DstPort:   443,
		Protocol:  6,
		Bytes:     1000,
		Packets:   10,
	})

	// Manually flush
	agg.Flush()

	repo.mu.Lock()
	defer repo.mu.Unlock()

	bucketKey := "2026-07-03 21:00"
	batch, ok := repo.Batches[bucketKey]
	if !ok {
		t.Fatalf("expected batch for bucket %s not found", bucketKey)
	}

	if len(batch) != 2 {
		t.Fatalf("expected 2 aggregated events in batch, got %d", len(batch))
	}

	var ev1, ev2 flow.FlowEvent
	for _, ev := range batch {
		if ev.SrcIP == "192.168.1.10" {
			ev1 = ev
		} else if ev.SrcIP == "192.168.1.20" {
			ev2 = ev
		}
	}

	// Verify roll-ups accumulated correctly
	if ev1.Bytes != 300 || ev1.Packets != 3 {
		t.Errorf("expected 192.168.1.10 aggregate bytes 300 and packets 3, got bytes %d and packets %d", ev1.Bytes, ev1.Packets)
	}
	if ev2.Bytes != 1000 || ev2.Packets != 10 {
		t.Errorf("expected 192.168.1.20 aggregate bytes 1000 and packets 10, got bytes %d and packets %d", ev2.Bytes, ev2.Packets)
	}
}

func TestFlowAggregator_SeparatesCollectorSources(t *testing.T) {
	repo := NewMockFlowRepository()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agg := NewFlowAggregator(repo, logger, 10*time.Second)
	defer agg.Shutdown()

	now := time.Date(2026, 7, 3, 21, 0, 10, 0, time.UTC)
	base := flow.FlowEvent{
		Timestamp: now,
		SrcIP:     "192.168.1.10",
		DstIP:     "8.8.8.8",
		DstPort:   53,
		Protocol:  17,
		Bytes:     100,
		Packets:   1,
	}
	netflowEvent := base
	netflowEvent.CollectorKind = flow.CollectorKindNetFlow
	netflowEvent.CollectorID = "unifi-gateway"
	netflowEvent.ExporterIP = "192.168.1.1"
	pcapEvent := base
	pcapEvent.CollectorKind = flow.CollectorKindPCAP
	pcapEvent.CollectorID = "pcap:br0"
	pcapEvent.ExporterIP = "pcap:br0"

	agg.Process(&netflowEvent)
	agg.Process(&pcapEvent)
	agg.Flush()

	repo.mu.Lock()
	defer repo.mu.Unlock()

	batch := repo.Batches["2026-07-03 21:00"]
	if len(batch) != 2 {
		t.Fatalf("expected identical traffic from two collectors to remain separate, got %d records: %+v", len(batch), batch)
	}
	seen := map[string]bool{}
	for _, ev := range batch {
		seen[ev.CollectorKind+"|"+ev.CollectorID] = true
	}
	if !seen["netflow|unifi-gateway"] || !seen["pcap|pcap:br0"] {
		t.Fatalf("missing collector identities in aggregate batch: %+v", batch)
	}
}

func TestFlowAggregator_ProactiveFlush(t *testing.T) {
	repo := NewMockFlowRepository()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agg := NewFlowAggregator(repo, logger, 10*time.Second)
	defer agg.Shutdown()

	now := time.Date(2026, 7, 3, 21, 0, 10, 0, time.UTC)

	agg.Process(&flow.FlowEvent{
		Timestamp: now,
		SrcIP:     "192.168.1.10",
		DstIP:     "8.8.8.8",
		DstPort:   53,
		Protocol:  17,
		Bytes:     100,
		Packets:   1,
	})

	// Process event belonging to the next minute
	nextMin := now.Add(1 * time.Minute)
	agg.Process(&flow.FlowEvent{
		Timestamp: nextMin,
		SrcIP:     "192.168.1.10",
		DstIP:     "8.8.8.8",
		DstPort:   53,
		Protocol:  17,
		Bytes:     500,
		Packets:   5,
	})

	// Allow goroutine flush to complete
	time.Sleep(50 * time.Millisecond)

	repo.mu.Lock()
	defer repo.mu.Unlock()

	// Verify old bucket was automatically flushed
	bucketKey := "2026-07-03 21:00"
	batch, ok := repo.Batches[bucketKey]
	if !ok {
		t.Fatalf("expected proactive flush for bucket %s, but none occurred", bucketKey)
	}
	if len(batch) != 1 || batch[0].Bytes != 100 {
		t.Errorf("expected proactive batch containing 100 bytes, got %v", batch)
	}
}

func TestFlowAggregator_Shutdown(t *testing.T) {
	repo := NewMockFlowRepository()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agg := NewFlowAggregator(repo, logger, 10*time.Second)
	agg.Start()

	now := time.Date(2026, 7, 3, 21, 0, 10, 0, time.UTC)
	agg.Process(&flow.FlowEvent{
		Timestamp: now,
		SrcIP:     "192.168.1.10",
		DstIP:     "8.8.8.8",
		Bytes:     100,
	})

	// Shutdown should automatically trigger flush
	agg.Shutdown()

	repo.mu.Lock()
	defer repo.mu.Unlock()

	bucketKey := "2026-07-03 21:00"
	batch, ok := repo.Batches[bucketKey]
	if !ok {
		t.Fatalf("expected shutdown flush for bucket %s, but none occurred", bucketKey)
	}
	if len(batch) != 1 || batch[0].Bytes != 100 {
		t.Errorf("expected shutdown batch containing 100 bytes, got %v", batch)
	}
}

func TestFlowAggregator_Concurrency(t *testing.T) {
	repo := NewMockFlowRepository()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agg := NewFlowAggregator(repo, logger, 10*time.Second)
	defer agg.Shutdown()

	now := time.Date(2026, 7, 3, 21, 0, 10, 0, time.UTC)
	var wg sync.WaitGroup

	// Concurrently process events to verify data-race safety
	numGoroutines := 10
	numEvents := 100
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numEvents; j++ {
				agg.Process(&flow.FlowEvent{
					Timestamp: now,
					SrcIP:     "192.168.1.10",
					DstIP:     "8.8.8.8",
					DstPort:   80,
					Protocol:  6,
					Bytes:     10,
					Packets:   1,
				})
			}
		}()
	}

	wg.Wait()
	agg.Flush()

	repo.mu.Lock()
	defer repo.mu.Unlock()

	bucketKey := "2026-07-03 21:00"
	batch := repo.Batches[bucketKey]
	if len(batch) != 1 {
		t.Fatalf("expected 1 aggregated event, got %d", len(batch))
	}

	expectedBytes := uint64(numGoroutines * numEvents * 10)
	if batch[0].Bytes != expectedBytes {
		t.Errorf("expected aggregated bytes %d, got %d", expectedBytes, batch[0].Bytes)
	}
}

func TestFlowAggregator_ProactiveFlushesAreSerialized(t *testing.T) {
	repo := NewMockFlowRepository()
	repo.saveDelay = 10 * time.Millisecond
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agg := NewFlowAggregator(repo, logger, 10*time.Second)
	defer agg.Shutdown()

	now := time.Date(2026, 7, 3, 21, 0, 10, 0, time.UTC)
	for i := 0; i < 4; i++ {
		agg.Process(&flow.FlowEvent{
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			SrcIP:     "192.168.1.10",
			DstIP:     "8.8.8.8",
			DstPort:   53,
			Protocol:  17,
			Bytes:     100,
			Packets:   1,
		})
	}
	agg.Shutdown()

	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.maxActiveSaves != 1 {
		t.Fatalf("expected serialized saves with max concurrency 1, got %d", repo.maxActiveSaves)
	}
	expectedOrder := []string{
		"2026-07-03 21:00",
		"2026-07-03 21:01",
		"2026-07-03 21:02",
		"2026-07-03 21:03",
	}
	if len(repo.saveOrder) != len(expectedOrder) {
		t.Fatalf("expected %d saved buckets, got order %v", len(expectedOrder), repo.saveOrder)
	}
	for i, want := range expectedOrder {
		if repo.saveOrder[i] != want {
			t.Fatalf("expected save order %v, got %v", expectedOrder, repo.saveOrder)
		}
	}
}

func TestFlowAggregator_ShutdownWaitsForFlushCallbacks(t *testing.T) {
	repo := NewMockFlowRepository()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agg := NewFlowAggregator(repo, logger, 10*time.Second)

	callbackDone := make(chan struct{})
	agg.RegisterFlushCallback(func(ctx context.Context, batch []flow.FlowEvent) {
		time.Sleep(25 * time.Millisecond)
		close(callbackDone)
	})

	now := time.Date(2026, 7, 3, 21, 0, 10, 0, time.UTC)
	agg.Process(&flow.FlowEvent{
		Timestamp: now,
		SrcIP:     "192.168.1.10",
		DstIP:     "8.8.8.8",
		DstPort:   53,
		Protocol:  17,
		Bytes:     100,
		Packets:   1,
	})

	agg.Shutdown()

	select {
	case <-callbackDone:
	default:
		t.Fatal("expected shutdown to wait for flush callback completion")
	}
}
