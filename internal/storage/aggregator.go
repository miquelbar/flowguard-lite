package storage

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/flowguard/flowguard/internal/flow"
)

// FlowAggregator rolls up normalized raw flow events into 1-minute time buckets in-memory.
type FlowAggregator struct {
	repo   FlowRepository
	logger *slog.Logger

	interval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	mu            sync.Mutex
	buffer        map[string]*flow.FlowEvent
	currentBucket time.Time
}

// NewFlowAggregator creates a new thread-safe FlowAggregator instance.
func NewFlowAggregator(repo FlowRepository, logger *slog.Logger, flushInterval time.Duration) *FlowAggregator {
	ctx, cancel := context.WithCancel(context.Background())
	return &FlowAggregator{
		repo:     repo,
		logger:   logger,
		interval: flushInterval,
		buffer:   make(map[string]*flow.FlowEvent),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start launches the automated background flush worker loop.
func (a *FlowAggregator) Start() {
	a.logger.Info("Starting Flow Aggregator flush loop...", slog.Duration("interval", a.interval))
	a.wg.Add(1)
	go a.flushLoop()
}

// Shutdown stops the background loop and flushes all remaining in-memory aggregates.
func (a *FlowAggregator) Shutdown() {
	a.logger.Info("Shutting down Flow Aggregator...")
	a.cancel()
	a.wg.Wait()

	// Perform final flush to verify no aggregates are lost
	a.Flush()
	a.logger.Info("Flow Aggregator shut down successfully.")
}

// Process implements the flow.FlowProcessor interface to aggregate incoming raw events.
func (a *FlowAggregator) Process(event *flow.FlowEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Truncate timestamp to minute level for 1m aggregation buckets
	bucketTime := event.Timestamp.Truncate(time.Minute)

	if a.currentBucket.IsZero() {
		a.currentBucket = bucketTime
	} else if bucketTime.After(a.currentBucket) {
		// If we receive a packet belonging to a newer minute bucket, proactively flush the old one
		// to preserve memory bounds.
		a.logger.Debug("Newer minute bucket detected, triggering intermediate flush",
			slog.Time("old_bucket", a.currentBucket),
			slog.Time("new_bucket", bucketTime))
		go a.flushBatch(a.currentBucket, a.drainBuffer())
		a.currentBucket = bucketTime
	}

	// Create unique compound key for aggregation grouping
	key := fmt.Sprintf("%s|%s|%d|%d", event.SrcIP, event.DstIP, event.DstPort, event.Protocol)

	if existing, ok := a.buffer[key]; ok {
		existing.Bytes += event.Bytes
		existing.Packets += event.Packets
		// TCP Flags bitwise OR to capture all flag occurrences (SYN, ACK, RST) in the minute
		existing.TCPFlags |= event.TCPFlags
	} else {
		// Clone event to avoid holding reference to collector buffer
		a.buffer[key] = &flow.FlowEvent{
			Timestamp:  bucketTime,
			SrcIP:      event.SrcIP,
			DstIP:      event.DstIP,
			SrcPort:    event.SrcPort,
			DstPort:    event.DstPort,
			Protocol:   event.Protocol,
			Bytes:      event.Bytes,
			Packets:    event.Packets,
			ExporterIP: event.ExporterIP,
			TCPFlags:   event.TCPFlags,
		}
	}
}

// Flush manually triggers in-memory buffer clearing and transactional writes to SQLite.
func (a *FlowAggregator) Flush() {
	a.mu.Lock()
	bucket := a.currentBucket
	batch := a.drainBuffer()
	a.mu.Unlock()

	if len(batch) > 0 {
		a.flushBatch(bucket, batch)
	}
}

// Helper: Drain and return buffer content, resetting map.
func (a *FlowAggregator) drainBuffer() []flow.FlowEvent {
	batch := make([]flow.FlowEvent, 0, len(a.buffer))
	for _, item := range a.buffer {
		batch = append(batch, *item)
	}
	a.buffer = make(map[string]*flow.FlowEvent)
	return batch
}

// Helper: Execute transaction batch write to SQLite.
func (a *FlowAggregator) flushBatch(bucket time.Time, batch []flow.FlowEvent) {
	if len(batch) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	a.logger.Debug("Flushing aggregated flows to storage",
		slog.Time("bucket", bucket),
		slog.Int("records", len(batch)))

	if err := a.repo.SaveAggregates(ctx, bucket, batch); err != nil {
		a.logger.Error("Failed to save aggregated flows to storage",
			slog.Time("bucket", bucket),
			slog.String("error", err.Error()))
	}
}

// Background loop running at regular interval.
func (a *FlowAggregator) flushLoop() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.Flush()
		}
	}
}
