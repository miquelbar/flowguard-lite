package storage

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
)

const aggregatorFlushQueueSize = 16

type aggregatorFlushRequest struct {
	bucket time.Time
	batch  []flow.FlowEvent
	done   chan struct{}
}

// FlowAggregator rolls up normalized raw flow events into 1-minute time buckets in-memory.
type FlowAggregator struct {
	repo   FlowRepository
	logger *slog.Logger

	interval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	startOnce    sync.Once
	shutdownOnce sync.Once
	queueMu      sync.Mutex
	flushQueue   chan aggregatorFlushRequest
	flushWG      sync.WaitGroup
	queueClosed  bool

	mu            sync.Mutex
	buffer        map[string]*flow.FlowEvent
	currentBucket time.Time
	stopping      bool

	// Post-flush callbacks to execute anomaly matching
	onFlush []func(ctx context.Context, batch []flow.FlowEvent)
}

// NewFlowAggregator creates a new thread-safe FlowAggregator instance.
func NewFlowAggregator(repo FlowRepository, logger *slog.Logger, flushInterval time.Duration) *FlowAggregator {
	ctx, cancel := context.WithCancel(context.Background())
	aggregator := &FlowAggregator{
		repo:       repo,
		logger:     logger,
		interval:   flushInterval,
		buffer:     make(map[string]*flow.FlowEvent),
		ctx:        ctx,
		cancel:     cancel,
		flushQueue: make(chan aggregatorFlushRequest, aggregatorFlushQueueSize),
	}
	aggregator.flushWG.Add(1)
	go aggregator.flushWorker()
	return aggregator
}

// RegisterFlushCallback registers a callback to run after each successful batch flush.
func (a *FlowAggregator) RegisterFlushCallback(cb func(ctx context.Context, batch []flow.FlowEvent)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onFlush = append(a.onFlush, cb)
}

func (a *FlowAggregator) Start() {
	a.startOnce.Do(func() {
		a.wg.Add(1)
		go a.flushLoop()
	})
}

// Shutdown flushes final buffered data and halts background routines.
func (a *FlowAggregator) Shutdown() {
	a.shutdownOnce.Do(func() {
		a.cancel()
		a.wg.Wait()

		bucket, batch := a.drainForShutdown()
		if len(batch) > 0 {
			a.enqueueFlush(bucket, batch, true)
		}

		a.queueMu.Lock()
		if !a.queueClosed {
			close(a.flushQueue)
			a.queueClosed = true
		}
		a.queueMu.Unlock()
		a.flushWG.Wait()
	})
}

// Process implements the flow.FlowProcessor interface to aggregate incoming traffic flows.
func (a *FlowAggregator) Process(event *flow.FlowEvent) {
	var oldBucket time.Time
	var oldBatch []flow.FlowEvent

	a.mu.Lock()
	if a.stopping {
		a.mu.Unlock()
		return
	}

	// Align event timestamp to 1-minute bucket boundary
	bucketTime := event.Timestamp.Truncate(time.Minute)

	// If bucket has advanced, trigger proactive flush of previous bucket
	if a.currentBucket.IsZero() {
		a.currentBucket = bucketTime
	} else if bucketTime.After(a.currentBucket) {
		oldBucket = a.currentBucket
		oldBatch = a.drainBuffer()
		a.currentBucket = bucketTime
	}

	collectorKind := flow.NormalizeCollectorKind(event.CollectorKind)
	collectorID := flow.NormalizeCollectorID(event.CollectorID, collectorKind, event.ExporterIP)

	// Aggregate flows matching collector source and unique traffic parameters.
	key := collectorKind + "|" + collectorID + "|" + event.SrcIP + "|" + event.DstIP + "|" +
		strconv.Itoa(event.DstPort) + "|" + strconv.Itoa(event.Protocol)

	if existing, ok := a.buffer[key]; ok {
		existing.Bytes += event.Bytes
		existing.Packets += event.Packets
		existing.TCPFlags |= event.TCPFlags
	} else {
		// Clone event to avoid holding reference to collector buffer
		a.buffer[key] = &flow.FlowEvent{
			Timestamp:     bucketTime,
			SrcIP:         event.SrcIP,
			DstIP:         event.DstIP,
			SrcPort:       event.SrcPort,
			DstPort:       event.DstPort,
			Protocol:      event.Protocol,
			Bytes:         event.Bytes,
			Packets:       event.Packets,
			CollectorKind: collectorKind,
			CollectorID:   collectorID,
			ExporterIP:    event.ExporterIP,
			TCPFlags:      event.TCPFlags,
		}
	}
	a.mu.Unlock()

	if len(oldBatch) > 0 {
		a.enqueueFlush(oldBucket, oldBatch, false)
	}
}

// Flush manually triggers in-memory buffer clearing and transactional writes to SQLite.
func (a *FlowAggregator) Flush() {
	a.mu.Lock()
	if a.stopping {
		a.mu.Unlock()
		return
	}
	bucket := a.currentBucket
	batch := a.drainBuffer()
	a.mu.Unlock()

	if len(batch) > 0 {
		a.enqueueFlush(bucket, batch, true)
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

func (a *FlowAggregator) drainForShutdown() (time.Time, []flow.FlowEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopping = true
	return a.currentBucket, a.drainBuffer()
}

func (a *FlowAggregator) enqueueFlush(bucket time.Time, batch []flow.FlowEvent, wait bool) bool {
	req := aggregatorFlushRequest{bucket: bucket, batch: batch}
	if wait {
		req.done = make(chan struct{})
	}

	a.queueMu.Lock()
	if a.queueClosed {
		a.queueMu.Unlock()
		return false
	}
	a.flushQueue <- req
	a.queueMu.Unlock()

	if req.done != nil {
		<-req.done
	}
	return true
}

func (a *FlowAggregator) flushWorker() {
	defer a.flushWG.Done()
	for req := range a.flushQueue {
		a.flushBatch(req.bucket, req.batch)
		if req.done != nil {
			close(req.done)
		}
	}
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
		return
	}

	// Trigger post-flush callbacks (e.g. anomaly detection checks)
	a.mu.Lock()
	callbacks := a.onFlush
	a.mu.Unlock()

	for _, cb := range callbacks {
		cb(ctx, batch)
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
