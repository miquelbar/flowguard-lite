package callbacks

import (
	"log/slog"
	"sync"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/storage"
)

const maxConcurrentAnomalyCallbacks = 16
const anomalyCallbackShutdownTimeout = 5 * time.Second

type Dispatcher struct {
	slots  chan struct{}
	mu     sync.Mutex
	wg     sync.WaitGroup
	closed bool
}

func NewDispatcher() Dispatcher {
	return Dispatcher{slots: make(chan struct{}, maxConcurrentAnomalyCallbacks)}
}

func (d *Dispatcher) Dispatch(logger *slog.Logger, callbacks []func(a *storage.Anomaly), anomaly *storage.Anomaly) {
	if len(callbacks) == 0 {
		return
	}

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		logger.Warn(
			"Dropped anomaly callbacks because dispatcher is closed",
			slog.Int64("anomaly_id", anomaly.ID),
			slog.String("ip", anomaly.IP),
			slog.Int("callback_count", len(callbacks)),
		)
		return
	}

	select {
	case d.slots <- struct{}{}:
		d.wg.Add(1)
		d.mu.Unlock()
	default:
		d.mu.Unlock()
		logger.Warn(
			"Dropped anomaly callbacks because dispatcher is saturated",
			slog.Int64("anomaly_id", anomaly.ID),
			slog.String("ip", anomaly.IP),
			slog.Int("callback_count", len(callbacks)),
		)
		return
	}

	go func() {
		defer func() {
			<-d.slots
			d.wg.Done()
		}()
		for _, cb := range callbacks {
			cb(anomaly)
		}
	}()
}

func (d *Dispatcher) Shutdown(logger *slog.Logger) {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(anomalyCallbackShutdownTimeout):
		logger.Warn("Timed out waiting for anomaly callbacks to finish", slog.Duration("timeout", anomalyCallbackShutdownTimeout))
	}
}
