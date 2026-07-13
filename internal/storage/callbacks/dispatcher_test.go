package callbacks

import (
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/storage"
)

func TestAnomalyCallbackDispatcherShutdownWaitsForCallbacks(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dispatcher := NewDispatcher()
	block := make(chan struct{})
	started := make(chan struct{})

	dispatcher.Dispatch(logger, []func(a *storage.Anomaly){
		func(a *storage.Anomaly) {
			close(started)
			<-block
		},
	}, &storage.Anomaly{ID: 1, IP: "192.168.1.10"})

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for callback to start")
	}

	shutdownDone := make(chan struct{})
	go func() {
		dispatcher.Shutdown(logger)
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
		t.Fatal("shutdown returned before callback finished")
	case <-time.After(25 * time.Millisecond):
	}

	close(block)
	select {
	case <-shutdownDone:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for dispatcher shutdown")
	}
}

func TestAnomalyCallbackDispatcherDropsAfterShutdown(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dispatcher := NewDispatcher()
	dispatcher.Shutdown(logger)

	var calls int32
	dispatcher.Dispatch(logger, []func(a *storage.Anomaly){
		func(a *storage.Anomaly) {
			atomic.AddInt32(&calls, 1)
		},
	}, &storage.Anomaly{ID: 1, IP: "192.168.1.10"})

	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected closed dispatcher to drop callback, got %d calls", got)
	}
}
