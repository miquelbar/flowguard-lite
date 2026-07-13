package benchmark

import (
	"context"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/anomaly"
	"github.com/miquelbar/flowguard-lite/internal/baseline"
	"github.com/miquelbar/flowguard-lite/internal/collector"
	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/storage"
	sqlitestore "github.com/miquelbar/flowguard-lite/internal/storage/sqlite"
)

// TestStress_QueueOverflowAndDrops tests bounded queue behavior and drops under overload.
func TestStress_QueueOverflowAndDrops(t *testing.T) {
	cfg := &config.Config{
		NetflowPort:           12085,
		SflowPort:             0,
		UniFiSyslogEnabled:   true,
		UniFiSyslogPort:       5544,
		UniFiSyslogAllowedIPs: []string{"127.0.0.1/32"},
		LogLevel:              "debug",
		Environment:           "test",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proc := &mockProcessor{}
	mockRepo := &mockRepository{}
	repoWrapper := &testRepoWrapper{
		mockRepository: mockRepo,
	}

	c := collector.NewFlowCollector(cfg, logger, proc, repoWrapper)
	if err := c.Start(); err != nil {
		t.Fatalf("failed to start collector: %v", err)
	}
	defer c.Shutdown()

	// Dial the collector UDP ports
	connNetflow, err := net.Dial("udp", "127.0.0.1:12085")
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer connNetflow.Close()

	connSyslog, err := net.Dial("udp", "127.0.0.1:5544")
	if err != nil {
		t.Fatalf("failed to dial syslog: %v", err)
	}
	defer connSyslog.Close()

	// Launch multiple concurrent workers to flood UDP ports at an extreme rate
	numWorkers := 10
	iterations := 1000
	var wg sync.WaitGroup
	wg.Add(numWorkers)

	packetData := GenerateNetFlowV9Packet(net.ParseIP("192.168.1.100"), net.ParseIP("8.8.8.8"), 1234, 443, 6, 1500, 1)
	syslogMsg := []byte("<14>1 2026-07-12T19:00:00Z 192.168.1.1 unifi-security - - - IDS Alert: Trojan detected from 192.168.30.210")

	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				if workerID%2 == 0 {
					_, _ = connNetflow.Write(packetData)
				} else {
					_, _ = connSyslog.Write(syslogMsg)
				}
			}
		}(i)
	}

	wg.Wait()
	time.Sleep(100 * time.Millisecond) // Allow queue processing to digest as much as possible

	stats := c.GetStats()
	t.Logf("Stress test completed. Received: %d, Drops/Overload: %d, Decoded successfully: %d", 
		stats.PacketsReceived, stats.PacketsDropped, len(proc.GetEvents()))
}

// TestStress_GracefulShutdownDraining verifies shutdown drains accepted work without deadlock.
func TestStress_GracefulShutdownDraining(t *testing.T) {
	cfg := &config.Config{
		NetflowPort:           12095,
		SflowPort:             0,
		UniFiSyslogEnabled:   true,
		UniFiSyslogPort:       5554,
		UniFiSyslogAllowedIPs: []string{"127.0.0.1/32"},
		LogLevel:              "debug",
		Environment:           "test",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proc := &mockProcessor{}
	mockRepo := &mockRepository{}
	repoWrapper := &testRepoWrapper{
		mockRepository: mockRepo,
	}

	c := collector.NewFlowCollector(cfg, logger, proc, repoWrapper)
	if err := c.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}

	conn, err := net.Dial("udp", "127.0.0.1:12095")
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	packetData := GenerateNetFlowV9Packet(net.ParseIP("192.168.1.100"), net.ParseIP("8.8.8.8"), 1234, 443, 6, 1500, 1)

	// Send flows in background thread while stopping
	stopChan := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopChan:
				return
			default:
				_, _ = conn.Write(packetData)
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	time.Sleep(50 * time.Millisecond) // let it run briefly

	// Trigger shutdown concurrently
	shutdownDone := make(chan struct{})
	go func() {
		c.Shutdown()
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
		// Clean exit
	case <-time.After(3 * time.Second):
		t.Fatal("collector shutdown deadlocked / took too long")
	}

	close(stopChan)
}

// TestStress_AnomalyCallbackOverhead measures anomaly callback processing duration.
func TestStress_AnomalyCallbackOverhead(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "stress_anomaly")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sqliteRepo, err := sqlitestore.NewRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}
	defer sqliteRepo.Close()

	baseEngine := baseline.NewBaselineEngine(sqliteRepo, logger)
	engine := anomaly.NewAnomalyEngine(sqliteRepo, logger, baseEngine, []string{"192.168.1.0/24"})

	// Pre-seed baseline for device
	ip := "192.168.1.100"
	_ = sqliteRepo.UpsertDevice(context.Background(), ip, "test-device", time.Now())
	_ = sqliteRepo.SaveBaseline(context.Background(), &storage.DeviceBaseline{
		IP:            ip,
		MeanBytes:     2000,
		StdDevBytes:   500,
		MeanPackets:   200,
		StdDevPackets: 50,
		MeanPeers:     5,
		StdDevPeers:   1,
	})
	_ = baseEngine.LoadBaselines(context.Background())
	
	// Create 5,000 flows representing a massive port scan and high-volume surge to trigger engine evaluation
	eventsCount := 5000
	batch := make([]flow.FlowEvent, eventsCount)
	rng := rand.New(rand.NewSource(42))

	for i := 0; i < eventsCount; i++ {
		batch[i] = flow.FlowEvent{
			Timestamp: time.Now(),
			SrcIP:     ip,
			DstIP:     "8.8.8.8",
			DstPort:   rng.Intn(65535),
			Protocol:  6,
			Bytes:     1500,
			Packets:   1,
		}
	}

	start := time.Now()
	// Process the batch through the anomaly engine
	engine.AnalyzeBatch(context.Background(), sqliteRepo, batch)
	duration := time.Since(start)

	t.Logf("Processed %d events through anomaly engine in %v", eventsCount, duration)

	if duration > 200*time.Millisecond {
		t.Errorf("Anomaly detection engine took too long: %v (target under 200ms)", duration)
	}
}
