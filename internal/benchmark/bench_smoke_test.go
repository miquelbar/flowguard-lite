package benchmark

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/collector"
	"github.com/miquelbar/flowguard-lite/internal/storage"
	"github.com/netsampler/goflow2/decoders/netflow"
)

// TestPerformanceRegressionSmoke asserts that basic ingest and parsing paths meet minimum performance expectations.
// It acts as a fast, non-flaky smoke gate with high thresholds to avoid CI environment variance.
func TestPerformanceRegressionSmoke(t *testing.T) {
	// 1. FlowAggregator Process limit: 10,000 events processed in < 50ms
	t.Run("FlowAggregator_Throughput", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		mockRepo := &mockRepository{}
		repoWrapper := &testRepoWrapper{mockRepository: mockRepo}
		agg := storage.NewFlowAggregator(repoWrapper, logger, 1*time.Hour)
		agg.Start()
		defer agg.Shutdown()

		gen := NewFlowEventGenerator(42)
		now := time.Now()
		events := gen.GenerateBusyOffice(1000, now)

		start := time.Now()
		for i := 0; i < 10000; i++ {
			agg.Process(&events[i%len(events)])
		}
		duration := time.Since(start)
		if duration > 50*time.Millisecond {
			t.Errorf("FlowAggregator Process was too slow: 10,000 flows took %s (max: 50ms)", duration)
		}
	})

	// 2. NetFlow v9 Packet decoding limit: 5,000 packets decoded in < 100ms
	t.Run("NetFlow_Decoding", func(t *testing.T) {
		templates := netflow.CreateTemplateSystem()
		srcIP := net.ParseIP("192.168.1.50")
		dstIP := net.ParseIP("8.8.8.8")
		packetData := GenerateNetFlowV9Packet(srcIP, dstIP, 12345, 443, 6, 1024, 5)

		start := time.Now()
		for i := 0; i < 5000; i++ {
			buf := bytes.NewBuffer(packetData)
			_, err := netflow.DecodeMessage(buf, templates)
			if err != nil {
				t.Fatalf("failed to decode message: %v", err)
			}
		}
		duration := time.Since(start)
		if duration > 100*time.Millisecond {
			t.Errorf("NetFlow decoding was too slow: 5,000 packets took %s (max: 100ms)", duration)
		}
	})

	// 3. Syslog Parsing limit: 5,000 lines parsed in < 100ms
	t.Run("Syslog_Parsing", func(t *testing.T) {
		syslogMsg := []byte("<14>1 2026-07-12T19:00:00Z 192.168.1.1 unifi-security - - - IDS Alert: Trojan detected from 192.168.30.210")
		defaultTime := time.Now().UTC()

		start := time.Now()
		for i := 0; i < 5000; i++ {
			parsed, err := collector.ParseUniFiSyslog(syslogMsg, defaultTime)
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
			}
			category := collector.ExtractUniFiCategory(parsed.Message, parsed.Severity)
			clientIP := collector.ExtractIP(parsed.Message)
			if category != "Security Detections" || clientIP != "192.168.30.210" {
				t.Fatalf("incorrect parsed value: category=%s IP=%s", category, clientIP)
			}
		}
		duration := time.Since(start)
		if duration > 100*time.Millisecond {
			t.Errorf("Syslog parsing was too slow: 5,000 lines took %s (max: 100ms)", duration)
		}
	})
}
