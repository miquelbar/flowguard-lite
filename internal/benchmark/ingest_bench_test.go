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

// BenchmarkFlowAggregator_Throughput measures the throughput of FlowAggregator.Process
// using Small Office (25 devices) and Busy Office (100 devices) cardinality profiles.
func BenchmarkFlowAggregator_Throughput(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &mockRepository{}
	repoWrapper := &testRepoWrapper{mockRepository: mockRepo}

	// 1. Small Office Profile
	b.Run("SmallOffice_25Devices", func(b *testing.B) {
		agg := storage.NewFlowAggregator(repoWrapper, logger, 1*time.Hour)
		agg.Start()
		defer agg.Shutdown()

		gen := NewFlowEventGenerator(42)
		now := time.Now()
		// Pre-generate a batch of events to avoid generator overhead in the loop
		events := gen.GenerateSmallOffice(10000, now)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			agg.Process(&events[i%len(events)])
		}
	})

	// 2. Busy Office Profile
	b.Run("BusyOffice_100Devices", func(b *testing.B) {
		agg := storage.NewFlowAggregator(repoWrapper, logger, 1*time.Hour)
		agg.Start()
		defer agg.Shutdown()

		gen := NewFlowEventGenerator(42)
		now := time.Now()
		events := gen.GenerateBusyOffice(10000, now)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			agg.Process(&events[i%len(events)])
		}
	})
}

// BenchmarkCollector_NetFlowDecode measures NetFlow v9 decoding speed.
func BenchmarkCollector_NetFlowDecode(b *testing.B) {
	templates := netflow.CreateTemplateSystem()
	srcIP := net.ParseIP("192.168.1.50")
	dstIP := net.ParseIP("8.8.8.8")

	// Create a pre-crafted NetFlow v9 packet
	packetData := GenerateNetFlowV9Packet(srcIP, dstIP, 12345, 443, 6, 1024, 5)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create a new buffer for each decode since it reads from it
		buf := bytes.NewBuffer(packetData)
		_, err := netflow.DecodeMessage(buf, templates)
		if err != nil {
			b.Fatalf("failed to decode message: %v", err)
		}
	}
}

// BenchmarkSyslog_Parsing measures UniFi syslog message parsing and classification speed.
func BenchmarkSyslog_Parsing(b *testing.B) {
	syslogMsg := []byte("<14>1 2026-07-12T19:00:00Z 192.168.1.1 unifi-security - - - IDS Alert: Trojan detected from 192.168.30.210")
	defaultTime := time.Now().UTC()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parsed, err := collector.ParseUniFiSyslog(syslogMsg, defaultTime)
		if err != nil {
			b.Fatalf("failed to parse: %v", err)
		}

		category := collector.ExtractUniFiCategory(parsed.Message, parsed.Severity)
		clientIP := collector.ExtractIP(parsed.Message)

		if category != "Security Detections" || clientIP != "192.168.30.210" {
			b.Fatalf("incorrect parsed value: category=%s IP=%s", category, clientIP)
		}
	}
}
