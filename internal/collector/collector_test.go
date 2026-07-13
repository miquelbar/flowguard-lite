package collector

import (
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/netsampler/goflow2/pb"
)

type MockProcessor struct {
	mu     sync.Mutex
	Events []*flow.FlowEvent
}

func (m *MockProcessor) Process(event *flow.FlowEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events = append(m.Events, event)
}

func (m *MockProcessor) GetEvents() []*flow.FlowEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]*flow.FlowEvent, len(m.Events))
	copy(res, m.Events)
	return res
}

func TestFlowCollector_StartStop(t *testing.T) {
	cfg := &config.Config{
		NetflowPort: 12055, // Use non-standard ports to avoid permission issues
		SflowPort:   16343,
		LogLevel:    "debug",
		Environment: "development",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proc := &MockProcessor{}

	c := NewFlowCollector(cfg, logger, proc, nil)

	if err := c.Start(); err != nil {
		t.Fatalf("failed to start collector: %v", err)
	}

	// Verify stats initialized to 0
	stats := c.GetStats()
	if stats.PacketsReceived != 0 {
		t.Errorf("expected 0 received packets, got %d", stats.PacketsReceived)
	}

	// Stop the collector
	c.Shutdown()
}

func TestFlowCollector_CanDisableFlowListeners(t *testing.T) {
	cfg := &config.Config{
		NetflowPort:           0,
		SflowPort:             0,
		UniFiSyslogPort:       5514,
		StorageDir:            "/tmp",
		LogLevel:              "info",
		Environment:           "test",
		StorageBackend:        config.StorageBackendSQLite,
		RetentionDays:         7,
		DDoSThresholdPPS:      1,
		DDoSThresholdBPS:      1,
		DDoSThresholdFPS:      1,
		SYNFloodThresholdPPS:  1,
		UDPFloodThresholdPPS:  1,
		ICMPFloodThresholdPPS: 1,
		LocalSubnets:          []string{"192.168.0.0/16"},
		WebhookFormat:         config.WebhookFormatGeneric,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewFlowCollector(cfg, logger, nil, nil)
	if err := c.Start(); err != nil {
		t.Fatalf("failed to start collector with disabled flow listeners: %v", err)
	}
	defer c.Shutdown()
	if c.nfConn != nil || c.sfConn != nil {
		t.Fatalf("expected no NetFlow/sFlow sockets when ports are 0")
	}
	stats := c.GetStats()
	if len(stats.Sources) != 5 {
		t.Fatalf("expected bounded source stats for 5 collector kinds, got %+v", stats.Sources)
	}
	for _, src := range stats.Sources {
		if (src.Kind == flow.CollectorKindNetFlow || src.Kind == flow.CollectorKindSFlow) && src.Enabled {
			t.Fatalf("expected disabled flow source for zero port, got %+v", src)
		}
	}
}

func TestFlowCollector_NormalizeFlowMessage(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewFlowCollector(cfg, logger, nil, nil)

	// Create a dummy FlowMessage
	msg := &flowpb.FlowMessage{
		SrcAddr:        []byte{192, 168, 1, 100},
		DstAddr:        []byte{8, 8, 8, 8},
		SrcPort:        51234,
		DstPort:        53,
		Proto:          17, // UDP
		Bytes:          1024,
		Packets:        2,
		TimeReceived:   uint64(time.Now().Unix()),
		TimeFlowStart:  uint64(time.Now().Unix() - 10),
		TcpFlags:       0,
		SamplerAddress: []byte{192, 168, 1, 1},
	}

	event := c.normalizeFlowMessage(msg, "192.168.1.1", "netflow")
	if event == nil {
		t.Fatal("expected normalized event, got nil")
	}

	if event.SrcIP != "192.168.1.100" {
		t.Errorf("expected SrcIP 192.168.1.100, got %s", event.SrcIP)
	}
	if event.DstIP != "8.8.8.8" {
		t.Errorf("expected DstIP 8.8.8.8, got %s", event.DstIP)
	}
	if event.SrcPort != 51234 {
		t.Errorf("expected SrcPort 51234, got %d", event.SrcPort)
	}
	if event.DstPort != 53 {
		t.Errorf("expected DstPort 53, got %d", event.DstPort)
	}
	if event.Protocol != 17 {
		t.Errorf("expected Protocol 17, got %d", event.Protocol)
	}
	if event.Bytes != 1024 {
		t.Errorf("expected Bytes 1024, got %d", event.Bytes)
	}
	if event.Packets != 2 {
		t.Errorf("expected Packets 2, got %d", event.Packets)
	}
	if event.ExporterIP != "192.168.1.1" {
		t.Errorf("expected ExporterIP 192.168.1.1, got %s", event.ExporterIP)
	}
	if event.CollectorKind != flow.CollectorKindNetFlow || event.CollectorID != "192.168.1.1" {
		t.Errorf("expected netflow collector identity, got kind=%s id=%s", event.CollectorKind, event.CollectorID)
	}
}

func TestFlowCollector_NormalizeIPv6FlowMessage(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewFlowCollector(cfg, logger, nil, nil)
	start := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

	msg := &flowpb.FlowMessage{
		SrcAddr:       net.ParseIP("2001:db8::10").To16(),
		DstAddr:       net.ParseIP("2001:db8::20").To16(),
		SrcPort:       12345,
		DstPort:       443,
		Proto:         6,
		Bytes:         4096,
		Packets:       8,
		TimeReceived:  uint64(start.Add(10 * time.Second).Unix()),
		TimeFlowStart: uint64(start.Unix()),
		TcpFlags:      0x12,
	}

	event := c.normalizeFlowMessage(msg, "2001:db8::1", "netflow")
	if event == nil {
		t.Fatal("expected normalized IPv6 event, got nil")
	}
	if event.SrcIP != "2001:db8::10" || event.DstIP != "2001:db8::20" {
		t.Fatalf("unexpected IPv6 normalization: %+v", event)
	}
	if !event.Timestamp.Equal(start) {
		t.Fatalf("expected flow start timestamp %s, got %s", start, event.Timestamp)
	}
	if event.Protocol != 6 || event.SrcPort != 12345 || event.DstPort != 443 ||
		event.Bytes != 4096 || event.Packets != 8 || event.TCPFlags != 0x12 {
		t.Fatalf("unexpected normalized IPv6 counters/ports: %+v", event)
	}
}

func TestFlowCollector_ExporterRegistry(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewFlowCollector(cfg, logger, nil, nil)

	before := time.Now()
	c.updateExporterStats("10.0.0.1")
	c.updateExporterStats("10.0.0.1")
	c.updateExporterStats("10.0.0.2")
	after := time.Now()

	exporters := c.GetExporters()
	if len(exporters) != 2 {
		t.Fatalf("expected 2 exporters, got %d", len(exporters))
	}

	var exp1, exp2 ExporterMetadata
	for _, exp := range exporters {
		if exp.IP == "10.0.0.1" {
			exp1 = exp
		} else if exp.IP == "10.0.0.2" {
			exp2 = exp
		}
	}

	if exp1.PacketCount != 2 {
		t.Errorf("expected exporter 10.0.0.1 packet count 2, got %d", exp1.PacketCount)
	}
	if exp1.LastSeen.Before(before) || exp1.LastSeen.After(after) {
		t.Errorf("expected exporter 10.0.0.1 last-seen within test window, got %s", exp1.LastSeen)
	}
	if exp2.PacketCount != 1 {
		t.Errorf("expected exporter 10.0.0.2 packet count 1, got %d", exp2.PacketCount)
	}
	if exp2.LastSeen.Before(before) || exp2.LastSeen.After(after) {
		t.Errorf("expected exporter 10.0.0.2 last-seen within test window, got %s", exp2.LastSeen)
	}
}

func TestFlowCollector_ListenReceive(t *testing.T) {
	cfg := &config.Config{
		NetflowPort: 12056,
		SflowPort:   16344,
		LogLevel:    "debug",
		Environment: "development",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proc := &MockProcessor{}

	c := NewFlowCollector(cfg, logger, proc, nil)
	if err := c.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer c.Shutdown()

	// Send a dummy UDP packet to the NetFlow port to trigger listen loop reception
	conn, err := net.Dial("udp", "127.0.0.1:12056")
	if err != nil {
		t.Fatalf("failed to dial collector: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("invalid netflow payload dummy content"))
	if err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}

	// Allow loop to catch up and process
	time.Sleep(100 * time.Millisecond)

	stats := c.GetStats()
	if stats.PacketsReceived != 1 {
		t.Errorf("expected PacketsReceived 1, got %d", stats.PacketsReceived)
	}

	// Since the packet payload was invalid, it must increment decode error count
	if stats.DecodeErrors != 1 {
		t.Errorf("expected DecodeErrors 1, got %d", stats.DecodeErrors)
	}
}

func TestFlowCollector_QueueOverflow(t *testing.T) {
	cfg := &config.Config{
		NetflowPort: 12057,
		SflowPort:   16345,
		LogLevel:    "debug",
		Environment: "development",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewFlowCollector(cfg, logger, nil, nil)

	// Close rawPacketsChan and replace it with a 1-capacity channel to simulate overflow
	c.rawPacketsChan = make(chan *rawPacket, 1)

	// Inject 3 items directly into the listenLoop flow
	c.nfConn = &net.UDPConn{} // Mock conn

	// Simulate listen receipt
	c.rawPacketsChan <- &rawPacket{} // fill queue

	// Staging overflow
	c.statsMu.Lock()
	c.receivedCount++
	c.statsMu.Unlock()

	select {
	case c.rawPacketsChan <- &rawPacket{}:
		t.Fatal("expected queue to be full and block/drop")
	default:
		// Queue full, drop packet
		c.statsMu.Lock()
		c.droppedCount++
		c.statsMu.Unlock()
	}

	stats := c.GetStats()
	if stats.PacketsDropped != 1 {
		t.Errorf("expected PacketsDropped to be 1, got %d", stats.PacketsDropped)
	}
}
