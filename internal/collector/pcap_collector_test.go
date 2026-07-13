package collector

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miquelbar/flowguard-lite/internal/flow"
)

func TestPcapCollectorUsesFiniteReadTimeout(t *testing.T) {
	c := NewPcapCollector("eth0", "ip", false, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	var received time.Duration
	c.openHandle = func(_ string, _ int32, _ bool, timeout time.Duration) (packetCaptureHandle, error) {
		received = timeout
		return nil, errors.New("stop after argument capture")
	}

	if err := c.Start(); err == nil {
		t.Fatal("expected opener error")
	}
	if received != pcapReadTimeout || received <= 0 {
		t.Fatalf("expected finite read timeout %s, got %s", pcapReadTimeout, received)
	}
}

type recordingProcessor struct {
	mu     sync.Mutex
	events []flow.FlowEvent
}

func (p *recordingProcessor) Process(event *flow.FlowEvent) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, *event)
}

func TestCapturedFlowIPv4TCP(t *testing.T) {
	packet := serializePacket(t,
		&layers.Ethernet{SrcMAC: mac(t, "00:11:22:33:44:55"), DstMAC: mac(t, "66:77:88:99:aa:bb"), EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP("192.0.2.10"), DstIP: net.ParseIP("198.51.100.20")},
		&layers.TCP{SrcPort: 51000, DstPort: 443, SYN: true},
		gopacket.Payload([]byte("discarded payload")),
	)

	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	key, event, ok := capturedFlow(packet, now, "pcap:en0")
	if !ok {
		t.Fatal("expected TCP packet to produce a flow")
	}
	if key.srcIP != "192.0.2.10" || key.dstIP != "198.51.100.20" || key.srcPort != 51000 || key.dstPort != 443 || key.protocol != 6 {
		t.Fatalf("unexpected key: %+v", key)
	}
	if event.Packets != 1 || event.Bytes != uint64(len(packet.Data())) || event.TCPFlags != 0x02 {
		t.Fatalf("unexpected counters: %+v", event)
	}
	if event.ExporterIP != "pcap:en0" || !event.Timestamp.Equal(now) {
		t.Fatalf("unexpected metadata: %+v", event)
	}
	if event.CollectorKind != flow.CollectorKindPCAP || event.CollectorID != "pcap:en0" {
		t.Fatalf("unexpected collector identity: %+v", event)
	}
}

func TestCapturedFlowIPv6UDPAndUnsupportedPacket(t *testing.T) {
	packet := serializePacket(t,
		&layers.Ethernet{SrcMAC: mac(t, "00:11:22:33:44:55"), DstMAC: mac(t, "66:77:88:99:aa:bb"), EthernetType: layers.EthernetTypeIPv6},
		&layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")},
		&layers.UDP{SrcPort: 5353, DstPort: 53},
		gopacket.Payload([]byte("dns metadata only")),
	)
	key, _, ok := capturedFlow(packet, time.Now(), "pcap:eth0")
	if !ok || key.srcIP != "2001:db8::1" || key.dstIP != "2001:db8::2" || key.protocol != 17 {
		t.Fatalf("unexpected IPv6 UDP key: %+v, ok=%t", key, ok)
	}

	arp := serializePacket(t,
		&layers.Ethernet{SrcMAC: mac(t, "00:11:22:33:44:55"), DstMAC: mac(t, "ff:ff:ff:ff:ff:ff"), EthernetType: layers.EthernetTypeARP},
		&layers.ARP{},
	)
	if _, _, ok := capturedFlow(arp, time.Now(), "pcap:eth0"); ok {
		t.Fatal("ARP packet must not produce a flow")
	}
}

func TestPcapCollectorAggregatesAndEvicts(t *testing.T) {
	processor := &recordingProcessor{}
	c := NewPcapCollector("eth0", "", false, slog.New(slog.NewTextHandler(io.Discard, nil)), processor)
	now := time.Now().UTC()
	packet := serializePacket(t,
		&layers.Ethernet{SrcMAC: mac(t, "00:11:22:33:44:55"), DstMAC: mac(t, "66:77:88:99:aa:bb"), EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("10.0.0.2"), DstIP: net.ParseIP("1.1.1.1")},
		&layers.UDP{SrcPort: 53000, DstPort: 53},
		gopacket.Payload([]byte("query")),
	)

	c.consumePacket(packet, now)
	c.consumePacket(packet, now.Add(time.Second))
	if len(c.active) != 1 {
		t.Fatalf("expected one active 5-tuple, got %d", len(c.active))
	}
	c.evictExpired(now.Add(defaultIdleFlowTimeout + 2*time.Second))

	if len(processor.events) != 1 {
		t.Fatalf("expected one emitted aggregate, got %d", len(processor.events))
	}
	if processor.events[0].Packets != 2 || processor.events[0].Bytes != 2*uint64(len(packet.Data())) {
		t.Fatalf("unexpected aggregate: %+v", processor.events[0])
	}
}

func TestPcapCollectorBoundsActiveFlows(t *testing.T) {
	c := NewPcapCollector("eth0", "", false, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	c.maxActive = 1
	now := time.Now().UTC()
	first := udpPacket(t, "10.0.0.1", "1.1.1.1")
	second := udpPacket(t, "10.0.0.2", "1.1.1.1")
	c.consumePacket(first, now)
	c.consumePacket(second, now)
	if len(c.active) != 1 {
		t.Fatalf("active flow table exceeded bound: %d", len(c.active))
	}
}

func udpPacket(t *testing.T, src, dst string) gopacket.Packet {
	t.Helper()
	return serializePacket(t,
		&layers.Ethernet{SrcMAC: mac(t, "00:11:22:33:44:55"), DstMAC: mac(t, "66:77:88:99:aa:bb"), EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst)},
		&layers.UDP{SrcPort: 1000, DstPort: 2000},
	)
}

func serializePacket(t *testing.T, serializable ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true}, serializable...); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func mac(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	addr, err := net.ParseMAC(value)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}
