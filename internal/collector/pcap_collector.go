package collector

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miquelbar/flowguard-lite/internal/flow"
)

const (
	pcapSnapshotLength       = 256
	pcapReadTimeout          = time.Second
	defaultActiveFlowTimeout = 30 * time.Second
	defaultIdleFlowTimeout   = 15 * time.Second
	defaultPcapFlushInterval = 30 * time.Second
	defaultMaxActiveFlows    = 65536
)

type packetCaptureHandle interface {
	gopacket.PacketDataSource
	LinkType() layers.LinkType
	SetBPFFilter(string) error
	Close()
}

type pcapHandleOpener func(device string, snaplen int32, promiscuous bool, timeout time.Duration) (packetCaptureHandle, error)

type captureFlowKey struct {
	srcIP, dstIP     string
	srcPort, dstPort uint16
	protocol         uint8
}

type activeCaptureFlow struct {
	event     flow.FlowEvent
	firstSeen time.Time
	lastSeen  time.Time
}

// PcapCollector reduces packets from a local interface to bounded 5-tuple flow
// metadata. Packet payload bytes and PCAP data are never retained.
type PcapCollector struct {
	interfaceName string
	bpfFilter     string
	promiscuous   bool
	logger        *slog.Logger
	processor     flow.FlowProcessor

	activeTimeout time.Duration
	idleTimeout   time.Duration
	flushInterval time.Duration
	maxActive     int
	openHandle    pcapHandleOpener

	mu       sync.Mutex
	active   map[captureFlowKey]*activeCaptureFlow
	handle   packetCaptureHandle
	stop     chan struct{}
	wg       sync.WaitGroup
	started  bool
	stopOnce sync.Once
}

// NewPcapCollector creates a disabled-until-started passive capture collector.
func NewPcapCollector(interfaceName, bpfFilter string, promiscuous bool, logger *slog.Logger, processor flow.FlowProcessor) *PcapCollector {
	return &PcapCollector{
		interfaceName: interfaceName,
		bpfFilter:     bpfFilter,
		promiscuous:   promiscuous,
		logger:        logger,
		processor:     processor,
		activeTimeout: defaultActiveFlowTimeout,
		idleTimeout:   defaultIdleFlowTimeout,
		flushInterval: defaultPcapFlushInterval,
		maxActive:     defaultMaxActiveFlows,
		openHandle: func(device string, snaplen int32, promiscuous bool, timeout time.Duration) (packetCaptureHandle, error) {
			return pcap.OpenLive(device, snaplen, promiscuous, timeout)
		},
		active: make(map[captureFlowKey]*activeCaptureFlow),
		stop:   make(chan struct{}),
	}
}

// Start opens the configured interface and begins packet reduction.
func (c *PcapCollector) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return nil
	}
	if c.interfaceName == "" {
		return fmt.Errorf("capture interface is required")
	}

	handle, err := c.openHandle(c.interfaceName, pcapSnapshotLength, c.promiscuous, pcapReadTimeout)
	if err != nil {
		return fmt.Errorf("open capture interface %q: %w", c.interfaceName, err)
	}
	if c.bpfFilter != "" {
		if err := handle.SetBPFFilter(c.bpfFilter); err != nil {
			handle.Close()
			return fmt.Errorf("apply capture BPF filter: %w", err)
		}
	}

	c.handle = handle
	c.started = true
	c.wg.Add(2)
	go c.captureLoop(handle)
	go c.evictionLoop()
	c.logger.Info("Passive packet capture started",
		slog.String("interface", c.interfaceName),
		slog.Bool("promiscuous", c.promiscuous))
	return nil
}

// Shutdown stops capture and emits all remaining reduced flow records.
func (c *PcapCollector) Shutdown() {
	c.stopOnce.Do(func() {
		close(c.stop)
		c.mu.Lock()
		if c.handle != nil {
			c.handle.Close()
		}
		c.mu.Unlock()
		c.wg.Wait()
		c.flushAll()
	})
}

func (c *PcapCollector) captureLoop(handle packetCaptureHandle) {
	defer c.wg.Done()
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-c.stop:
			return
		case packet, ok := <-source.Packets():
			if !ok {
				return
			}
			c.consumePacket(packet, time.Now().UTC())
		}
	}
}

func (c *PcapCollector) evictionLoop() {
	defer c.wg.Done()
	evictionTick := time.NewTicker(time.Second)
	flushTick := time.NewTicker(c.flushInterval)
	defer evictionTick.Stop()
	defer flushTick.Stop()
	for {
		select {
		case <-c.stop:
			return
		case now := <-evictionTick.C:
			c.evictExpired(now.UTC())
		case <-flushTick.C:
			c.flushAll()
		}
	}
}

func (c *PcapCollector) consumePacket(packet gopacket.Packet, now time.Time) {
	key, event, ok := capturedFlow(packet, now, "pcap:"+c.interfaceName)
	if !ok {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, found := c.active[key]; found {
		existing.event.Bytes += event.Bytes
		existing.event.Packets++
		existing.event.TCPFlags |= event.TCPFlags
		existing.lastSeen = now
		return
	}
	if len(c.active) >= c.maxActive {
		return
	}
	c.active[key] = &activeCaptureFlow{event: event, firstSeen: now, lastSeen: now}
}

func (c *PcapCollector) evictExpired(now time.Time) {
	var expired []flow.FlowEvent
	c.mu.Lock()
	for key, item := range c.active {
		if now.Sub(item.firstSeen) >= c.activeTimeout || now.Sub(item.lastSeen) >= c.idleTimeout {
			expired = append(expired, item.event)
			delete(c.active, key)
		}
	}
	c.mu.Unlock()
	c.emit(expired)
}

func (c *PcapCollector) flushAll() {
	c.mu.Lock()
	batch := make([]flow.FlowEvent, 0, len(c.active))
	for key, item := range c.active {
		batch = append(batch, item.event)
		delete(c.active, key)
	}
	c.mu.Unlock()
	c.emit(batch)
}

func (c *PcapCollector) emit(batch []flow.FlowEvent) {
	if c.processor == nil {
		return
	}
	for i := range batch {
		event := batch[i]
		c.processor.Process(&event)
	}
}

func capturedFlow(packet gopacket.Packet, now time.Time, exporter string) (captureFlowKey, flow.FlowEvent, bool) {
	var key captureFlowKey
	network := packet.NetworkLayer()
	transport := packet.TransportLayer()
	if network == nil || transport == nil {
		return key, flow.FlowEvent{}, false
	}

	switch layer := network.(type) {
	case *layers.IPv4:
		key.srcIP, key.dstIP = layer.SrcIP.String(), layer.DstIP.String()
	case *layers.IPv6:
		key.srcIP, key.dstIP = layer.SrcIP.String(), layer.DstIP.String()
	default:
		return key, flow.FlowEvent{}, false
	}

	var flags uint8
	switch layer := transport.(type) {
	case *layers.TCP:
		key.protocol = uint8(layers.IPProtocolTCP)
		key.srcPort, key.dstPort = uint16(layer.SrcPort), uint16(layer.DstPort)
		if layer.FIN {
			flags |= 0x01
		}
		if layer.SYN {
			flags |= 0x02
		}
		if layer.RST {
			flags |= 0x04
		}
		if layer.PSH {
			flags |= 0x08
		}
		if layer.ACK {
			flags |= 0x10
		}
		if layer.URG {
			flags |= 0x20
		}
		if layer.ECE {
			flags |= 0x40
		}
		if layer.CWR {
			flags |= 0x80
		}
	case *layers.UDP:
		key.protocol = uint8(layers.IPProtocolUDP)
		key.srcPort, key.dstPort = uint16(layer.SrcPort), uint16(layer.DstPort)
	default:
		return key, flow.FlowEvent{}, false
	}

	length := len(packet.Data())
	if metadata := packet.Metadata(); metadata != nil && metadata.Length > 0 {
		length = metadata.Length
	}
	return key, flow.FlowEvent{
		Timestamp: now, SrcIP: key.srcIP, DstIP: key.dstIP,
		SrcPort: int(key.srcPort), DstPort: int(key.dstPort), Protocol: int(key.protocol),
		Bytes: uint64(length), Packets: 1, CollectorKind: flow.CollectorKindPCAP,
		CollectorID: exporter, ExporterIP: exporter, TCPFlags: flags,
	}, true
}
