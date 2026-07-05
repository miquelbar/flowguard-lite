package collector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/flowguard/flowguard/internal/config"
	"github.com/flowguard/flowguard/internal/flow"
	"github.com/netsampler/goflow2/decoders/netflow"
	"github.com/netsampler/goflow2/decoders/sflow"
	"github.com/netsampler/goflow2/pb"
	"github.com/netsampler/goflow2/producer"
)

// ExporterMetadata tracks basic status information for a flow exporter.
type ExporterMetadata struct {
	IP          string    `json:"ip"`
	LastSeen    time.Time `json:"last_seen"`
	PacketCount uint64    `json:"packet_count"`
}

// Collector stats reporting structure.
type Stats struct {
	PacketsReceived  uint64 `json:"packets_received"`
	PacketsDropped   uint64 `json:"packets_dropped"`
	DecodeErrors     uint64 `json:"decode_errors"`
	QueueDepth       int    `json:"queue_depth"`
	PacketsNetflow   uint64 `json:"packets_netflow,omitempty"`
	PacketsSflow     uint64 `json:"packets_sflow,omitempty"`
}

// FlowCollector manages the UDP listeners and decoding workers.
type FlowCollector struct {
	cfg       *config.Config
	logger    *slog.Logger
	processor flow.FlowProcessor

	// UDP Listeners
	nfConn *net.UDPConn
	sfConn *net.UDPConn

	// Concurrency & Queues
	rawPacketsChan chan *rawPacket
	wg             sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc

	// Exporter registry and stats
	exportersMu sync.RWMutex
	exporters   map[string]*ExporterMetadata

	statsMu              sync.Mutex
	receivedCount        uint64
	receivedNetflowCount uint64
	receivedSflowCount   uint64
	droppedCount         uint64
	decodeErrCount       uint64
}

// Type of raw packets buffered for processing
type rawPacket struct {
	data       []byte
	exporterIP string
	packetType string // "netflow" or "sflow"
}

// NewFlowCollector instantiates a new FlowCollector daemon.
func NewFlowCollector(cfg *config.Config, logger *slog.Logger, processor flow.FlowProcessor) *FlowCollector {
	ctx, cancel := context.WithCancel(context.Background())
	exporters := make(map[string]*ExporterMetadata)
	if cfg != nil && cfg.Environment == "development" {
		now := time.Now()
		exporters["192.168.1.1"] = &ExporterMetadata{
			IP:          "192.168.1.1",
			LastSeen:    now.Add(-2 * time.Minute),
			PacketCount: 154320,
		}
		exporters["192.168.30.150"] = &ExporterMetadata{
			IP:          "192.168.30.150",
			LastSeen:    now.Add(-45 * time.Second),
			PacketCount: 12050,
		}
	}

	return &FlowCollector{
		cfg:            cfg,
		logger:         logger,
		processor:      processor,
		rawPacketsChan: make(chan *rawPacket, 5000), // Buffer to handle bursts without blocking UDP stack
		exporters:      exporters,
		ctx:            ctx,
		cancel:         cancel,
	}
}

// Start launches the UDP listeners and decoding worker pool.
func (c *FlowCollector) Start() error {
	c.logger.Info("Starting Flow Collector daemon...")

	// 1. Resolve and open NetFlow / IPFIX UDP Listener
	nfAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", c.cfg.NetflowPort))
	if err != nil {
		return fmt.Errorf("failed to resolve NetFlow UDP address: %w", err)
	}
	nfConn, err := net.ListenUDP("udp", nfAddr)
	if err != nil {
		return fmt.Errorf("failed to bind NetFlow UDP port: %w", err)
	}
	c.nfConn = nfConn

	// 2. Resolve and open sFlow UDP Listener
	sfAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", c.cfg.SflowPort))
	if err != nil {
		nfConn.Close()
		return fmt.Errorf("failed to resolve sFlow UDP address: %w", err)
	}
	sfConn, err := net.ListenUDP("udp", sfAddr)
	if err != nil {
		nfConn.Close()
		return fmt.Errorf("failed to bind sFlow UDP port: %w", err)
	}
	c.sfConn = sfConn

	// 3. Start worker pool for concurrent decoding (e.g. 4 workers)
	numWorkers := 4
	c.wg.Add(numWorkers)
	templates := netflow.CreateTemplateSystem()
	for i := 0; i < numWorkers; i++ {
		go c.workerLoop(templates)
	}

	// 4. Start listener loops
	c.wg.Add(2)
	go c.listenLoop(c.nfConn, "netflow")
	go c.listenLoop(c.sfConn, "sflow")

	c.logger.Info("Flow Collector started successfully",
		slog.Int("netflow_port", c.cfg.NetflowPort),
		slog.Int("sflow_port", c.cfg.SflowPort),
		slog.Int("workers", numWorkers))

	return nil
}

// Shutdown stops all listeners and workers, draining the remaining packets.
func (c *FlowCollector) Shutdown() {
	c.logger.Info("Shutting down Flow Collector...")
	c.cancel()

	// Close connections to break read loops
	if c.nfConn != nil {
		c.nfConn.Close()
	}
	if c.sfConn != nil {
		c.sfConn.Close()
	}

	// Close worker channel
	close(c.rawPacketsChan)

	// Wait for goroutines to finish
	c.wg.Wait()
	c.logger.Info("Flow Collector shut down successfully.")
}

// GetStats returns current collector performance stats.
func (c *FlowCollector) GetStats() Stats {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()
	return Stats{
		PacketsReceived:  c.receivedCount,
		PacketsDropped:   c.droppedCount,
		DecodeErrors:     c.decodeErrCount,
		QueueDepth:       len(c.rawPacketsChan),
		PacketsNetflow:   c.receivedNetflowCount,
		PacketsSflow:     c.receivedSflowCount,
	}
}

// GetExporters returns a slice of active exporters.
func (c *FlowCollector) GetExporters() []ExporterMetadata {
	c.exportersMu.RLock()
	defer c.exportersMu.RUnlock()

	res := make([]ExporterMetadata, 0, len(c.exporters))
	for _, exp := range c.exporters {
		res = append(res, *exp)
	}
	return res
}

// listenLoop reads UDP packets from the interface and places them in the buffered channel.
func (c *FlowCollector) listenLoop(conn *net.UDPConn, packetType string) {
	defer c.wg.Done()
	buf := make([]byte, 9000) // Standard MTU is 1500, but some flows can have jumbo frames up to 9000

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			n, rAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				c.logger.Warn("Error reading from UDP socket", slog.String("type", packetType), slog.String("error", err.Error()))
				continue
			}

			// Copy packet data to avoid overwrite in buffer
			data := make([]byte, n)
			copy(data, buf[:n])

			c.statsMu.Lock()
			c.receivedCount++
			if packetType == "netflow" {
				c.receivedNetflowCount++
			} else if packetType == "sflow" {
				c.receivedSflowCount++
			}
			c.statsMu.Unlock()

			// Push to rawPacketsChan. If channel is full, drop packet to preserve system stability
			select {
			case c.rawPacketsChan <- &rawPacket{
				data:       data,
				exporterIP: rAddr.IP.String(),
				packetType: packetType,
			}:
			default:
				c.statsMu.Lock()
				c.droppedCount++
				c.statsMu.Unlock()
			}
		}
	}
}

// workerLoop decodes raw packets from the buffer channel.
func (c *FlowCollector) workerLoop(templates netflow.NetFlowTemplateSystem) {
	defer c.wg.Done()

	for packet := range c.rawPacketsChan {
		c.updateExporterStats(packet.exporterIP)

		var flowMsgs []*flowpb.FlowMessage
		var err error

		if packet.packetType == "netflow" {
			flowMsgs, err = c.decodeNetFlow(packet.data, templates)
		} else if packet.packetType == "sflow" {
			flowMsgs, err = c.decodeSFlow(packet.data)
		}

		if err != nil {
			c.statsMu.Lock()
			c.decodeErrCount++
			c.statsMu.Unlock()
			c.logger.Debug("Failed to decode flow packet", slog.String("exporter", packet.exporterIP), slog.String("error", err.Error()))
			continue
		}

		// Normalize decoded FlowMessages and forward to the processor
		for _, msg := range flowMsgs {
			event := c.normalizeFlowMessage(msg, packet.exporterIP)
			if event != nil && c.processor != nil {
				c.processor.Process(event)
			}
		}
	}
}

// decodeNetFlow decodes NetFlow v9 or IPFIX packets.
func (c *FlowCollector) decodeNetFlow(data []byte, templates netflow.NetFlowTemplateSystem) ([]*flowpb.FlowMessage, error) {
	buf := bytes.NewBuffer(data)
	decoded, err := netflow.DecodeMessage(buf, templates)
	if err != nil {
		return nil, err
	}

	// Convert raw decoded message into flat protobuf FlowMessages
	msgs, err := producer.ProcessMessageNetFlow(decoded, nil)
	if err != nil {
		return nil, err
	}
	return msgs, nil
}

// decodeSFlow decodes sFlow packets.
func (c *FlowCollector) decodeSFlow(data []byte) ([]*flowpb.FlowMessage, error) {
	buf := bytes.NewBuffer(data)
	decoded, err := sflow.DecodeMessage(buf)
	if err != nil {
		return nil, err
	}

	msgs, err := producer.ProcessMessageSFlow(decoded)
	if err != nil {
		return nil, err
	}
	return msgs, nil
}

// normalizeFlowMessage converts goflow2 proto FlowMessage into our local normalized FlowEvent struct.
func (c *FlowCollector) normalizeFlowMessage(msg *flowpb.FlowMessage, exporterIP string) *flow.FlowEvent {
	// Parse IPv4/IPv6 addresses
	srcIP := net.IP(msg.GetSrcAddr()).String()
	dstIP := net.IP(msg.GetDstAddr()).String()

	// If IP addresses are invalid/empty, skip flow
	if srcIP == "<nil>" || dstIP == "<nil>" {
		return nil
	}

	// Use TimeReceived if start/end flow times are not provided
	ts := time.Unix(int64(msg.GetTimeReceived()), 0)
	if msg.GetTimeFlowStart() > 0 {
		ts = time.Unix(int64(msg.GetTimeFlowStart()), 0)
	}

	return &flow.FlowEvent{
		Timestamp:  ts,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		SrcPort:    int(msg.GetSrcPort()),
		DstPort:    int(msg.GetDstPort()),
		Protocol:   int(msg.GetProto()),
		Bytes:      msg.GetBytes(),
		Packets:    msg.GetPackets(),
		ExporterIP: exporterIP,
		TCPFlags:   uint8(msg.GetTcpFlags()),
	}
}

// updateExporterStats registers last seen time and packet counters per exporter IP.
func (c *FlowCollector) updateExporterStats(ip string) {
	c.exportersMu.Lock()
	defer c.exportersMu.Unlock()

	exp, ok := c.exporters[ip]
	if !ok {
		exp = &ExporterMetadata{
			IP: ip,
		}
		c.exporters[ip] = exp
	}
	exp.LastSeen = time.Now()
	exp.PacketCount++
}
