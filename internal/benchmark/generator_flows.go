package benchmark

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
)

// FlowEventGenerator generates deterministic, seedable mock flow events for benchmarks.
type FlowEventGenerator struct {
	rng *rand.Rand
}

// NewFlowEventGenerator creates a new generator initialized with a specific seed.
func NewFlowEventGenerator(seed int64) *FlowEventGenerator {
	return &FlowEventGenerator{
		rng: rand.New(rand.NewSource(seed)),
	}
}

// GenerateSmallOffice generates flow events representing a standard small office (25 devices).
func (g *FlowEventGenerator) GenerateSmallOffice(count int, startTime time.Time) []flow.FlowEvent {
	return g.generate(count, startTime, 25, 50, false)
}

// GenerateBusyOffice generates flow events representing a busy office profile (100 devices).
func (g *FlowEventGenerator) GenerateBusyOffice(count int, startTime time.Time) []flow.FlowEvent {
	return g.generate(count, startTime, 100, 150, false)
}

// GenerateHighFlowLab generates flow events representing high-volume lab profile (200 devices).
func (g *FlowEventGenerator) GenerateHighFlowLab(count int, startTime time.Time) []flow.FlowEvent {
	return g.generate(count, startTime, 200, 500, false)
}

// GenerateDDoSAttack generates flow events representing a volumetric flood targeting a specific local IP.
func (g *FlowEventGenerator) GenerateDDoSAttack(count int, startTime time.Time, victimIP string) []flow.FlowEvent {
	events := make([]flow.FlowEvent, count)
	protocols := []uint8{6, 17, 1} // TCP, UDP, ICMP
	
	for i := 0; i < count; i++ {
		proto := protocols[g.rng.Intn(len(protocols))]
		srcIP := fmt.Sprintf("10.99.%d.%d", g.rng.Intn(250)+1, g.rng.Intn(250)+1)
		
		events[i] = flow.FlowEvent{
			Timestamp:     startTime.Add(time.Duration(i) * time.Millisecond),
			SrcIP:         srcIP,
			DstIP:         victimIP,
			SrcPort:       int(g.rng.Intn(65535-1024) + 1024),
			DstPort:       int(g.rng.Intn(65535-1) + 1),
			Protocol:      int(proto),
			Bytes:         64,
			Packets:       1,
			CollectorKind: flow.CollectorKindNetFlow,
			CollectorID:   "10.0.0.1",
		}
	}
	return events
}

// Internal generator engine
func (g *FlowEventGenerator) generate(count int, startTime time.Time, localDevicesCount, externalDstsCount int, burst bool) []flow.FlowEvent {
	events := make([]flow.FlowEvent, count)
	
	// Generate fixed pool of IPs
	localIPs := make([]string, localDevicesCount)
	for i := 0; i < localDevicesCount; i++ {
		localIPs[i] = fmt.Sprintf("192.168.1.%d", i+2) // start at 192.168.1.2
	}
	
	externalIPs := make([]string, externalDstsCount)
	for i := 0; i < externalDstsCount; i++ {
		externalIPs[i] = fmt.Sprintf("8.8.8.%d", i+1)
	}

	protocols := []uint8{6, 17, 1} // TCP, UDP, ICMP
	commonPorts := []uint16{80, 443, 53, 22, 123}

	for i := 0; i < count; i++ {
		// 80% outbound traffic, 20% inbound or internal
		var srcIP, dstIP string
		var collectorKind string
		var collectorID string
		
		direction := g.rng.Float32()
		if direction < 0.8 {
			srcIP = localIPs[g.rng.Intn(len(localIPs))]
			dstIP = externalIPs[g.rng.Intn(len(externalIPs))]
		} else if direction < 0.95 {
			srcIP = externalIPs[g.rng.Intn(len(externalIPs))]
			dstIP = localIPs[g.rng.Intn(len(localIPs))]
		} else {
			// East-West local traffic
			srcIP = localIPs[g.rng.Intn(len(localIPs))]
			dstIP = localIPs[g.rng.Intn(len(localIPs))]
			for srcIP == dstIP {
				dstIP = localIPs[g.rng.Intn(len(localIPs))]
			}
		}

		// Distribute between collectors
		collChoice := g.rng.Float32()
		if collChoice < 0.7 {
			collectorKind = flow.CollectorKindNetFlow
			collectorID = "192.168.1.1" // gateway exporter
		} else if collChoice < 0.9 {
			collectorKind = flow.CollectorKindSFlow
			collectorID = "192.168.1.254" // switch exporter
		} else {
			collectorKind = flow.CollectorKindPCAP
			collectorID = "pcap:eth0"
		}

		proto := protocols[g.rng.Intn(len(protocols))]
		var srcPort, dstPort uint16

		if proto == 1 {
			// ICMP has no ports
			srcPort = 0
			dstPort = 0
		} else {
			// 70% to common ports, 30% random high ports
			if g.rng.Float32() < 0.7 {
				dstPort = commonPorts[g.rng.Intn(len(commonPorts))]
			} else {
				dstPort = uint16(g.rng.Intn(65535-1024) + 1024)
			}
			srcPort = uint16(g.rng.Intn(65535-1024) + 1024)
		}

		packets := uint32(g.rng.Intn(20) + 1)
		bytesVal := packets * uint32(g.rng.Intn(1400)+40)

		events[i] = flow.FlowEvent{
			Timestamp:     startTime.Add(time.Duration(i) * 5 * time.Millisecond), // spread over time
			SrcIP:         srcIP,
			DstIP:         dstIP,
			SrcPort:       int(srcPort),
			DstPort:       int(dstPort),
			Protocol:      int(proto),
			Bytes:         uint64(bytesVal),
			Packets:       uint64(packets),
			CollectorKind: collectorKind,
			CollectorID:   collectorID,
		}
	}

	return events
}
