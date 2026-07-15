package anomaly

import (
	"net"

	"github.com/miquelbar/flowguard-lite/internal/flow"
)

func (e *AnomalyEngine) aggregateDeviceMetrics(batch []flow.FlowEvent) map[string]*deviceMetrics {
	metrics := make(map[string]*deviceMetrics)
	for _, f := range batch {
		if !e.isLocalIP(f.SrcIP) {
			continue
		}

		m, ok := metrics[f.SrcIP]
		if !ok {
			m = &deviceMetrics{
				dstIPs:               make(map[string]bool),
				dstPorts:             make(map[int]bool),
				dstIPByPort:          make(map[int]string),
				internalDstIPs:       make(map[string]bool),
				portsByDestination:   make(map[string]map[int]bool),
				packetsByDestination: make(map[string]uint64),
				protocols:            make(map[int]bool),
			}
			metrics[f.SrcIP] = m
		}

		m.bytes += f.Bytes
		m.packets += f.Packets
		if len(m.protocols) < 256 {
			m.protocols[f.Protocol] = true
		}
		if f.Timestamp.After(m.timestamp) {
			m.timestamp = f.Timestamp.UTC()
		}
		if isFanoutDestination(f.DstIP) {
			if len(m.dstIPs) < maxFanoutCardinality {
				m.dstIPs[f.DstIP] = true
			} else if !m.dstIPs[f.DstIP] {
				m.dstIPsTruncated = true
			}
		}
		if f.DstIP != f.SrcIP && e.isLocalIP(f.DstIP) && len(m.internalDstIPs) < internalPeerMaxPeers {
			m.internalDstIPs[f.DstIP] = true
		}
		if f.DstPort > 0 && f.DstPort <= 65535 {
			if len(m.dstPorts) < maxFanoutCardinality {
				m.dstPorts[f.DstPort] = true
			}
			if _, exists := m.dstIPByPort[f.DstPort]; !exists && len(m.dstIPByPort) < maxFanoutCardinality {
				m.dstIPByPort[f.DstPort] = f.DstIP
			}
			ports, exists := m.portsByDestination[f.DstIP]
			if !exists && len(m.portsByDestination) < maxFanoutCardinality {
				ports = make(map[int]bool)
				m.portsByDestination[f.DstIP] = ports
			}
			if ports != nil && len(ports) < maxFanoutCardinality {
				ports[f.DstPort] = true
				m.packetsByDestination[f.DstIP] += f.Packets
			}
		}
	}
	return metrics
}

func isFanoutDestination(ipString string) bool {
	ip := net.ParseIP(ipString)
	return ip != nil && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback()
}

// isLocalIP checks if an IP is a private local IP based on configuration subnets.
func (e *AnomalyEngine) isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, subnet := range e.localSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}
