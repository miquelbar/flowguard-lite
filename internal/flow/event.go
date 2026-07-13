package flow

import (
	"strings"
	"time"
)

const (
	CollectorKindUnknown     = "unknown"
	CollectorKindNetFlow     = "netflow"
	CollectorKindSFlow       = "sflow"
	CollectorKindPCAP        = "pcap"
	CollectorKindSuricata    = "suricata"
	CollectorKindUniFiSyslog = "unifi_syslog"
	CollectorKindSNMP        = "snmp"
)

// NormalizeCollectorKind returns a bounded collector kind for persisted telemetry.
func NormalizeCollectorKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case CollectorKindNetFlow:
		return CollectorKindNetFlow
	case CollectorKindSFlow:
		return CollectorKindSFlow
	case CollectorKindPCAP:
		return CollectorKindPCAP
	case CollectorKindSuricata:
		return CollectorKindSuricata
	case CollectorKindUniFiSyslog:
		return CollectorKindUniFiSyslog
	case CollectorKindSNMP:
		return CollectorKindSNMP
	default:
		return CollectorKindUnknown
	}
}

// NormalizeCollectorID returns a stable source label without overloading exporter_ip.
func NormalizeCollectorID(id, kind, exporterIP string) string {
	id = strings.TrimSpace(id)
	if id != "" {
		return id
	}
	exporterIP = strings.TrimSpace(exporterIP)
	if exporterIP != "" {
		return exporterIP
	}
	kind = NormalizeCollectorKind(kind)
	if kind != CollectorKindUnknown {
		return kind
	}
	return CollectorKindUnknown
}

// FlowEvent represents a normalized NetFlow/IPFIX/sFlow record.
type FlowEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	SrcIP         string    `json:"src_ip"`
	DstIP         string    `json:"dst_ip"`
	SrcPort       int       `json:"src_port"`
	DstPort       int       `json:"dst_port"`
	Protocol      int       `json:"protocol"`
	Bytes         uint64    `json:"bytes"`
	Packets       uint64    `json:"packets"`
	CollectorKind string    `json:"collector_kind,omitempty"`
	CollectorID   string    `json:"collector_id,omitempty"`
	ExporterIP    string    `json:"exporter_ip"`
	TCPFlags      uint8     `json:"tcp_flags,omitempty"`
}

// FlowProcessor defines the interface for consumer components that receive normalized flow events.
type FlowProcessor interface {
	Process(event *FlowEvent)
}

// TopResult represents an aggregated statistics result for Top Talkers dashboards.
type TopResult struct {
	Key     string `json:"key"` // e.g. IP address or port number
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}

// TrafficTimeBucket represents aggregate traffic counters for a bounded time bucket.
type TrafficTimeBucket struct {
	Timestamp time.Time `json:"timestamp"`
	Bytes     uint64    `json:"bytes"`
	Packets   uint64    `json:"packets"`
	Flows     uint64    `json:"flows"`
}

// AggregateRecord represents one persisted aggregate row used by the bounded
// Flow Explorer. It is not a raw packet or raw flow record; it is the retained
// rollup keyed by bucket/source/destination/service/protocol.
type AggregateRecord struct {
	Timestamp     time.Time `json:"timestamp"`
	CollectorKind string    `json:"collector_kind"`
	CollectorID   string    `json:"collector_id"`
	SrcIP         string    `json:"src_ip"`
	DstIP         string    `json:"dst_ip"`
	DstPort       int       `json:"dst_port"`
	Protocol      int       `json:"protocol"`
	Bytes         uint64    `json:"bytes"`
	Packets       uint64    `json:"packets"`
	Flows         uint64    `json:"flows"`
}

// DeviceHeatmapCell represents aggregate traffic volume for one device in one hour of day.
type DeviceHeatmapCell struct {
	IP      string `json:"ip"`
	Hour    int    `json:"hour"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}
