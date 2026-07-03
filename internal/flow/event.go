package flow

import "time"

// FlowEvent represents a normalized NetFlow/IPFIX/sFlow record.
type FlowEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	SrcPort    int       `json:"src_port"`
	DstPort    int       `json:"dst_port"`
	Protocol   int       `json:"protocol"`
	Bytes      uint64    `json:"bytes"`
	Packets    uint64    `json:"packets"`
	ExporterIP string    `json:"exporter_ip"`
	TCPFlags   uint8     `json:"tcp_flags,omitempty"`
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
