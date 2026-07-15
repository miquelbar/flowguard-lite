package api

import (
	"context"
	"errors"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/collector"
	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

type MockCollector struct {
	Stats     collector.Stats
	Exporters []collector.ExporterMetadata
}

func (m *MockCollector) GetStats() collector.Stats {
	return m.Stats
}

func (m *MockCollector) GetExporters() []collector.ExporterMetadata {
	return m.Exporters
}

type MockFlowRepository struct {
	storage.DeviceRepository
	Sources      []flow.TopResult
	Destinations []flow.TopResult
	Ports        []flow.TopResult
	Protocols    []flow.TopResult
	TopDevices   []flow.TopResult
	Heatmap      []flow.DeviceHeatmapCell
	Records      []flow.AggregateRecord
	Baseline     *storage.DeviceBaseline
	Devices      []storage.Device
	Anomalies    []storage.Anomaly
	UniFiEvents  []storage.UniFiEvent
	Err          error
	EmptyDevices bool
}

func (m *MockFlowRepository) SaveAggregates(ctx context.Context, ts time.Time, aggregates []flow.FlowEvent) error {
	return nil
}

func (m *MockFlowRepository) GetTopSources(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return m.Sources, m.Err
}

func (m *MockFlowRepository) GetTopDestinations(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return m.Destinations, m.Err
}

func (m *MockFlowRepository) GetTopPorts(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return m.Ports, m.Err
}

func (m *MockFlowRepository) GetTopProtocols(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return m.Protocols, m.Err
}

func (m *MockFlowRepository) GetTopDevicesByVolume(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return m.TopDevices, m.Err
}

func (m *MockFlowRepository) GetTrafficTimeSeries(ctx context.Context, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error) {
	return []flow.TrafficTimeBucket{
		{Timestamp: start.UTC(), Bytes: 1000, Packets: 10, Flows: 2},
	}, m.Err
}

func (m *MockFlowRepository) QueryFlowAggregateRecords(ctx context.Context, start, end time.Time, q string, protocol, dstPort, limit int) ([]flow.AggregateRecord, error) {
	if m.Records != nil {
		return m.Records, m.Err
	}
	return []flow.AggregateRecord{
		{Timestamp: start.UTC(), CollectorKind: flow.CollectorKindNetFlow, CollectorID: "unifi-gateway", SrcIP: "192.168.1.10", DstIP: "8.8.8.8", DstPort: 53, Protocol: 17, Bytes: 1200, Packets: 12, Flows: 2},
	}, m.Err
}

func (m *MockFlowRepository) GetDeviceActivityHeatmap(ctx context.Context, start, end time.Time, limit int) ([]flow.DeviceHeatmapCell, error) {
	if m.Heatmap == nil {
		return []flow.DeviceHeatmapCell{}, m.Err
	}
	return m.Heatmap, m.Err
}

func (m *MockFlowRepository) UpsertDevice(ctx context.Context, ip string, hostname string, lastSeen time.Time) error {
	for idx, device := range m.Devices {
		if device.IP == ip {
			m.Devices[idx].LastSeen = lastSeen
			if hostname != "" {
				m.Devices[idx].Hostname = hostname
			}
			return m.Err
		}
	}
	m.Devices = append(m.Devices, storage.Device{IP: ip, Hostname: hostname, FirstSeen: lastSeen, LastSeen: lastSeen})
	return nil
}

func (m *MockFlowRepository) UpdateDeviceLabel(ctx context.Context, ip string, label string) error {
	if ip == "192.168.1.10" {
		return m.Err
	}
	return errors.New("device not found")
}

func (m *MockFlowRepository) GetDevice(ctx context.Context, ip string) (*storage.Device, error) {
	for _, d := range m.Devices {
		if d.IP == ip {
			return &d, m.Err
		}
	}
	return nil, m.Err
}

func (m *MockFlowRepository) ListDevices(ctx context.Context) ([]storage.Device, error) {
	if len(m.Devices) > 0 {
		return m.Devices, m.Err
	}
	if m.EmptyDevices {
		return []storage.Device{}, m.Err
	}
	return []storage.Device{
		{IP: "192.168.1.10", Label: "Discovered Device", Hostname: "test.local"},
	}, m.Err
}

func (m *MockFlowRepository) SaveBaseline(ctx context.Context, b *storage.DeviceBaseline) error {
	m.Baseline = b
	return m.Err
}

func (m *MockFlowRepository) GetBaseline(ctx context.Context, ip string) (*storage.DeviceBaseline, error) {
	if m.Baseline != nil && m.Baseline.IP == ip {
		return m.Baseline, m.Err
	}
	return nil, m.Err
}

func (m *MockFlowRepository) SaveAnomaly(ctx context.Context, a *storage.Anomaly) error {
	return m.Err
}

func (m *MockFlowRepository) UpdateAnomalyStatus(ctx context.Context, id int64, status string) error {
	if id == 123 {
		return m.Err
	}
	return errors.New("anomaly not found")
}

func (m *MockFlowRepository) ListAnomalies(ctx context.Context, limit int) ([]storage.Anomaly, error) {
	return []storage.Anomaly{
		{ID: 123, IP: "192.168.1.10", Type: "TRAFFIC_SPIKE", Status: "active"},
	}, m.Err
}

func (m *MockFlowRepository) GetActiveAnomalies(ctx context.Context, since time.Time) ([]storage.Anomaly, error) {
	if len(m.Anomalies) > 0 {
		return m.Anomalies, m.Err
	}
	return []storage.Anomaly{
		{ID: 123, IP: "192.168.1.10", Type: "TRAFFIC_SPIKE", Status: "active", CreatedAt: time.Now()},
	}, m.Err
}

func (m *MockFlowRepository) SaveAuditLog(ctx context.Context, action string, details string) error {
	return m.Err
}

func (m *MockFlowRepository) ListAuditLogs(ctx context.Context, limit int) ([]storage.AuditLog, error) {
	return []storage.AuditLog{
		{ID: 1, Timestamp: time.Now(), Action: "update_label", Details: "Updated label"},
	}, m.Err
}

func (m *MockFlowRepository) GetAnomaliesForIP(ctx context.Context, ip string, limit int) ([]storage.Anomaly, error) {
	var filtered []storage.Anomaly
	for _, a := range m.Anomalies {
		if a.IP == ip {
			filtered = append(filtered, a)
			if len(filtered) >= limit {
				break
			}
		}
	}
	if len(filtered) == 0 && len(m.Anomalies) > 0 {
		for _, a := range m.Anomalies {
			filtered = append(filtered, a)
			if len(filtered) >= limit {
				break
			}
		}
	}
	return filtered, m.Err
}

func (m *MockFlowRepository) GetDeviceTrafficTimeSeries(ctx context.Context, ip string, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error) {
	return []flow.TrafficTimeBucket{
		{Timestamp: start.UTC(), Bytes: 500, Packets: 5, Flows: 1},
	}, m.Err
}

func (m *MockFlowRepository) GetDeviceTopPeers(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error) {
	if m.Destinations == nil {
		return []flow.TopResult{}, m.Err
	}
	return m.Destinations, m.Err
}

func (m *MockFlowRepository) GetDeviceTopPorts(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error) {
	if m.Ports == nil {
		return []flow.TopResult{}, m.Err
	}
	return m.Ports, m.Err
}

func (m *MockFlowRepository) SavePolicy(ctx context.Context, p *storage.Policy) error {
	return m.Err
}

func (m *MockFlowRepository) DeletePolicy(ctx context.Context, id int64) error {
	return m.Err
}

func (m *MockFlowRepository) GetPolicy(ctx context.Context, id int64) (*storage.Policy, error) {
	return nil, m.Err
}

func (m *MockFlowRepository) ListPolicies(ctx context.Context) ([]storage.Policy, error) {
	return []storage.Policy{}, m.Err
}

func (m *MockFlowRepository) HasRecentAnomaly(ctx context.Context, ip string, anomalyType string, since time.Time) (bool, error) {
	return false, m.Err
}

func (m *MockFlowRepository) GetPoliciesForIP(ctx context.Context, ip string) ([]storage.Policy, error) {
	return []storage.Policy{}, m.Err
}

func (m *MockFlowRepository) SaveNotificationRule(ctx context.Context, r *storage.NotificationRule) error {
	return m.Err
}

func (m *MockFlowRepository) DeleteNotificationRule(ctx context.Context, id int64) error {
	return m.Err
}

func (m *MockFlowRepository) GetNotificationRule(ctx context.Context, id int64) (*storage.NotificationRule, error) {
	if id == 555 {
		return &storage.NotificationRule{
			ID:             555,
			Name:           "Mock Slack Test Rule",
			Enabled:        true,
			SeverityMin:    "high",
			Scope:          "global",
			ChannelTargets: []string{"slack"},
		}, nil
	}
	return nil, m.Err
}

func (m *MockFlowRepository) ListNotificationRules(ctx context.Context) ([]storage.NotificationRule, error) {
	return []storage.NotificationRule{}, m.Err
}

func (m *MockFlowRepository) SaveNotificationLog(ctx context.Context, l *storage.NotificationLog) error {
	return m.Err
}

func (m *MockFlowRepository) ListNotificationLogs(ctx context.Context, limit int) ([]storage.NotificationLog, error) {
	return []storage.NotificationLog{}, m.Err
}

func (m *MockFlowRepository) HasRecentNotification(ctx context.Context, ruleID int64, ip string, anomalyType string, since time.Time) (bool, error) {
	return false, m.Err
}

func (m *MockFlowRepository) SaveUniFiEvent(ctx context.Context, e *storage.UniFiEvent) error {
	m.UniFiEvents = append(m.UniFiEvents, *e)
	return m.Err
}

func (m *MockFlowRepository) ListUniFiEvents(ctx context.Context, limit int) ([]storage.UniFiEvent, error) {
	return m.UniFiEvents, m.Err
}

func (m *MockFlowRepository) GetUniFiEventsForIP(ctx context.Context, ip string, limit int) ([]storage.UniFiEvent, error) {
	var res []storage.UniFiEvent
	for _, e := range m.UniFiEvents {
		if e.ClientIP == ip {
			res = append(res, e)
		}
	}
	return res, m.Err
}
