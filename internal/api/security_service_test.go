package api

import (
	"context"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/collector"
	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/risk"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

type mockRiskCalculator struct {
	risks []risk.DeviceRisk
	err   error
}

func (m mockRiskCalculator) CalculateDeviceRisks(ctx context.Context) ([]risk.DeviceRisk, error) {
	return m.risks, m.err
}

func TestSecurityQueryServiceBuildSummary(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SuricataEvePath = "/var/log/suricata/eve.json"
	cfg.WebhookURL = "https://hooks.example.test/flowguard"
	cfg.UniFiSyslogEnabled = true
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)

	repo := &MockFlowRepository{
		Devices: []storage.Device{
			{IP: "192.168.1.10", Label: "NAS"},
			{IP: "192.168.1.20", Label: "Camera"},
			{IP: "192.168.1.30", Label: "Laptop"},
		},
		Anomalies: []storage.Anomaly{
			{ID: 1, IP: "192.168.1.10", Severity: "high", CreatedAt: now.Add(-10 * time.Minute)},
			{ID: 2, IP: "192.168.1.20", Severity: "critical", CreatedAt: now.Add(-20 * time.Minute)},
			{ID: 3, IP: "192.168.1.30", Severity: "unknown", CreatedAt: now.Add(-30 * time.Minute)},
		},
	}
	service := newSecurityQueryService(
		cfg,
		repo,
		mockRiskCalculator{risks: []risk.DeviceRisk{
			{IP: "192.168.1.20", RiskScore: 90, RiskLevel: "high"},
			{IP: "192.168.1.10", RiskScore: 35, RiskLevel: "medium"},
		}},
		&MockCollector{Stats: collector.Stats{
			PacketsReceived: 12,
			QueueDepth:      3,
			Sources: []collector.SourceStats{
				{Kind: "netflow", ID: "netflow", Enabled: true, Status: "listening", Port: 2055, Packets: 12, Drops: 1, DecodeErrors: 2},
			},
		}},
	)
	service.now = func() time.Time { return now }

	got, err := service.BuildSummary(context.Background())
	if err != nil {
		t.Fatalf("BuildSummary returned error: %v", err)
	}

	if got.ActiveAlertsTotal != 3 {
		t.Fatalf("expected 3 active alerts, got %d", got.ActiveAlertsTotal)
	}
	if got.ActiveAlertsBySeverity["critical"] != 1 || got.ActiveAlertsBySeverity["high"] != 1 || got.ActiveAlertsBySeverity["low"] != 1 {
		t.Fatalf("unexpected severity counts: %+v", got.ActiveAlertsBySeverity)
	}
	if got.MaxRiskScore != 90 || got.ElevatedRiskDevices != 2 {
		t.Fatalf("unexpected risk summary: max=%d elevated=%d", got.MaxRiskScore, got.ElevatedRiskDevices)
	}
	if got.RiskDistribution["high"] != 1 || got.RiskDistribution["medium"] != 1 || got.RiskDistribution["low"] != 1 {
		t.Fatalf("unexpected risk distribution: %+v", got.RiskDistribution)
	}
	if len(got.RecentHighAlerts) != 2 || got.RecentHighAlerts[0].ID != 1 {
		t.Fatalf("expected newest high/critical alerts first, got %+v", got.RecentHighAlerts)
	}
	if !got.SuricataConfigured || !got.NotificationConfigured || !got.UniFiConfigured {
		t.Fatalf("expected configured integrations, got suricata=%t notifications=%t unifi=%t", got.SuricataConfigured, got.NotificationConfigured, got.UniFiConfigured)
	}
	if got.DetectorStatus["unifi_siem"] != "configured" {
		t.Fatalf("expected unifi_siem detector configured, got %s", got.DetectorStatus["unifi_siem"])
	}
	if got.Collector == nil || got.Collector.QueueDepth != 3 || got.Collector.PacketsReceived != 12 {

		t.Fatalf("unexpected collector summary: %+v", got.Collector)
	}
	if len(got.Collector.Sources) != 1 || got.Collector.Sources[0].Kind != "netflow" || got.Collector.Sources[0].Status != "listening" {
		t.Fatalf("unexpected collector source summary: %+v", got.Collector.Sources)
	}
	if got.Collector.Sources[0].Drops != 1 || got.Collector.Sources[0].DecodeErrors != 2 {
		t.Fatalf("expected collector source drops/errors, got %+v", got.Collector.Sources[0])
	}
}

func TestSecurityQueryServiceBuildTimelineBucketsByTime(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	repo := &MockFlowRepository{
		Anomalies: []storage.Anomaly{
			{ID: 1, Severity: "high", CreatedAt: now.Add(30 * time.Second)},
			{ID: 2, Severity: "medium", CreatedAt: now.Add(59 * time.Second)},
			{ID: 3, Severity: "critical", CreatedAt: now.Add(2 * time.Minute)},
			{ID: 4, Severity: "low", CreatedAt: now.Add(2 * time.Hour)},
		},
	}
	service := newSecurityQueryService(config.DefaultConfig(), repo, mockRiskCalculator{}, nil)

	got, err := service.BuildTimeline(context.Background(), now, now.Add(5*time.Minute), 60)
	if err != nil {
		t.Fatalf("BuildTimeline returned error: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected two buckets inside window, got %+v", got)
	}
	if !got[0].Timestamp.Equal(now) || got[0].Total != 2 || got[0].Counts["high"] != 1 || got[0].Counts["medium"] != 1 {
		t.Fatalf("unexpected first bucket: %+v", got[0])
	}
	if got[1].Total != 1 || got[1].Counts["critical"] != 1 {
		t.Fatalf("unexpected second bucket: %+v", got[1])
	}
}
