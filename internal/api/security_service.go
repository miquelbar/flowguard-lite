package api

import (
	"context"
	"sort"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/collector"
	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/risk"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

type SecuritySummaryResponse struct {
	ActiveAlertsBySeverity map[string]int       `json:"active_alerts_by_severity"`
	ActiveAlertsTotal      int                  `json:"active_alerts_total"`
	MaxRiskScore           int                  `json:"max_risk_score"`
	ElevatedRiskDevices    int                  `json:"elevated_risk_devices"`
	TotalDevices           int                  `json:"total_devices"`
	RiskDistribution       map[string]int       `json:"risk_distribution"`
	DetectorStatus         map[string]string    `json:"detector_status"`
	DDoSThresholds         map[string]int       `json:"ddos_thresholds"`
	SuricataConfigured     bool                 `json:"suricata_configured"`
	NotificationConfigured bool                 `json:"notification_configured"`
	UniFiConfigured        bool                 `json:"unifi_configured"`
	TopRiskDevices         []risk.DeviceRisk    `json:"top_risk_devices"`
	RecentHighAlerts       []storage.Anomaly    `json:"recent_high_alerts"`
	Collector              *collectorHealthView `json:"collector,omitempty"`
}

type collectorHealthView struct {
	PacketsReceived uint64                  `json:"packets_received"`
	PacketsDropped  uint64                  `json:"packets_dropped"`
	DecodeErrors    uint64                  `json:"decode_errors"`
	QueueDepth      int                     `json:"queue_depth"`
	Sources         []collectorSourceHealth `json:"sources,omitempty"`
}

type collectorSourceHealth struct {
	Kind         string `json:"kind"`
	ID           string `json:"id"`
	Enabled      bool   `json:"enabled"`
	Status       string `json:"status"`
	Port         int    `json:"port,omitempty"`
	Packets      uint64 `json:"packets,omitempty"`
	Drops        uint64 `json:"drops,omitempty"`
	DecodeErrors uint64 `json:"decode_errors,omitempty"`
}

type SecurityTimelineBucket struct {
	Timestamp time.Time      `json:"timestamp"`
	Counts    map[string]int `json:"counts"`
	Total     int            `json:"total"`
}

type deviceRiskCalculator interface {
	CalculateDeviceRisks(ctx context.Context) ([]risk.DeviceRisk, error)
}

type securityQueryService struct {
	cfg            *config.Config
	deviceRepo     storage.DeviceRepository
	riskCalculator deviceRiskCalculator
	collector      CollectorProvider
	now            func() time.Time
}

func newSecurityQueryService(
	cfg *config.Config,
	deviceRepo storage.DeviceRepository,
	riskCalculator deviceRiskCalculator,
	collector CollectorProvider,
) securityQueryService {
	return securityQueryService{
		cfg:            cfg,
		deviceRepo:     deviceRepo,
		riskCalculator: riskCalculator,
		collector:      collector,
		now:            time.Now,
	}
}

func (q securityQueryService) BuildSummary(ctx context.Context) (SecuritySummaryResponse, error) {
	since := q.now().Add(-7 * 24 * time.Hour)
	active, err := q.deviceRepo.GetActiveAnomalies(ctx, since)
	if err != nil {
		return SecuritySummaryResponse{}, err
	}

	risks, err := q.riskCalculator.CalculateDeviceRisks(ctx)
	if err != nil {
		return SecuritySummaryResponse{}, err
	}

	devices, err := q.deviceRepo.ListDevices(ctx)
	if err != nil {
		return SecuritySummaryResponse{}, err
	}

	counts := map[string]int{
		storage.SeverityCritical: 0,
		storage.SeverityHigh:     0,
		storage.SeverityMedium:   0,
		storage.SeverityLow:      0,
	}
	var recentHigh []storage.Anomaly
	for _, a := range active {
		severity := normalizeSeverity(a.Severity)
		counts[severity]++
		if severity == storage.SeverityCritical || severity == storage.SeverityHigh {
			recentHigh = append(recentHigh, a)
		}
	}
	sortAnomaliesNewestFirst(recentHigh)
	if len(recentHigh) > 10 {
		recentHigh = recentHigh[:10]
	}

	maxRisk := 0
	elevated := 0
	riskDistribution := map[string]int{
		storage.SeverityLow:    len(devices),
		storage.SeverityMedium: 0,
		storage.SeverityHigh:   0,
	}
	for _, d := range risks {
		if d.RiskScore > maxRisk {
			maxRisk = d.RiskScore
		}
		if d.RiskScore >= 30 || d.RiskLevel == storage.SeverityMedium || d.RiskLevel == storage.SeverityHigh {
			elevated++
		}
		if d.RiskScore >= 70 || d.RiskLevel == storage.SeverityHigh {
			riskDistribution[storage.SeverityHigh]++
			riskDistribution[storage.SeverityLow]--
		} else if d.RiskScore >= 30 || d.RiskLevel == storage.SeverityMedium {
			riskDistribution[storage.SeverityMedium]++
			riskDistribution[storage.SeverityLow]--
		}
	}
	if riskDistribution[storage.SeverityLow] < 0 {
		riskDistribution[storage.SeverityLow] = 0
	}

	topRisks := risks
	if len(topRisks) > 5 {
		topRisks = topRisks[:5]
	}

	res := SecuritySummaryResponse{
		ActiveAlertsBySeverity: counts,
		ActiveAlertsTotal:      len(active),
		MaxRiskScore:           maxRisk,
		ElevatedRiskDevices:    elevated,
		TotalDevices:           len(devices),
		RiskDistribution:       riskDistribution,
		DetectorStatus: map[string]string{
			"behavior_anomalies": "enabled",
			"ddos":               "enabled",
			"suricata":           configuredStatus(q.cfg.SuricataEvePath != ""),
			"unifi_siem":         configuredStatus(q.cfg.UniFiSyslogEnabled),
			"notifications":      configuredStatus(q.cfg.TelegramEnabled || q.cfg.SlackWebhookURL != "" || q.cfg.WebhookURL != ""),
		},
		DDoSThresholds: map[string]int{
			"pps":  q.cfg.DDoSThresholdPPS,
			"bps":  q.cfg.DDoSThresholdBPS,
			"fps":  q.cfg.DDoSThresholdFPS,
			"syn":  q.cfg.SYNFloodThresholdPPS,
			"udp":  q.cfg.UDPFloodThresholdPPS,
			"icmp": q.cfg.ICMPFloodThresholdPPS,
		},
		SuricataConfigured:     q.cfg.SuricataEvePath != "",
		NotificationConfigured: q.cfg.TelegramEnabled || q.cfg.SlackWebhookURL != "" || q.cfg.WebhookURL != "",
		UniFiConfigured:        q.cfg.UniFiSyslogEnabled,
		TopRiskDevices:         topRisks,
		RecentHighAlerts:       recentHigh,
	}
	if q.collector != nil {
		stats := q.collector.GetStats()
		res.Collector = &collectorHealthView{
			PacketsReceived: stats.PacketsReceived,
			PacketsDropped:  stats.PacketsDropped,
			DecodeErrors:    stats.DecodeErrors,
			QueueDepth:      stats.QueueDepth,
			Sources:         mapCollectorSources(stats.Sources),
		}
	}

	return res, nil
}

func mapCollectorSources(sources []collector.SourceStats) []collectorSourceHealth {
	if len(sources) == 0 {
		return nil
	}
	out := make([]collectorSourceHealth, 0, len(sources))
	for _, src := range sources {
		out = append(out, collectorSourceHealth{
			Kind:         src.Kind,
			ID:           src.ID,
			Enabled:      src.Enabled,
			Status:       src.Status,
			Port:         src.Port,
			Packets:      src.Packets,
			Drops:        src.Drops,
			DecodeErrors: src.DecodeErrors,
		})
	}
	return out
}

func (q securityQueryService) BuildTimeline(ctx context.Context, start, end time.Time, bucketSeconds int) ([]SecurityTimelineBucket, error) {
	active, err := q.deviceRepo.GetActiveAnomalies(ctx, start)
	if err != nil {
		return nil, err
	}

	merged := make(map[int64]*SecurityTimelineBucket)
	for _, a := range active {
		if a.CreatedAt.Before(start) || a.CreatedAt.After(end) {
			continue
		}
		bucketStart := (a.CreatedAt.Unix() / int64(bucketSeconds)) * int64(bucketSeconds)
		item, ok := merged[bucketStart]
		if !ok {
			item = &SecurityTimelineBucket{
				Timestamp: time.Unix(bucketStart, 0).UTC(),
				Counts: map[string]int{
					storage.SeverityCritical: 0,
					storage.SeverityHigh:     0,
					storage.SeverityMedium:   0,
					storage.SeverityLow:      0,
				},
			}
			merged[bucketStart] = item
		}
		severity := normalizeSeverity(a.Severity)
		item.Counts[severity]++
		item.Total++
	}

	keys := make([]int64, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	res := make([]SecurityTimelineBucket, 0, len(keys))
	for _, key := range keys {
		res = append(res, *merged[key])
	}
	return res, nil
}

func normalizeSeverity(severity string) string {
	switch severity {
	case storage.SeverityCritical, storage.SeverityHigh, storage.SeverityMedium, storage.SeverityLow:
		return severity
	default:
		return storage.SeverityLow
	}
}

func configuredStatus(ok bool) string {
	if ok {
		return "configured"
	}
	return "not_configured"
}

func sortAnomaliesNewestFirst(items []storage.Anomaly) {
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
}
