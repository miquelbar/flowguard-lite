package anomaly

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/flowguard/flowguard/internal/baseline"
	"github.com/flowguard/flowguard/internal/flow"
	"github.com/flowguard/flowguard/internal/storage"
)

type deviceMetrics struct {
	bytes    uint64
	packets  uint64
	dstIPs   map[string]bool
	dstPorts map[int]bool
}

// AnomalyEngine processes aggregated flows to detect traffic spikes, new ports, and new destinations.
type AnomalyEngine struct {
	repo           storage.DeviceRepository
	logger         *slog.Logger
	baselineEngine *baseline.BaselineEngine

	// Local network subnet matchers (to identify local source devices)
	localSubnets []*net.IPNet

	// In-memory cache to deduplicate alerts triggered in the last 15 minutes
	mu                sync.Mutex
	alertDeduplicator map[string]time.Time
}

// NewAnomalyEngine instantiates a new AnomalyEngine.
func NewAnomalyEngine(
	repo storage.DeviceRepository,
	logger *slog.Logger,
	baseEngine *baseline.BaselineEngine,
	subnets []string,
) *AnomalyEngine {
	var parsed []*net.IPNet
	for _, cidr := range subnets {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			logger.Error("Failed to parse CIDR configured for local subnet in anomaly engine",
				slog.String("cidr", cidr),
				slog.String("error", err.Error()))
			continue
		}
		parsed = append(parsed, ipNet)
	}

	return &AnomalyEngine{
		repo:              repo,
		logger:            logger,
		baselineEngine:    baseEngine,
		localSubnets:      parsed,
		alertDeduplicator: make(map[string]time.Time),
	}
}

// AnalyzeBatch inspects a flushed batch of 1-minute flow events to detect anomalies.
func (e *AnomalyEngine) AnalyzeBatch(ctx context.Context, flowRepo storage.FlowRepository, batch []flow.FlowEvent) {
	if len(batch) == 0 {
		return
	}

	// 1. Group metrics by local source IP
	metrics := make(map[string]*deviceMetrics)

	for _, f := range batch {
		if !e.isLocalIP(f.SrcIP) {
			continue
		}

		m, ok := metrics[f.SrcIP]
		if !ok {
			m = &deviceMetrics{
				dstIPs:   make(map[string]bool),
				dstPorts: make(map[int]bool),
			}
			metrics[f.SrcIP] = m
		}

		m.bytes += f.Bytes
		m.packets += f.Packets
		m.dstIPs[f.DstIP] = true
		m.dstPorts[f.DstPort] = true
	}

	// 2. Process each local device
	for ip, m := range metrics {
		// A. Check abnormal volume spike
		if ok, reason := e.baselineEngine.IsAnomaly(ip, m.bytes, m.packets, len(m.dstIPs)); ok {
			e.triggerAlert(ctx, ip, "TRAFFIC_SPIKE", reason, "high")
		}

		// B. Check for new destination IPs and Ports
		// To run fast, we execute historical queries on the database shards
		sqliteRepo, ok := flowRepo.(*storage.SQLiteRepository)
		if !ok {
			continue
		}

		e.checkNewDestinations(ctx, sqliteRepo, ip, m)
	}
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

// checkNewDestinations queries historical databases to see if IPs or Ports are new.
func (e *AnomalyEngine) checkNewDestinations(ctx context.Context, repo *storage.SQLiteRepository, ip string, m *deviceMetrics) {
	// Look back 7 days
	end := time.Now()
	start := end.AddDate(0, 0, -7)

	dbs, err := repo.GetShardsInRange(start, end)
	if err != nil {
		e.logger.Error("Failed to query historical shards for new destination checks", slog.String("error", err.Error()))
		return
	}

	// Check new destination IPs
	for dstIP := range m.dstIPs {
		// Skip checking if destination IP is private local to focus on external peers
		if e.isLocalIP(dstIP) {
			continue
		}

		found := false
		for _, db := range dbs {
			var count int
			err := db.QueryRowContext(ctx, `
				SELECT COUNT(1) FROM flow_aggregates WHERE src_ip = ? AND dst_ip = ? LIMIT 1
			`, ip, dstIP).Scan(&count)
			if err == nil && count > 0 {
				found = true
				break
			}
		}

		if !found && len(dbs) > 0 {
			reason := fmt.Sprintf("device contacted external destination IP %s for the first time in the past 7 days", dstIP)
			e.triggerAlert(ctx, ip, "NEW_DESTINATION", reason, "medium")
		}
	}

	// Check new destination ports
	for dstPort := range m.dstPorts {
		found := false
		for _, db := range dbs {
			var count int
			err := db.QueryRowContext(ctx, `
				SELECT COUNT(1) FROM flow_aggregates WHERE src_ip = ? AND dst_port = ? LIMIT 1
			`, ip, dstPort).Scan(&count)
			if err == nil && count > 0 {
				found = true
				break
			}
		}

		if !found && len(dbs) > 0 {
			reason := fmt.Sprintf("device contacted destination port %d for the first time in the past 7 days", dstPort)
			e.triggerAlert(ctx, ip, "NEW_PORT", reason, "low")
		}
	}
}

// triggerAlert records the anomaly in database if not deduplicated.
func (e *AnomalyEngine) triggerAlert(ctx context.Context, ip string, alertType string, reason string, severity string) {
	e.mu.Lock()
	dedupKey := fmt.Sprintf("%s|%s", ip, alertType)
	lastTriggered, exists := e.alertDeduplicator[dedupKey]
	now := time.Now()

	// Deduplicate: ignore same alert type for same IP if triggered in the last 15 minutes
	if exists && now.Sub(lastTriggered) < 15*time.Minute {
		e.mu.Unlock()
		return
	}

	e.alertDeduplicator[dedupKey] = now
	e.mu.Unlock()

	e.logger.Warn("Triggering behavioral anomaly alert",
		slog.String("ip", ip),
		slog.String("type", alertType),
		slog.String("reason", reason))

	anom := &storage.Anomaly{
		IP:          ip,
		Type:        alertType,
		Description: reason,
		Severity:    severity,
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Write to database
	go func() {
		dbCtx, dbCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer dbCancel()
		if err := e.repo.SaveAnomaly(dbCtx, anom); err != nil {
			e.logger.Error("Failed to save triggered anomaly into database", slog.String("error", err.Error()))
		}
	}()
}
