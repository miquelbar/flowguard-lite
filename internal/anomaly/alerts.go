package anomaly

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/storage"
)

// triggerAlert records the anomaly in database if not deduplicated.
func (e *AnomalyEngine) triggerAlert(ctx context.Context, ip string, alertType string, reason string, severity string) {
	e.triggerAlertWithDestination(ctx, ip, "", alertType, reason, severity)
}

func (e *AnomalyEngine) triggerAlertWithDestination(ctx context.Context, ip string, destinationIP string, alertType string, reason string, severity string) {
	if e.alertSuppressed(ip, alertType) {
		return
	}

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
		IP:            ip,
		DestinationIP: destinationIP,
		Type:          alertType,
		Description:   reason,
		Severity:      severity,
		Status:        "active",
		CreatedAt:     now,
		UpdatedAt:     now,
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

func (e *AnomalyEngine) alertSuppressed(ip string, alertType string) bool {
	e.controlsMu.RLock()
	defer e.controlsMu.RUnlock()

	for disabledType := range e.controls.disabledTypes {
		if strings.EqualFold(disabledType, alertType) {
			return true
		}
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	for _, subnet := range e.controls.mutedSubnets {
		if subnet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func (e *AnomalyEngine) detectionControlsSnapshot() detectionControls {
	e.controlsMu.RLock()
	defer e.controlsMu.RUnlock()
	controls := e.controls
	controls.disabledTypes = nil
	controls.mutedSubnets = nil
	return controls
}
