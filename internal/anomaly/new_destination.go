package anomaly

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/storage"
)

const minNewDestinationHistoryBuckets = 12

// checkNewDestinations queries retained aggregate history to see if IPs or Ports are new.
func (e *AnomalyEngine) checkNewDestinations(ctx context.Context, repo storage.FlowHistoryRepository, ip string, m *deviceMetrics) {
	// Look back 7 days
	end := m.timestamp
	if end.IsZero() {
		end = time.Now()
	} else {
		end = end.Add(-time.Second)
	}
	start := end.AddDate(0, 0, -7)

	// Check new destination IPs
	for dstIP := range m.dstIPs {
		// Skip checking if destination IP is private local to focus on external peers
		if e.isLocalIP(dstIP) {
			continue
		}

		result, err := repo.HasObservedDestination(ctx, ip, dstIP, start, end)
		if err != nil {
			e.logger.Error("Failed to query retained flow history for new destination check",
				slog.String("ip", ip),
				slog.String("destination_ip", dstIP),
				slog.String("error", err.Error()))
			continue
		}

		if !hasMatureNewDestinationHistory(result, e.detectionControlsSnapshot().newDestinationMinHistoryBuckets) {
			continue
		}

		if !result.Observed {
			reason := fmt.Sprintf(
				"what happened: device contacted external destination IP %s for the first time in the past 7 days; why unusual: the destination was absent from the device's retained aggregate history; baseline used: 7 days of stored flow aggregates for this source/destination pair; current value: destination %s present in this one-minute batch; expected value: destination previously observed or explicitly approved; confidence: medium; recommended next check: verify DNS, certificate, owner, and whether the destination belongs to a new approved service",
				dstIP, dstIP,
			)
			e.triggerAlertWithDestination(ctx, ip, dstIP, "NEW_DESTINATION", reason, "medium")
		}
	}

	// Check new destination ports
	for dstPort := range m.dstPorts {
		result, err := repo.HasObservedDestinationPort(ctx, ip, dstPort, start, end)
		if err != nil {
			e.logger.Error("Failed to query retained flow history for new port check",
				slog.String("ip", ip),
				slog.Int("destination_port", dstPort),
				slog.String("error", err.Error()))
			continue
		}

		if !hasMatureNewDestinationHistory(result, e.detectionControlsSnapshot().newDestinationMinHistoryBuckets) {
			continue
		}

		if !result.Observed {
			dstIP := m.dstIPByPort[dstPort]
			destinationContext := "an observed destination"
			if dstIP != "" {
				destinationContext = fmt.Sprintf("destination %s", dstIP)
			}
			reason := fmt.Sprintf(
				"what happened: device contacted %s on destination port %d for the first time in the past 7 days; why unusual: the port was absent from the device's retained aggregate history; baseline used: 7 days of stored flow aggregates for this source/port pair; current value: %s port %d present in this one-minute batch; expected value: port previously observed or explicitly approved; confidence: low; recommended next check: verify the remote host, application protocol, and whether a new service, update, or admin workflow introduced this port",
				destinationContext, dstPort, destinationContext, dstPort,
			)
			e.triggerAlertWithDestination(ctx, ip, dstIP, "NEW_PORT", reason, "low")
		}
	}
}

func hasMatureNewDestinationHistory(result storage.FlowHistoryResult, minBuckets int) bool {
	if minBuckets <= 0 {
		minBuckets = minNewDestinationHistoryBuckets
	}
	return result.SourceBuckets >= minBuckets
}
