package anomaly

import (
	"context"
	"fmt"
	"math"
)

func (e *AnomalyEngine) checkFanout(ctx context.Context, ip string, m *deviceMetrics) {
	destinationCount := len(m.dstIPs)
	destinationLimit := destinationFanoutMin
	baselineDescription := fmt.Sprintf("absolute minimum of %d unique destinations per one-minute window", destinationFanoutMin)
	confidence := "medium"

	if b := e.baselineEngine.GetCachedBaseline(ip); b != nil {
		statisticalLimit := int(math.Ceil(b.MeanPeers + 3*b.StdDevPeers))
		if statisticalLimit > destinationLimit {
			destinationLimit = statisticalLimit
		}
		if destinationLimit > destinationFanoutMaxLimit {
			destinationLimit = destinationFanoutMaxLimit
		}
		baselineDescription = fmt.Sprintf(
			"device baseline mean %.1f plus 3 standard deviations (%.1f), with threshold %d",
			b.MeanPeers, b.StdDevPeers, destinationLimit,
		)
		confidence = "high"
	}

	if destinationCount >= destinationLimit &&
		m.packets <= uint64(destinationCount*maxScanPacketsPerTarget) {
		current := fmt.Sprintf("%d unique destinations", destinationCount)
		if m.dstIPsTruncated {
			current = fmt.Sprintf("at least %d unique destinations", destinationCount)
		}
		reason := fmt.Sprintf(
			"what happened: device contacted %s in one minute; why unusual: broad low-density fan-out can indicate horizontal scanning; baseline used: %s; current value: %s and %d packets; expected value: fewer than %d unique destinations; confidence: %s; recommended next check: review the destination list and verify whether discovery or inventory software was expected",
			current, baselineDescription, current, m.packets, destinationLimit, confidence,
		)
		e.triggerAlert(ctx, ip, "DESTINATION_FANOUT", reason, "high")
	}

	target, portCount, packetCount := highestPortFanout(m)
	if portCount >= portFanoutMin &&
		packetCount <= uint64(portCount*maxScanPacketsPerTarget) {
		reason := fmt.Sprintf(
			"what happened: device contacted %d unique destination ports on %s in one minute; why unusual: broad low-density port fan-out can indicate vertical port scanning; baseline used: absolute minimum of %d unique ports per destination per one-minute window; current value: %d unique ports and %d packets; expected value: fewer than %d unique ports on one destination; confidence: medium; recommended next check: inspect the target service inventory and confirm whether an authorized vulnerability scan was running",
			portCount, target, portFanoutMin, portCount, packetCount, portFanoutMin,
		)
		e.triggerAlert(ctx, ip, "PORT_FANOUT", reason, "high")
	}
}

func highestPortFanout(m *deviceMetrics) (target string, portCount int, packetCount uint64) {
	for destination, ports := range m.portsByDestination {
		count := len(ports)
		if count > portCount || (count == portCount && count > 0 && (target == "" || destination < target)) {
			target = destination
			portCount = count
			packetCount = m.packetsByDestination[destination]
		}
	}
	return target, portCount, packetCount
}
