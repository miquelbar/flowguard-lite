package anomaly

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
)

func (e *AnomalyEngine) checkBeaconing(ctx context.Context, batch []flow.FlowEvent) {
	if len(batch) == 0 {
		return
	}
	controls := e.detectionControlsSnapshot()
	for _, event := range batch {
		if event.Timestamp.IsZero() ||
			!e.isLocalIP(event.SrcIP) ||
			e.isLocalIP(event.DstIP) ||
			!isFanoutDestination(event.DstIP) ||
			event.DstPort <= 0 ||
			event.Packets == 0 ||
			event.Packets > beaconMaxPackets ||
			event.Bytes > beaconMaxBytes {
			continue
		}

		key := beaconKey{
			srcIP: event.SrcIP, dstIP: event.DstIP,
			dstPort: event.DstPort, protocol: event.Protocol,
		}
		period, jitter, observations, detected := e.observeBeacon(key, event.Timestamp.UTC(), controls)
		if !detected {
			continue
		}

		reason := fmt.Sprintf(
			"what happened: device contacted %s:%d over protocol %d on a repeating schedule; why unusual: low-volume communication repeated with stable timing can indicate command-and-control beaconing; baseline used: %d recent observations with maximum tolerated jitter of %.0f%% or %s; current value: %d observations at an average interval of %s with %.1f%% jitter; expected value: irregular timing or an explicitly approved scheduled service; confidence: high; recommended next check: identify the owning process and verify the destination, certificate, DNS history, and scheduled-task configuration",
			key.dstIP, key.dstPort, key.protocol,
			controls.beaconMinObservations, beaconJitterRatio*100, beaconJitterFloor,
			observations, period.Round(time.Second), jitter*100,
		)
		e.triggerAlert(ctx, key.srcIP, "BEACONING", reason, "medium")
	}
}

func (e *AnomalyEngine) observeBeacon(key beaconKey, timestamp time.Time, controls detectionControls) (time.Duration, float64, int, bool) {
	e.beaconMu.Lock()
	defer e.beaconMu.Unlock()

	if timestamp.After(e.beaconWatermark) {
		if e.beaconWatermark.IsZero() || timestamp.Sub(e.beaconWatermark) >= 1*time.Minute {
			e.pruneBeaconsLocked(timestamp.Add(-beaconStateRetention))
		}
		e.beaconWatermark = timestamp
	}

	series, exists := e.beacons[key]
	if !exists {
		if len(e.beacons) >= beaconMaxSeries {
			return 0, 0, 0, false
		}
		series = &beaconSeries{}
		e.beacons[key] = series
	}

	index := sort.Search(len(series.observations), func(i int) bool {
		return !series.observations[i].Before(timestamp)
	})
	if index < len(series.observations) && series.observations[index].Equal(timestamp) {
		return 0, 0, len(series.observations), false
	}
	series.observations = append(series.observations, time.Time{})
	copy(series.observations[index+1:], series.observations[index:])
	series.observations[index] = timestamp
	if len(series.observations) > beaconMaxObservations {
		series.observations = series.observations[len(series.observations)-beaconMaxObservations:]
	}
	series.lastSeen = series.observations[len(series.observations)-1]

	minObservations := controls.beaconMinObservations
	if minObservations <= 0 {
		minObservations = beaconMinObservations
	}
	minInterval := controls.beaconMinInterval
	if minInterval <= 0 {
		minInterval = beaconMinInterval
	}

	if len(series.observations) < minObservations {
		return 0, 0, len(series.observations), false
	}
	recent := series.observations[len(series.observations)-minObservations:]
	intervals := make([]time.Duration, 0, len(recent)-1)
	var total time.Duration
	for i := 1; i < len(recent); i++ {
		interval := recent[i].Sub(recent[i-1])
		if interval < minInterval || interval > beaconMaxInterval {
			return 0, 0, len(recent), false
		}
		intervals = append(intervals, interval)
		total += interval
	}

	mean := total / time.Duration(len(intervals))
	tolerance := time.Duration(float64(mean) * beaconJitterRatio)
	if tolerance < beaconJitterFloor {
		tolerance = beaconJitterFloor
	}
	var maxDeviation time.Duration
	for _, interval := range intervals {
		deviation := interval - mean
		if deviation < 0 {
			deviation = -deviation
		}
		if deviation > maxDeviation {
			maxDeviation = deviation
		}
	}
	if maxDeviation > tolerance {
		return mean, float64(maxDeviation) / float64(mean), len(recent), false
	}
	return mean, float64(maxDeviation) / float64(mean), len(recent), true
}

func (e *AnomalyEngine) pruneBeaconsLocked(cutoff time.Time) {
	for key, series := range e.beacons {
		if series.lastSeen.Before(cutoff) {
			delete(e.beacons, key)
		}
	}
}
