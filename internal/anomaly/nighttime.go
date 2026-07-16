package anomaly

import (
	"context"
	"fmt"
	"sort"
	"time"
)

func (e *AnomalyEngine) checkNighttime(ctx context.Context, ip string, metrics *deviceMetrics) {
	if metrics.timestamp.IsZero() {
		return
	}
	localTime := metrics.timestamp.In(e.location)
	hour := localTime.Hour()
	isNight := hour >= nightStartHour && hour < nightEndHour
	isDaytime := hour >= daytimeStartHour && hour < daytimeEndHour
	if !isNight && !isDaytime {
		return
	}
	significant := metrics.bytes >= nightMinBytes ||
		metrics.packets >= nightMinPackets ||
		len(metrics.dstIPs) >= nightMinDestinations
	if !significant {
		return
	}

	daytimeWindows, priorNightWindows := e.observeActivity(ip, metrics.timestamp, isDaytime, isNight)
	if !isNight ||
		daytimeWindows < nightMinDaytimeWindows ||
		priorNightWindows >= nightExpectedWindows {
		return
	}

	reason := fmt.Sprintf(
		"what happened: device generated significant traffic at %s during the configured nighttime window %02d:00-%02d:00; why unusual: its learned in-memory activity profile contains %d distinct daytime windows and only %d prior nighttime windows; baseline used: at least %d daytime windows with fewer than %d prior nighttime windows; current value: %d bytes, %d packets, and %d unique destinations; expected value: no significant activity during nighttime or an explicitly approved overnight schedule; confidence: medium; recommended next check: verify the device owner, scheduled jobs, remote sessions, update tasks, and destination activity",
		localTime.Format("15:04 MST"), nightStartHour, nightEndHour,
		daytimeWindows, priorNightWindows, nightMinDaytimeWindows, nightExpectedWindows,
		metrics.bytes, metrics.packets, len(metrics.dstIPs),
	)
	e.triggerAlert(ctx, ip, "NIGHTTIME_TRAFFIC", reason, "medium")
}

func (e *AnomalyEngine) observeActivity(ip string, timestamp time.Time, isDaytime, isNight bool) (int, int) {
	e.activityMu.Lock()
	defer e.activityMu.Unlock()

	if timestamp.After(e.activityWatermark) {
		if e.activityWatermark.IsZero() || timestamp.Sub(e.activityWatermark) >= 1*time.Minute {
			cutoff := timestamp.Add(-nightStateRetention)
			for deviceIP, profile := range e.activityProfiles {
				if profile.lastSeen.Before(cutoff) {
					delete(e.activityProfiles, deviceIP)
				}
			}
		}
		e.activityWatermark = timestamp
	}

	profile, exists := e.activityProfiles[ip]
	if !exists {
		if len(e.activityProfiles) >= nightMaxDevices {
			return 0, 0
		}
		profile = &activityProfile{}
		e.activityProfiles[ip] = profile
	}
	profile.lastSeen = timestamp
	bucket := timestamp.Truncate(time.Minute).Unix()
	priorNightWindows := len(profile.nighttimeBuckets)
	if isDaytime {
		profile.daytimeBuckets = appendUniqueBucket(profile.daytimeBuckets, bucket, nightMinDaytimeWindows)
	}
	if isNight {
		profile.nighttimeBuckets = appendUniqueBucket(profile.nighttimeBuckets, bucket, nightExpectedWindows)
	}
	return len(profile.daytimeBuckets), priorNightWindows
}

func appendUniqueBucket(buckets []int64, bucket int64, limit int) []int64 {
	index := sort.Search(len(buckets), func(i int) bool { return buckets[i] >= bucket })
	if index < len(buckets) && buckets[index] == bucket {
		return buckets
	}
	buckets = append(buckets, 0)
	copy(buckets[index+1:], buckets[index:])
	buckets[index] = bucket
	if len(buckets) > limit {
		return buckets[len(buckets)-limit:]
	}
	return buckets
}
