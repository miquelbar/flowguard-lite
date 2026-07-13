package flowquery

import (
	"sort"

	"github.com/miquelbar/flowguard-lite/internal/flow"
)

// SortAndLimit orders top-result maps by bytes descending and applies the requested limit.
func SortAndLimit(m map[string]*flow.TopResult, limit int) []flow.TopResult {
	if len(m) == 0 {
		return []flow.TopResult{}
	}

	slice := make([]flow.TopResult, 0, len(m))
	for _, val := range m {
		slice = append(slice, *val)
	}

	sort.Slice(slice, func(i, j int) bool {
		return slice[i].Bytes > slice[j].Bytes
	})

	if len(slice) > limit {
		return slice[:limit]
	}
	return slice
}

// SortTrafficBuckets orders time buckets by ascending bucket timestamp.
func SortTrafficBuckets(m map[int64]*flow.TrafficTimeBucket) []flow.TrafficTimeBucket {
	if len(m) == 0 {
		return []flow.TrafficTimeBucket{}
	}
	keys := make([]int64, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	results := make([]flow.TrafficTimeBucket, 0, len(keys))
	for _, key := range keys {
		results = append(results, *m[key])
	}
	return results
}

// SortHeatmapCells returns deterministic heatmap output ordered by IP and hour.
func SortHeatmapCells(m map[string]*flow.DeviceHeatmapCell) []flow.DeviceHeatmapCell {
	if len(m) == 0 {
		return []flow.DeviceHeatmapCell{}
	}
	results := make([]flow.DeviceHeatmapCell, 0, len(m))
	for _, val := range m {
		results = append(results, *val)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].IP == results[j].IP {
			return results[i].Hour < results[j].Hour
		}
		return results[i].IP < results[j].IP
	})
	return results
}
