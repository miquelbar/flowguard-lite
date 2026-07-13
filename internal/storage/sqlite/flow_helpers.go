package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/storage/flowquery"
)

// Helper: Merge raw SQL query rows into a map of keys.
func (r *Repository) mergeRows(rows *sql.Rows, merged map[string]*flow.TopResult) {
	defer rows.Close()
	for rows.Next() {
		var keyRaw interface{}
		var bytesVal, packetsVal, flowsVal uint64

		if err := rows.Scan(&keyRaw, &bytesVal, &packetsVal, &flowsVal); err != nil {
			r.logger.Warn("Failed scanning query row", slog.String("error", err.Error()))
			continue
		}

		var key string
		switch v := keyRaw.(type) {
		case string:
			key = v
		case int64:
			key = strconv.FormatInt(v, 10)
		default:
			key = fmt.Sprintf("%v", keyRaw)
		}

		if item, ok := merged[key]; ok {
			item.Bytes += bytesVal
			item.Packets += packetsVal
			item.Flows += flowsVal
		} else {
			merged[key] = &flow.TopResult{
				Key:     key,
				Bytes:   bytesVal,
				Packets: packetsVal,
				Flows:   flowsVal,
			}
		}
	}
}

// Helper: Sort top map by bytes descending and limit results.
func sortAndLimit(m map[string]*flow.TopResult, limit int) []flow.TopResult {
	return flowquery.SortAndLimit(m, limit)
}

func (r *Repository) filterTopResultsToKnownDevices(ctx context.Context, merged map[string]*flow.TopResult) {
	devices, err := r.ListDevices(ctx)
	if err != nil || len(devices) == 0 {
		return
	}
	allowed := make(map[string]struct{}, len(devices))
	for _, d := range devices {
		allowed[d.IP] = struct{}{}
	}
	for key := range merged {
		if _, ok := allowed[key]; !ok {
			delete(merged, key)
		}
	}
}

func sortTrafficBuckets(m map[int64]*flow.TrafficTimeBucket) []flow.TrafficTimeBucket {
	return flowquery.SortTrafficBuckets(m)
}

func sortHeatmapCells(m map[string]*flow.DeviceHeatmapCell) []flow.DeviceHeatmapCell {
	return flowquery.SortHeatmapCells(m)
}
