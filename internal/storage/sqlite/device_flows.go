package sqlite

import (
	"context"
	"fmt"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
)

// GetDeviceTrafficTimeSeries returns total traffic counters for a specific IP grouped into fixed-size bounded time buckets.
func (r *Repository) GetDeviceTrafficTimeSeries(ctx context.Context, ip string, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error) {
	dbs, err := r.GetShardsInRange(start, end)
	if err != nil {
		return nil, err
	}

	startUnix := start.Unix()
	endUnix := end.Unix()
	merged := make(map[int64]*flow.TrafficTimeBucket)

	for _, db := range dbs {
		rows, err := db.QueryContext(ctx, `
			SELECT (bucket_ts / ?) * ? AS bucket_start, SUM(bytes), SUM(packets), SUM(flows)
			FROM flow_aggregates
			WHERE bucket_ts >= ? AND bucket_ts <= ? AND (src_ip = ? OR dst_ip = ?)
			GROUP BY bucket_start
			ORDER BY bucket_start ASC
		`, bucketSeconds, bucketSeconds, startUnix, endUnix, ip, ip)
		if err != nil {
			return nil, fmt.Errorf("failed to query device traffic time series: %w", err)
		}

		for rows.Next() {
			var bucketStart int64
			var bytesVal, packetsVal, flowsVal uint64
			if err := rows.Scan(&bucketStart, &bytesVal, &packetsVal, &flowsVal); err != nil {
				rows.Close()
				return nil, fmt.Errorf("failed scanning device traffic time series: %w", err)
			}
			item, ok := merged[bucketStart]
			if !ok {
				item = &flow.TrafficTimeBucket{Timestamp: time.Unix(bucketStart, 0).UTC()}
				merged[bucketStart] = item
			}
			item.Bytes += bytesVal
			item.Packets += packetsVal
			item.Flows += flowsVal
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed iterating device traffic time series rows: %w", err)
		}
		rows.Close()
	}

	return sortTrafficBuckets(merged), nil
}

// GetDeviceTopPeers returns the top communicating peer IPs for a device sorted by byte volume.
func (r *Repository) GetDeviceTopPeers(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error) {
	dbs, err := r.GetShardsInRange(start, end)
	if err != nil {
		return nil, err
	}

	merged := make(map[string]*flow.TopResult)
	startUnix := start.Unix()
	endUnix := end.Unix()

	for _, db := range dbs {
		rows, err := db.QueryContext(ctx, `
			SELECT peer, SUM(bytes), SUM(packets), SUM(flows)
			FROM (
				SELECT dst_ip AS peer, bytes, packets, flows
				FROM flow_aggregates
				WHERE bucket_ts >= ? AND bucket_ts <= ? AND src_ip = ?
				UNION ALL
				SELECT src_ip AS peer, bytes, packets, flows
				FROM flow_aggregates
				WHERE bucket_ts >= ? AND bucket_ts <= ? AND dst_ip = ?
			)
			GROUP BY peer
		`, startUnix, endUnix, ip, startUnix, endUnix, ip)
		if err != nil {
			return nil, fmt.Errorf("failed to query device top peers: %w", err)
		}
		r.mergeRows(rows, merged)
	}

	return sortAndLimit(merged, limit), nil
}

// GetDeviceTopPorts returns the top destination/service ports for a device sorted by byte volume.
func (r *Repository) GetDeviceTopPorts(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error) {
	dbs, err := r.GetShardsInRange(start, end)
	if err != nil {
		return nil, err
	}

	merged := make(map[string]*flow.TopResult)
	startUnix := start.Unix()
	endUnix := end.Unix()

	for _, db := range dbs {
		rows, err := db.QueryContext(ctx, `
			SELECT dst_port, SUM(bytes), SUM(packets), SUM(flows)
			FROM flow_aggregates
			WHERE bucket_ts >= ? AND bucket_ts <= ? AND (src_ip = ? OR dst_ip = ?)
			GROUP BY dst_port
		`, startUnix, endUnix, ip, ip)
		if err != nil {
			return nil, fmt.Errorf("failed to query device top ports: %w", err)
		}
		r.mergeRows(rows, merged)
	}

	return sortAndLimit(merged, limit), nil
}

// GetDeviceBaselineSamples returns per-bucket aggregate samples for a source device.
func (r *Repository) GetDeviceBaselineSamples(ctx context.Context, ip string, start, end time.Time) ([]DeviceBaselineSample, error) {
	dbs, err := r.GetShardsInRange(start, end)
	if err != nil {
		return nil, err
	}

	startUnix := start.Unix()
	endUnix := end.Unix()
	var samples []DeviceBaselineSample

	for _, db := range dbs {
		rows, err := db.QueryContext(ctx, `
			SELECT SUM(bytes), SUM(packets), COUNT(DISTINCT dst_ip)
			FROM flow_aggregates
			WHERE src_ip = ? AND bucket_ts >= ? AND bucket_ts <= ?
			GROUP BY bucket_ts
		`, ip, startUnix, endUnix)
		if err != nil {
			return nil, fmt.Errorf("failed querying SQLite baseline samples: %w", err)
		}
		for rows.Next() {
			var sample DeviceBaselineSample
			if err := rows.Scan(&sample.Bytes, &sample.Packets, &sample.Peers); err != nil {
				rows.Close()
				return nil, fmt.Errorf("failed scanning SQLite baseline sample: %w", err)
			}
			samples = append(samples, sample)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed iterating SQLite baseline samples: %w", err)
		}
		rows.Close()
	}

	if samples == nil {
		samples = []DeviceBaselineSample{}
	}
	return samples, nil
}

// HasObservedDestination reports whether a source/destination pair exists in retained SQLite aggregate history.
func (r *Repository) HasObservedDestination(ctx context.Context, sourceIP, destinationIP string, start, end time.Time) (FlowHistoryResult, error) {
	return r.hasObservedFlowTuple(ctx, start, end, `
		SELECT COUNT(1)
		FROM flow_aggregates
		WHERE src_ip = ? AND dst_ip = ? AND bucket_ts >= ? AND bucket_ts <= ?
		LIMIT 1
	`, sourceIP, destinationIP)
}

// HasObservedDestinationPort reports whether a source/destination-port pair exists in retained SQLite aggregate history.
func (r *Repository) HasObservedDestinationPort(ctx context.Context, sourceIP string, destinationPort int, start, end time.Time) (FlowHistoryResult, error) {
	return r.hasObservedFlowTuple(ctx, start, end, `
		SELECT COUNT(1)
		FROM flow_aggregates
		WHERE src_ip = ? AND dst_port = ? AND bucket_ts >= ? AND bucket_ts <= ?
		LIMIT 1
	`, sourceIP, destinationPort)
}

func (r *Repository) hasObservedFlowTuple(ctx context.Context, start, end time.Time, query string, args ...interface{}) (FlowHistoryResult, error) {
	dbs, err := r.GetShardsInRange(start, end)
	if err != nil {
		return FlowHistoryResult{}, err
	}
	if len(dbs) == 0 {
		return FlowHistoryResult{}, nil
	}

	startUnix := start.Unix()
	endUnix := end.Unix()
	queryArgs := append(args, startUnix, endUnix)
	var history FlowHistoryResult
	for _, db := range dbs {
		var sourceBuckets int
		var firstSeenUnix int64
		if err := db.QueryRowContext(ctx, `
			SELECT COUNT(DISTINCT bucket_ts), COALESCE(MIN(bucket_ts), 0)
			FROM flow_aggregates
			WHERE src_ip = ? AND bucket_ts >= ? AND bucket_ts <= ?
		`, args[0], startUnix, endUnix).Scan(&sourceBuckets, &firstSeenUnix); err != nil {
			return FlowHistoryResult{}, fmt.Errorf("failed querying SQLite source history: %w", err)
		}
		history.SourceBuckets += sourceBuckets
		if firstSeenUnix > 0 && (history.SourceFirstSeen.IsZero() || firstSeenUnix < history.SourceFirstSeen.Unix()) {
			history.SourceFirstSeen = time.Unix(firstSeenUnix, 0).UTC()
		}

		var count int
		if err := db.QueryRowContext(ctx, query, queryArgs...).Scan(&count); err != nil {
			return FlowHistoryResult{}, fmt.Errorf("failed querying SQLite flow history: %w", err)
		}
		if count > 0 {
			history.Observed = true
		}
	}
	return history, nil
}
