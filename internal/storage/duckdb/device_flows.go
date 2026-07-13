package duckdb

import (
	"context"
	"fmt"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
)

// GetDeviceTrafficTimeSeries returns total traffic counters for a specific IP grouped into fixed-size bounded time buckets.
func (r *Repository) GetDeviceTrafficTimeSeries(ctx context.Context, ip string, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT CAST(FLOOR(bucket_ts / ?) * ? AS BIGINT) AS bucket_start,
		       SUM(bytes), SUM(packets), SUM(flows)
		FROM flow_aggregates
		WHERE bucket_ts >= ? AND bucket_ts <= ? AND (src_ip = ? OR dst_ip = ?)
		GROUP BY bucket_start
		ORDER BY bucket_start ASC
	`, bucketSeconds, bucketSeconds, start.Unix(), end.Unix(), ip, ip)
	if err != nil {
		return nil, fmt.Errorf("failed querying DuckDB device traffic time series: %w", err)
	}
	defer rows.Close()

	var results []flow.TrafficTimeBucket
	for rows.Next() {
		var bucketStart int64
		var item flow.TrafficTimeBucket
		if err := rows.Scan(&bucketStart, &item.Bytes, &item.Packets, &item.Flows); err != nil {
			return nil, fmt.Errorf("failed scanning DuckDB device traffic time series: %w", err)
		}
		item.Timestamp = time.Unix(bucketStart, 0).UTC()
		results = append(results, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating DuckDB device traffic time series rows: %w", err)
	}
	if results == nil {
		results = []flow.TrafficTimeBucket{}
	}
	return results, nil
}

// GetDeviceTopPeers returns the top communicating peer IPs for a device sorted by byte volume.
func (r *Repository) GetDeviceTopPeers(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT peer, SUM(bytes) as total_bytes, SUM(packets), SUM(flows)
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
		ORDER BY total_bytes DESC
		LIMIT ?
	`, start.Unix(), end.Unix(), ip, start.Unix(), end.Unix(), ip, limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying DuckDB device top peers: %w", err)
	}
	defer rows.Close()

	var results []flow.TopResult
	for rows.Next() {
		var tr flow.TopResult
		if err := rows.Scan(&tr.Key, &tr.Bytes, &tr.Packets, &tr.Flows); err != nil {
			return nil, fmt.Errorf("failed scanning DuckDB device top peers: %w", err)
		}
		results = append(results, tr)
	}
	if results == nil {
		results = []flow.TopResult{}
	}
	return results, nil
}

// GetDeviceTopPorts returns the top destination/service ports for a device sorted by byte volume.
func (r *Repository) GetDeviceTopPorts(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT CAST(dst_port AS VARCHAR) AS port, SUM(bytes) as total_bytes, SUM(packets), SUM(flows)
		FROM flow_aggregates
		WHERE bucket_ts >= ? AND bucket_ts <= ? AND (src_ip = ? OR dst_ip = ?)
		GROUP BY port
		ORDER BY total_bytes DESC
		LIMIT ?
	`, start.Unix(), end.Unix(), ip, ip, limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying DuckDB device top ports: %w", err)
	}
	defer rows.Close()

	var results []flow.TopResult
	for rows.Next() {
		var tr flow.TopResult
		if err := rows.Scan(&tr.Key, &tr.Bytes, &tr.Packets, &tr.Flows); err != nil {
			return nil, fmt.Errorf("failed scanning DuckDB device top ports: %w", err)
		}
		results = append(results, tr)
	}
	if results == nil {
		results = []flow.TopResult{}
	}
	return results, nil
}

// GetDeviceBaselineSamples returns per-bucket aggregate samples for a source device.
func (r *Repository) GetDeviceBaselineSamples(ctx context.Context, ip string, start, end time.Time) ([]DeviceBaselineSample, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT SUM(bytes), SUM(packets), COUNT(DISTINCT dst_ip)
		FROM flow_aggregates
		WHERE src_ip = ? AND bucket_ts >= ? AND bucket_ts <= ?
		GROUP BY bucket_ts
	`, ip, start.Unix(), end.Unix())
	if err != nil {
		return nil, fmt.Errorf("failed querying DuckDB baseline samples: %w", err)
	}
	defer rows.Close()

	var samples []DeviceBaselineSample
	for rows.Next() {
		var sample DeviceBaselineSample
		if err := rows.Scan(&sample.Bytes, &sample.Packets, &sample.Peers); err != nil {
			return nil, fmt.Errorf("failed scanning DuckDB baseline sample: %w", err)
		}
		samples = append(samples, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating DuckDB baseline samples: %w", err)
	}
	if samples == nil {
		samples = []DeviceBaselineSample{}
	}
	return samples, nil
}

// HasObservedDestination reports whether a source/destination pair exists in retained DuckDB aggregate history.
func (r *Repository) HasObservedDestination(ctx context.Context, sourceIP, destinationIP string, start, end time.Time) (FlowHistoryResult, error) {
	return r.hasObservedFlowTuple(ctx, start, end, `
		SELECT COUNT(1)
		FROM flow_aggregates
		WHERE src_ip = ? AND dst_ip = ? AND bucket_ts >= ? AND bucket_ts <= ?
	`, sourceIP, destinationIP)
}

// HasObservedDestinationPort reports whether a source/destination-port pair exists in retained DuckDB aggregate history.
func (r *Repository) HasObservedDestinationPort(ctx context.Context, sourceIP string, destinationPort int, start, end time.Time) (FlowHistoryResult, error) {
	return r.hasObservedFlowTuple(ctx, start, end, `
		SELECT COUNT(1)
		FROM flow_aggregates
		WHERE src_ip = ? AND dst_port = ? AND bucket_ts >= ? AND bucket_ts <= ?
	`, sourceIP, destinationPort)
}

func (r *Repository) hasObservedFlowTuple(ctx context.Context, start, end time.Time, query string, args ...interface{}) (FlowHistoryResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var historyCount int
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(1)
		FROM flow_aggregates
		WHERE bucket_ts >= ? AND bucket_ts <= ?
	`, start.Unix(), end.Unix()).Scan(&historyCount); err != nil {
		return FlowHistoryResult{}, fmt.Errorf("failed querying DuckDB history availability: %w", err)
	}
	if historyCount == 0 {
		return FlowHistoryResult{}, nil
	}

	queryArgs := append(args, start.Unix(), end.Unix())
	var count int
	if err := r.db.QueryRowContext(ctx, query, queryArgs...).Scan(&count); err != nil {
		return FlowHistoryResult{}, fmt.Errorf("failed querying DuckDB flow history: %w", err)
	}
	return FlowHistoryResult{Observed: count > 0, HistoryAvailable: true}, nil
}
