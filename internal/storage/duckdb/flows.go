package duckdb

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/storage/flowquery"
)

func (r *Repository) SaveAggregates(ctx context.Context, ts time.Time, aggregates []flow.FlowEvent) error {
	if len(aggregates) == 0 {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin DuckDB write transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO flow_aggregates (
			bucket_ts, collector_kind, collector_id, src_ip, dst_ip, dst_port, protocol, bytes, packets, flows
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (bucket_ts, collector_kind, collector_id, src_ip, dst_ip, dst_port, protocol) DO UPDATE SET
			bytes = bytes + excluded.bytes,
			packets = packets + excluded.packets,
			flows = flows + excluded.flows
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare DuckDB aggregates stmt: %w", err)
	}
	defer stmt.Close()

	bucketUnix := ts.Unix()
	for _, agg := range aggregates {
		collectorKind := flow.NormalizeCollectorKind(agg.CollectorKind)
		collectorID := flow.NormalizeCollectorID(agg.CollectorID, collectorKind, agg.ExporterIP)
		_, err = stmt.ExecContext(ctx,
			bucketUnix,
			collectorKind,
			collectorID,
			agg.SrcIP,
			agg.DstIP,
			agg.DstPort,
			agg.Protocol,
			agg.Bytes,
			agg.Packets,
			1,
		)
		if err != nil {
			return fmt.Errorf("failed executing DuckDB flow aggregate write: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit DuckDB aggregates: %w", err)
	}
	return nil
}

// GetTopSources returns source IPs with the highest bytes volume.
func (r *Repository) GetTopSources(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT src_ip, SUM(bytes), SUM(packets), SUM(flows)
		FROM flow_aggregates
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		GROUP BY src_ip
		ORDER BY SUM(bytes) DESC
		LIMIT ?
	`, start.Unix(), end.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying DuckDB top sources: %w", err)
	}
	defer rows.Close()

	var results []flow.TopResult
	for rows.Next() {
		var tr flow.TopResult
		if err := rows.Scan(&tr.Key, &tr.Bytes, &tr.Packets, &tr.Flows); err != nil {
			return nil, fmt.Errorf("failed scanning DuckDB top sources: %w", err)
		}
		results = append(results, tr)
	}
	if results == nil {
		results = []flow.TopResult{}
	}
	return results, nil
}

// GetTopDestinations returns destination IPs with the highest bytes volume.
func (r *Repository) GetTopDestinations(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT dst_ip, SUM(bytes), SUM(packets), SUM(flows)
		FROM flow_aggregates
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		GROUP BY dst_ip
		ORDER BY SUM(bytes) DESC
		LIMIT ?
	`, start.Unix(), end.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying DuckDB top destinations: %w", err)
	}
	defer rows.Close()

	var results []flow.TopResult
	for rows.Next() {
		var tr flow.TopResult
		if err := rows.Scan(&tr.Key, &tr.Bytes, &tr.Packets, &tr.Flows); err != nil {
			return nil, fmt.Errorf("failed scanning DuckDB top destinations: %w", err)
		}
		results = append(results, tr)
	}
	if results == nil {
		results = []flow.TopResult{}
	}
	return results, nil
}

// GetTopPorts returns destination ports with the highest bytes volume.
func (r *Repository) GetTopPorts(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT CAST(dst_port AS VARCHAR), SUM(bytes), SUM(packets), SUM(flows)
		FROM flow_aggregates
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		GROUP BY dst_port
		ORDER BY SUM(bytes) DESC
		LIMIT ?
	`, start.Unix(), end.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying DuckDB top ports: %w", err)
	}
	defer rows.Close()

	var results []flow.TopResult
	for rows.Next() {
		var tr flow.TopResult
		if err := rows.Scan(&tr.Key, &tr.Bytes, &tr.Packets, &tr.Flows); err != nil {
			return nil, fmt.Errorf("failed scanning DuckDB top ports: %w", err)
		}
		results = append(results, tr)
	}
	if results == nil {
		results = []flow.TopResult{}
	}
	return results, nil
}

// GetTopProtocols returns transport protocols with the highest bytes volume.
func (r *Repository) GetTopProtocols(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT CAST(protocol AS VARCHAR), SUM(bytes), SUM(packets), SUM(flows)
		FROM flow_aggregates
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		GROUP BY protocol
		ORDER BY SUM(bytes) DESC
		LIMIT ?
	`, start.Unix(), end.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying DuckDB top protocols: %w", err)
	}
	defer rows.Close()

	var results []flow.TopResult
	for rows.Next() {
		var tr flow.TopResult
		if err := rows.Scan(&tr.Key, &tr.Bytes, &tr.Packets, &tr.Flows); err != nil {
			return nil, fmt.Errorf("failed scanning DuckDB top protocols: %w", err)
		}
		results = append(results, tr)
	}
	if results == nil {
		results = []flow.TopResult{}
	}
	return results, nil
}

// GetTopDevicesByVolume returns IPs with the highest source+destination byte volume.
func (r *Repository) GetTopDevicesByVolume(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT ip, SUM(bytes), SUM(packets), SUM(flows)
		FROM (
			SELECT src_ip AS ip, bytes, packets, flows
			FROM flow_aggregates
			WHERE bucket_ts >= ? AND bucket_ts <= ?
			UNION ALL
			SELECT dst_ip AS ip, bytes, packets, flows
			FROM flow_aggregates
			WHERE bucket_ts >= ? AND bucket_ts <= ?
		)
		GROUP BY ip
	`, start.Unix(), end.Unix(), start.Unix(), end.Unix())
	if err != nil {
		return nil, fmt.Errorf("failed querying DuckDB top devices: %w", err)
	}
	defer rows.Close()

	merged := make(map[string]*flow.TopResult)
	for rows.Next() {
		var tr flow.TopResult
		if err := rows.Scan(&tr.Key, &tr.Bytes, &tr.Packets, &tr.Flows); err != nil {
			return nil, fmt.Errorf("failed scanning DuckDB top devices: %w", err)
		}
		merged[tr.Key] = &tr
	}
	r.filterTopResultsToKnownDevices(ctx, merged)
	return flowquery.SortAndLimit(merged, limit), nil
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

// GetTrafficTimeSeries returns total traffic counters grouped into fixed-size bounded time buckets.
func (r *Repository) GetTrafficTimeSeries(ctx context.Context, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT CAST(FLOOR(bucket_ts / ?) * ? AS BIGINT) AS bucket_start,
		       SUM(bytes), SUM(packets), SUM(flows)
		FROM flow_aggregates
		WHERE bucket_ts >= ? AND bucket_ts <= ?
		GROUP BY bucket_start
		ORDER BY bucket_start ASC
	`, bucketSeconds, bucketSeconds, start.Unix(), end.Unix())
	if err != nil {
		return nil, fmt.Errorf("failed querying DuckDB traffic time series: %w", err)
	}
	defer rows.Close()

	var results []flow.TrafficTimeBucket
	for rows.Next() {
		var bucketStart int64
		var item flow.TrafficTimeBucket
		if err := rows.Scan(&bucketStart, &item.Bytes, &item.Packets, &item.Flows); err != nil {
			return nil, fmt.Errorf("failed scanning DuckDB traffic time series: %w", err)
		}
		item.Timestamp = time.Unix(bucketStart, 0).UTC()
		results = append(results, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating DuckDB traffic time series rows: %w", err)
	}
	if results == nil {
		results = []flow.TrafficTimeBucket{}
	}
	return results, nil
}

// QueryFlowAggregateRecords returns bounded aggregate rows for analyst filtering.
func (r *Repository) QueryFlowAggregateRecords(ctx context.Context, start, end time.Time, q string, protocol, dstPort, limit int) ([]flow.AggregateRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if limit <= 0 || limit > 500 {
		limit = 100
	}

	clauses := []string{"bucket_ts >= ?", "bucket_ts <= ?"}
	args := []interface{}{start.Unix(), end.Unix()}
	tokens := strings.Fields(strings.ToLower(q))
	for _, token := range tokens {
		clauses = append(clauses, "(lower(src_ip) LIKE ? OR lower(dst_ip) LIKE ?)")
		like := "%" + token + "%"
		args = append(args, like, like)
	}
	if protocol > 0 {
		clauses = append(clauses, "protocol = ?")
		args = append(args, protocol)
	}
	if dstPort > 0 {
		clauses = append(clauses, "dst_port = ?")
		args = append(args, dstPort)
	}
	args = append(args, limit)

	rows, err := r.db.QueryContext(ctx, `
		SELECT bucket_ts, collector_kind, collector_id, src_ip, dst_ip, dst_port, protocol, bytes, packets, flows
		FROM flow_aggregates
		WHERE `+strings.Join(clauses, " AND ")+`
		ORDER BY bucket_ts DESC, bytes DESC
		LIMIT ?
	`, args...)
	if err != nil {
		return nil, fmt.Errorf("failed querying DuckDB flow aggregate records: %w", err)
	}
	defer rows.Close()

	var out []flow.AggregateRecord
	for rows.Next() {
		var rec flow.AggregateRecord
		var ts int64
		if err := rows.Scan(&ts, &rec.CollectorKind, &rec.CollectorID, &rec.SrcIP, &rec.DstIP, &rec.DstPort, &rec.Protocol, &rec.Bytes, &rec.Packets, &rec.Flows); err != nil {
			return nil, fmt.Errorf("failed scanning DuckDB flow aggregate record: %w", err)
		}
		rec.Timestamp = time.Unix(ts, 0).UTC()
		rec.CollectorKind = flow.NormalizeCollectorKind(rec.CollectorKind)
		rec.CollectorID = flow.NormalizeCollectorID(rec.CollectorID, rec.CollectorKind, "")
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating DuckDB flow aggregate records: %w", err)
	}
	if out == nil {
		out = []flow.AggregateRecord{}
	}
	return out, nil
}

// GetDeviceActivityHeatmap returns hour-of-day traffic activity for the top device-like IPs.
func (r *Repository) GetDeviceActivityHeatmap(ctx context.Context, start, end time.Time, limit int) ([]flow.DeviceHeatmapCell, error) {
	topDevices, err := r.GetTopDevicesByVolume(ctx, start, end, limit)
	if err != nil {
		return nil, err
	}
	if len(topDevices) == 0 {
		return []flow.DeviceHeatmapCell{}, nil
	}

	allowed := make(map[string]struct{}, len(topDevices))
	for _, item := range topDevices {
		allowed[item.Key] = struct{}{}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT ip,
		       CAST(FLOOR((bucket_ts % 86400) / 3600) AS INTEGER) AS hour_of_day,
		       SUM(bytes), SUM(packets), SUM(flows)
		FROM (
			SELECT src_ip AS ip, bucket_ts, bytes, packets, flows
			FROM flow_aggregates
			WHERE bucket_ts >= ? AND bucket_ts <= ?
			UNION ALL
			SELECT dst_ip AS ip, bucket_ts, bytes, packets, flows
			FROM flow_aggregates
			WHERE bucket_ts >= ? AND bucket_ts <= ?
		)
		GROUP BY ip, hour_of_day
		ORDER BY ip ASC, hour_of_day ASC
	`, start.Unix(), end.Unix(), start.Unix(), end.Unix())
	if err != nil {
		return nil, fmt.Errorf("failed querying DuckDB device heatmap: %w", err)
	}
	defer rows.Close()

	var results []flow.DeviceHeatmapCell
	for rows.Next() {
		var cell flow.DeviceHeatmapCell
		if err := rows.Scan(&cell.IP, &cell.Hour, &cell.Bytes, &cell.Packets, &cell.Flows); err != nil {
			return nil, fmt.Errorf("failed scanning DuckDB device heatmap: %w", err)
		}
		if _, ok := allowed[cell.IP]; ok {
			results = append(results, cell)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating DuckDB device heatmap rows: %w", err)
	}
	if results == nil {
		results = []flow.DeviceHeatmapCell{}
	}
	return results, nil
}
