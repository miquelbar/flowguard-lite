package sqlite

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
)

// SaveAggregates writes aggregated minute records to the shard matching the bucket date.
func (r *Repository) SaveAggregates(ctx context.Context, ts time.Time, aggregates []flow.FlowEvent) error {
	if len(aggregates) == 0 {
		return nil
	}

	dateStr := ts.Format("2006-01-02")
	db, err := r.getOrCreateShard(dateStr)
	if err != nil {
		return fmt.Errorf("failed to open database shard: %w", err)
	}

	// Write batch using a single transaction to minimize disk IOPS and wear
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO flow_aggregates (
			bucket_ts, collector_kind, collector_id, src_ip, dst_ip, dst_port, protocol, bytes, packets, flows
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(bucket_ts, collector_kind, collector_id, src_ip, dst_ip, dst_port, protocol) DO UPDATE SET
			bytes = bytes + excluded.bytes,
			packets = packets + excluded.packets,
			flows = flows + excluded.flows
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare insert statement: %w", err)
	}
	defer stmt.Close()

	for _, agg := range aggregates {
		unixTs := agg.Timestamp.Unix()
		collectorKind := flow.NormalizeCollectorKind(agg.CollectorKind)
		collectorID := flow.NormalizeCollectorID(agg.CollectorID, collectorKind, agg.ExporterIP)
		_, err := stmt.ExecContext(ctx,
			unixTs,
			collectorKind,
			collectorID,
			agg.SrcIP,
			agg.DstIP,
			agg.DstPort,
			agg.Protocol,
			agg.Bytes,
			agg.Packets,
			agg.Packets,
		)
		if err != nil {
			return fmt.Errorf("failed to write flow record: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	return nil
}

// GetTopSources returns source IPs sorted by byte volume.
func (r *Repository) GetTopSources(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	dbs, err := r.GetShardsInRange(start, end)
	if err != nil {
		return nil, err
	}

	merged := make(map[string]*flow.TopResult)
	startUnix := start.Unix()
	endUnix := end.Unix()

	for _, db := range dbs {
		rows, err := db.QueryContext(ctx, `
			SELECT src_ip, SUM(bytes), SUM(packets), SUM(flows)
			FROM flow_aggregates
			WHERE bucket_ts >= ? AND bucket_ts <= ?
			GROUP BY src_ip
		`, startUnix, endUnix)
		if err != nil {
			return nil, fmt.Errorf("failed to query top sources: %w", err)
		}
		r.mergeRows(rows, merged)
	}

	return sortAndLimit(merged, limit), nil
}

// GetTopDestinations returns destination IPs sorted by byte volume.
func (r *Repository) GetTopDestinations(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	dbs, err := r.GetShardsInRange(start, end)
	if err != nil {
		return nil, err
	}

	merged := make(map[string]*flow.TopResult)
	startUnix := start.Unix()
	endUnix := end.Unix()

	for _, db := range dbs {
		rows, err := db.QueryContext(ctx, `
			SELECT dst_ip, SUM(bytes), SUM(packets), SUM(flows)
			FROM flow_aggregates
			WHERE bucket_ts >= ? AND bucket_ts <= ?
			GROUP BY dst_ip
		`, startUnix, endUnix)
		if err != nil {
			return nil, fmt.Errorf("failed to query top destinations: %w", err)
		}
		r.mergeRows(rows, merged)
	}

	return sortAndLimit(merged, limit), nil
}

// GetTopPorts returns destination ports sorted by byte volume.
func (r *Repository) GetTopPorts(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
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
			WHERE bucket_ts >= ? AND bucket_ts <= ?
			GROUP BY dst_port
		`, startUnix, endUnix)
		if err != nil {
			return nil, fmt.Errorf("failed to query top ports: %w", err)
		}
		r.mergeRows(rows, merged)
	}

	return sortAndLimit(merged, limit), nil
}

// GetTopProtocols returns transport protocols sorted by byte volume.
func (r *Repository) GetTopProtocols(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	dbs, err := r.GetShardsInRange(start, end)
	if err != nil {
		return nil, err
	}

	merged := make(map[string]*flow.TopResult)
	startUnix := start.Unix()
	endUnix := end.Unix()

	for _, db := range dbs {
		rows, err := db.QueryContext(ctx, `
			SELECT protocol, SUM(bytes), SUM(packets), SUM(flows)
			FROM flow_aggregates
			WHERE bucket_ts >= ? AND bucket_ts <= ?
			GROUP BY protocol
		`, startUnix, endUnix)
		if err != nil {
			return nil, fmt.Errorf("failed to query top protocols: %w", err)
		}
		r.mergeRows(rows, merged)
	}

	return sortAndLimit(merged, limit), nil
}

// GetTopDevicesByVolume returns IPs with the highest source+destination byte volume.
func (r *Repository) GetTopDevicesByVolume(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	dbs, err := r.GetShardsInRange(start, end)
	if err != nil {
		return nil, err
	}

	merged := make(map[string]*flow.TopResult)
	startUnix := start.Unix()
	endUnix := end.Unix()

	for _, db := range dbs {
		rows, err := db.QueryContext(ctx, `
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
		`, startUnix, endUnix, startUnix, endUnix)
		if err != nil {
			return nil, fmt.Errorf("failed to query top devices: %w", err)
		}
		r.mergeRows(rows, merged)
	}

	r.filterTopResultsToKnownDevices(ctx, merged)
	return sortAndLimit(merged, limit), nil
}

// GetTrafficTimeSeries returns total traffic counters grouped into fixed-size bounded time buckets.
func (r *Repository) GetTrafficTimeSeries(ctx context.Context, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error) {
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
			WHERE bucket_ts >= ? AND bucket_ts <= ?
			GROUP BY bucket_start
			ORDER BY bucket_start ASC
		`, bucketSeconds, bucketSeconds, startUnix, endUnix)
		if err != nil {
			return nil, fmt.Errorf("failed to query traffic time series: %w", err)
		}

		for rows.Next() {
			var bucketStart int64
			var bytesVal, packetsVal, flowsVal uint64
			if err := rows.Scan(&bucketStart, &bytesVal, &packetsVal, &flowsVal); err != nil {
				rows.Close()
				return nil, fmt.Errorf("failed scanning traffic time series: %w", err)
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
			return nil, fmt.Errorf("failed iterating traffic time series rows: %w", err)
		}
		rows.Close()
	}

	return sortTrafficBuckets(merged), nil
}

// QueryFlowAggregateRecords returns bounded aggregate rows for analyst filtering.
func (r *Repository) QueryFlowAggregateRecords(ctx context.Context, start, end time.Time, q string, protocol, dstPort, limit int) ([]flow.AggregateRecord, error) {
	dbs, err := r.GetShardsInRange(start, end)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	startUnix := start.Unix()
	endUnix := end.Unix()
	var out []flow.AggregateRecord

	for _, db := range dbs {
		clauses := []string{"bucket_ts >= ?", "bucket_ts <= ?"}
		args := []interface{}{startUnix, endUnix}
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

		rows, err := db.QueryContext(ctx, `
			SELECT bucket_ts, collector_kind, collector_id, src_ip, dst_ip, dst_port, protocol, bytes, packets, flows
			FROM flow_aggregates
			WHERE `+strings.Join(clauses, " AND ")+`
			ORDER BY bucket_ts DESC, bytes DESC
			LIMIT ?
		`, args...)
		if err != nil {
			return nil, fmt.Errorf("failed querying flow aggregate records: %w", err)
		}
		for rows.Next() {
			var rec flow.AggregateRecord
			var ts int64
			if err := rows.Scan(&ts, &rec.CollectorKind, &rec.CollectorID, &rec.SrcIP, &rec.DstIP, &rec.DstPort, &rec.Protocol, &rec.Bytes, &rec.Packets, &rec.Flows); err != nil {
				rows.Close()
				return nil, fmt.Errorf("failed scanning flow aggregate record: %w", err)
			}
			rec.Timestamp = time.Unix(ts, 0).UTC()
			rec.CollectorKind = flow.NormalizeCollectorKind(rec.CollectorKind)
			rec.CollectorID = flow.NormalizeCollectorID(rec.CollectorID, rec.CollectorKind, "")
			out = append(out, rec)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed iterating flow aggregate records: %w", err)
		}
		rows.Close()
	}

	sort.Slice(out, func(i, j int) bool {
		if !out[i].Timestamp.Equal(out[j].Timestamp) {
			return out[i].Timestamp.After(out[j].Timestamp)
		}
		return out[i].Bytes > out[j].Bytes
	})
	if len(out) > limit {
		out = out[:limit]
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

	dbs, err := r.GetShardsInRange(start, end)
	if err != nil {
		return nil, err
	}

	startUnix := start.Unix()
	endUnix := end.Unix()
	merged := make(map[string]*flow.DeviceHeatmapCell)

	for _, db := range dbs {
		rows, err := db.QueryContext(ctx, `
			SELECT ip, CAST(strftime('%H', bucket_ts, 'unixepoch') AS INTEGER) AS hour_of_day,
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
		`, startUnix, endUnix, startUnix, endUnix)
		if err != nil {
			return nil, fmt.Errorf("failed to query device heatmap: %w", err)
		}

		for rows.Next() {
			var cell flow.DeviceHeatmapCell
			if err := rows.Scan(&cell.IP, &cell.Hour, &cell.Bytes, &cell.Packets, &cell.Flows); err != nil {
				rows.Close()
				return nil, fmt.Errorf("failed scanning device heatmap: %w", err)
			}
			if _, ok := allowed[cell.IP]; !ok {
				continue
			}
			key := fmt.Sprintf("%s|%d", cell.IP, cell.Hour)
			if existing, ok := merged[key]; ok {
				existing.Bytes += cell.Bytes
				existing.Packets += cell.Packets
				existing.Flows += cell.Flows
			} else {
				merged[key] = &cell
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed iterating device heatmap rows: %w", err)
		}
		rows.Close()
	}

	return sortHeatmapCells(merged), nil
}
