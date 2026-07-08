package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flowguard/flowguard/internal/flow"
	_ "modernc.org/sqlite"
)

// SQLiteRepository manages Daily SQLite Shards for aggregated flow data and metadata.
type SQLiteRepository struct {
	dataDir string
	logger  *slog.Logger

	// Persistent Metadata Database
	metaDB *sql.DB

	mu            sync.RWMutex
	shards        map[string]*sql.DB
	onSaveAnomaly []func(a *Anomaly)
}

// NewSQLiteRepository creates a new SQLite daily shard storage repository.
func NewSQLiteRepository(dataDir string, logger *slog.Logger) (*SQLiteRepository, error) {
	// Create flows directory if not exists
	flowsDir := filepath.Join(dataDir, "flows")
	if err := os.MkdirAll(flowsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create flows storage dir: %w", err)
	}

	// 1. Initialize persistent metadata database
	metaPath := filepath.Join(dataDir, "metadata.sqlite")
	metaDB, err := sql.Open("sqlite", metaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open metadata database: %w", err)
	}

	// 2. Optimize metadata database performance
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA busy_timeout=5000;",
	}
	for _, p := range pragmas {
		if _, err := metaDB.Exec(p); err != nil {
			metaDB.Close()
			return nil, fmt.Errorf("failed pragma for metadata: %s, err: %w", p, err)
		}
	}

	// 3. Create persistent tables
	_, err = metaDB.Exec(`
		CREATE TABLE IF NOT EXISTS devices (
			ip TEXT PRIMARY KEY,
			label TEXT NOT NULL DEFAULT '',
			hostname TEXT NOT NULL DEFAULT '',
			vendor TEXT NOT NULL DEFAULT '',
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS device_baselines (
			ip TEXT PRIMARY KEY,
			mean_bytes REAL NOT NULL DEFAULT 0,
			stddev_bytes REAL NOT NULL DEFAULT 0,
			mean_packets REAL NOT NULL DEFAULT 0,
			stddev_packets REAL NOT NULL DEFAULT 0,
			mean_peers REAL NOT NULL DEFAULT 0,
			stddev_peers REAL NOT NULL DEFAULT 0,
			updated_at DATETIME NOT NULL,
			FOREIGN KEY(ip) REFERENCES devices(ip) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS anomalies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL,
			type TEXT NOT NULL,
			description TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'medium',
			status TEXT NOT NULL DEFAULT 'active',
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			FOREIGN KEY(ip) REFERENCES devices(ip) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_anomalies_created ON anomalies (created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_anomalies_ip ON anomalies (ip);

		CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME NOT NULL,
			action TEXT NOT NULL,
			details TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs (timestamp DESC);

		CREATE TABLE IF NOT EXISTS policies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			scope TEXT NOT NULL,
			target TEXT NOT NULL,
			severity_threshold TEXT NOT NULL DEFAULT '',
			suppressed INTEGER NOT NULL DEFAULT 0,
			cooldown_seconds INTEGER NOT NULL DEFAULT 0,
			quiet_hours_start TEXT NOT NULL DEFAULT '',
			quiet_hours_end TEXT NOT NULL DEFAULT '',
			notification_channels TEXT NOT NULL DEFAULT '[]',
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_policies_scope ON policies (scope);

		CREATE TABLE IF NOT EXISTS notification_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			severity_min TEXT NOT NULL DEFAULT 'low',
			alert_types TEXT NOT NULL DEFAULT '[]',
			scope TEXT NOT NULL DEFAULT 'global',
			target TEXT NOT NULL DEFAULT '',
			cooldown_seconds INTEGER NOT NULL DEFAULT 300,
			channel_targets TEXT NOT NULL DEFAULT '[]',
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS notification_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			anomaly_id INTEGER NOT NULL,
			rule_id INTEGER,
			channel TEXT NOT NULL,
			status TEXT NOT NULL,
			error_message TEXT,
			dispatched_at DATETIME NOT NULL,
			FOREIGN KEY(anomaly_id) REFERENCES anomalies(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_notification_logs_dispatched ON notification_logs (dispatched_at DESC);
		CREATE INDEX IF NOT EXISTS idx_notification_logs_lookup ON notification_logs (rule_id, status);
	`)
	if err != nil {
		metaDB.Close()
		return nil, fmt.Errorf("failed schema metadata setup: %w", err)
	}

	return &SQLiteRepository{
		dataDir: flowsDir,
		logger:  logger,
		metaDB:  metaDB,
		shards:  make(map[string]*sql.DB),
	}, nil
}

// Close closes all open database connections.
func (r *SQLiteRepository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var firstErr error

	// Close shards
	for date, db := range r.shards {
		r.logger.Debug("Closing SQLite shard connection", slog.String("date", date))
		if err := db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	r.shards = make(map[string]*sql.DB)

	// Close metadata database
	if r.metaDB != nil {
		r.logger.Debug("Closing SQLite metadata database connection")
		if err := r.metaDB.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// CleanupRetention deletes daily shard files older than the retention threshold.
func (r *SQLiteRepository) CleanupRetention(retentionDays int) error {
	r.logger.Info("Running storage retention cleanup...", slog.Int("retention_days", retentionDays))

	files, err := os.ReadDir(r.dataDir)
	if err != nil {
		return fmt.Errorf("failed to read flows storage dir: %w", err)
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format("2006-01-02")

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sqlite") {
			continue
		}

		// Shard filename structure YYYY-MM-DD.sqlite
		dateStr := strings.TrimSuffix(file.Name(), ".sqlite")
		if dateStr < cutoff {
			r.logger.Info("Pruning expired SQLite daily shard", slog.String("file", file.Name()))

			// 1. Close cached handle if active
			r.mu.Lock()
			if db, ok := r.shards[dateStr]; ok {
				db.Close()
				delete(r.shards, dateStr)
			}
			r.mu.Unlock()

			// 2. Delete file
			path := filepath.Join(r.dataDir, file.Name())
			if err := os.Remove(path); err != nil {
				r.logger.Error("Failed to delete expired daily shard file", slog.String("path", path), slog.String("error", err.Error()))
			}
		}
	}
	return nil
}

// SaveAggregates writes aggregated minute records to the shard matching the bucket date.
func (r *SQLiteRepository) SaveAggregates(ctx context.Context, ts time.Time, aggregates []flow.FlowEvent) error {
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
		INSERT INTO flow_aggregates (bucket_ts, src_ip, dst_ip, dst_port, protocol, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(bucket_ts, src_ip, dst_ip, dst_port, protocol) DO UPDATE SET
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
		_, err := stmt.ExecContext(ctx,
			unixTs,
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
func (r *SQLiteRepository) GetTopSources(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
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
func (r *SQLiteRepository) GetTopDestinations(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
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
func (r *SQLiteRepository) GetTopPorts(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
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
func (r *SQLiteRepository) GetTopProtocols(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
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
func (r *SQLiteRepository) GetTopDevicesByVolume(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
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
func (r *SQLiteRepository) GetTrafficTimeSeries(ctx context.Context, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error) {
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

// GetDeviceActivityHeatmap returns hour-of-day traffic activity for the top device-like IPs.
func (r *SQLiteRepository) GetDeviceActivityHeatmap(ctx context.Context, start, end time.Time, limit int) ([]flow.DeviceHeatmapCell, error) {
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

// === DeviceRepository Implementation ===

// UpsertDevice registers or updates a device's last-seen status and hostname.
func (r *SQLiteRepository) UpsertDevice(ctx context.Context, ip string, hostname string, lastSeen time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	lastSeenUnix := lastSeen.Format(time.RFC3339)

	// If hostname is empty, we don't want to overwrite an existing hostname with an empty string!
	// We handle this conditionally using CASE WHEN.
	_, err := r.metaDB.ExecContext(ctx, `
		INSERT INTO devices (ip, hostname, first_seen, last_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			last_seen = ?,
			hostname = CASE WHEN ? != '' THEN ? ELSE hostname END
	`, ip, hostname, lastSeenUnix, lastSeenUnix, lastSeenUnix, hostname, hostname)
	if err != nil {
		return fmt.Errorf("failed to upsert device IP %s: %w", ip, err)
	}
	return nil
}

// UpdateDeviceLabel manually sets the descriptive label for a device.
func (r *SQLiteRepository) UpdateDeviceLabel(ctx context.Context, ip string, label string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	res, err := r.metaDB.ExecContext(ctx, `
		UPDATE devices SET label = ? WHERE ip = ?
	`, label, ip)
	if err != nil {
		return fmt.Errorf("failed to update device label: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("device not found")
	}
	return nil
}

// GetDevice fetches details of a single device.
func (r *SQLiteRepository) GetDevice(ctx context.Context, ip string) (*Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var d Device
	var firstSeenStr, lastSeenStr string

	err := r.metaDB.QueryRowContext(ctx, `
		SELECT ip, label, hostname, vendor, first_seen, last_seen
		FROM devices
		WHERE ip = ?
	`, ip).Scan(&d.IP, &d.Label, &d.Hostname, &d.Vendor, &firstSeenStr, &lastSeenStr)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Return nil, nil when device is not found
		}
		return nil, fmt.Errorf("failed to query device %s: %w", ip, err)
	}

	// Parse timestamps
	if t, err := time.Parse(time.RFC3339, firstSeenStr); err == nil {
		d.FirstSeen = t
	}
	if t, err := time.Parse(time.RFC3339, lastSeenStr); err == nil {
		d.LastSeen = t
	}

	return &d, nil
}

// ListDevices lists all discovered network devices.
func (r *SQLiteRepository) ListDevices(ctx context.Context) ([]Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.metaDB.QueryContext(ctx, `
		SELECT ip, label, hostname, vendor, first_seen, last_seen
		FROM devices
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query devices: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		var firstSeenStr, lastSeenStr string

		if err := rows.Scan(&d.IP, &d.Label, &d.Hostname, &d.Vendor, &firstSeenStr, &lastSeenStr); err != nil {
			return nil, fmt.Errorf("failed to scan device: %w", err)
		}

		if t, err := time.Parse(time.RFC3339, firstSeenStr); err == nil {
			d.FirstSeen = t
		}
		if t, err := time.Parse(time.RFC3339, lastSeenStr); err == nil {
			d.LastSeen = t
		}

		devices = append(devices, d)
	}

	if devices == nil {
		devices = []Device{}
	}
	return devices, nil
}

// SaveBaseline persists/updates the historical behavioral baseline profile for a device.
func (r *SQLiteRepository) SaveBaseline(ctx context.Context, b *DeviceBaseline) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	updatedAtStr := b.UpdatedAt.Format(time.RFC3339)

	_, err := r.metaDB.ExecContext(ctx, `
		INSERT INTO device_baselines (ip, mean_bytes, stddev_bytes, mean_packets, stddev_packets, mean_peers, stddev_peers, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			mean_bytes = excluded.mean_bytes,
			stddev_bytes = excluded.stddev_bytes,
			mean_packets = excluded.mean_packets,
			stddev_packets = excluded.stddev_packets,
			mean_peers = excluded.mean_peers,
			stddev_peers = excluded.stddev_peers,
			updated_at = excluded.updated_at
	`, b.IP, b.MeanBytes, b.StdDevBytes, b.MeanPackets, b.StdDevPackets, b.MeanPeers, b.StdDevPeers, updatedAtStr)
	if err != nil {
		return fmt.Errorf("failed to save baseline for IP %s: %w", b.IP, err)
	}
	return nil
}

// GetBaseline retrieves the cached historical baseline profile for a device.
func (r *SQLiteRepository) GetBaseline(ctx context.Context, ip string) (*DeviceBaseline, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var b DeviceBaseline
	var updatedAtStr string

	err := r.metaDB.QueryRowContext(ctx, `
		SELECT ip, mean_bytes, stddev_bytes, mean_packets, stddev_packets, mean_peers, stddev_peers, updated_at
		FROM device_baselines
		WHERE ip = ?
	`, ip).Scan(&b.IP, &b.MeanBytes, &b.StdDevBytes, &b.MeanPackets, &b.StdDevPackets, &b.MeanPeers, &b.StdDevPeers, &updatedAtStr)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Return nil, nil when baseline is not found
		}
		return nil, fmt.Errorf("failed to query baseline %s: %w", ip, err)
	}

	if t, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
		b.UpdatedAt = t
	}

	return &b, nil
}

// SaveAnomaly registers a new behavioral alert.
func (r *SQLiteRepository) SaveAnomaly(ctx context.Context, a *Anomaly) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Evaluate policies to potentially silence the anomaly before saving
	if err := r.evaluateAnomalyPoliciesLocked(ctx, a); err != nil {
		r.logger.Warn("Failed to evaluate anomaly policies", slog.String("ip", a.IP), slog.String("type", a.Type), slog.String("error", err.Error()))
	}

	createdStr := a.CreatedAt.Format(time.RFC3339)
	updatedStr := a.UpdatedAt.Format(time.RFC3339)

	res, err := r.metaDB.ExecContext(ctx, `
		INSERT INTO anomalies (ip, type, description, severity, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, a.IP, a.Type, a.Description, a.Severity, a.Status, createdStr, updatedStr)
	if err != nil {
		return fmt.Errorf("failed to save anomaly for IP %s: %w", a.IP, err)
	}

	id, err := res.LastInsertId()
	if err == nil {
		a.ID = id
	}

	// Trigger callbacks in a non-blocking background goroutine
	callbacks := r.onSaveAnomaly
	if len(callbacks) > 0 {
		go func(anomaly *Anomaly) {
			for _, cb := range callbacks {
				cb(anomaly)
			}
		}(a)
	}

	return nil
}

// UpdateAnomalyStatus reviews, silences, or acknowledges an alert.
func (r *SQLiteRepository) UpdateAnomalyStatus(ctx context.Context, id int64, status string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	updatedStr := time.Now().Format(time.RFC3339)

	res, err := r.metaDB.ExecContext(ctx, `
		UPDATE anomalies SET status = ?, updated_at = ? WHERE id = ?
	`, status, updatedStr, id)
	if err != nil {
		return fmt.Errorf("failed to update anomaly status: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("anomaly not found")
	}

	return nil
}

// ListAnomalies queries recent anomalies triggered.
func (r *SQLiteRepository) ListAnomalies(ctx context.Context, limit int) ([]Anomaly, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.metaDB.QueryContext(ctx, `
		SELECT id, ip, type, description, severity, status, created_at, updated_at
		FROM anomalies
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed query anomalies list: %w", err)
	}
	defer rows.Close()

	var list []Anomaly
	for rows.Next() {
		var a Anomaly
		var createdStr, updatedStr string

		err = rows.Scan(&a.ID, &a.IP, &a.Type, &a.Description, &a.Severity, &a.Status, &createdStr, &updatedStr)
		if err != nil {
			return nil, fmt.Errorf("failed to scan anomaly row: %w", err)
		}

		if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
			a.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, updatedStr); err == nil {
			a.UpdatedAt = t
		}

		list = append(list, a)
	}

	if list == nil {
		list = []Anomaly{}
	}
	return list, nil
}

// GetActiveAnomalies queries all active anomalies triggered since a given time.
func (r *SQLiteRepository) GetActiveAnomalies(ctx context.Context, since time.Time) ([]Anomaly, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sinceStr := since.Format(time.RFC3339)

	rows, err := r.metaDB.QueryContext(ctx, `
		SELECT id, ip, type, description, severity, status, created_at, updated_at
		FROM anomalies
		WHERE status = 'active' AND created_at >= ?
		ORDER BY created_at DESC
	`, sinceStr)
	if err != nil {
		return nil, fmt.Errorf("failed query active anomalies list: %w", err)
	}
	defer rows.Close()

	var list []Anomaly
	for rows.Next() {
		var a Anomaly
		var createdStr, updatedStr string

		err = rows.Scan(&a.ID, &a.IP, &a.Type, &a.Description, &a.Severity, &a.Status, &createdStr, &updatedStr)
		if err != nil {
			return nil, fmt.Errorf("failed to scan active anomaly row: %w", err)
		}

		if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
			a.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, updatedStr); err == nil {
			a.UpdatedAt = t
		}

		list = append(list, a)
	}

	if list == nil {
		list = []Anomaly{}
	}
	return list, nil
}

// Helper: Open / cache daily SQLite shards and verify table schema.
func (r *SQLiteRepository) getOrCreateShard(dateStr string) (*sql.DB, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if db, ok := r.shards[dateStr]; ok {
		return db, nil
	}

	path := filepath.Join(r.dataDir, dateStr+".sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA busy_timeout=5000;",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed pragma: %s, err: %w", p, err)
		}
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS flow_aggregates (
			bucket_ts INTEGER NOT NULL,
			src_ip TEXT NOT NULL,
			dst_ip TEXT NOT NULL,
			dst_port INTEGER NOT NULL,
			protocol INTEGER NOT NULL,
			bytes INTEGER NOT NULL,
			packets INTEGER NOT NULL,
			flows INTEGER NOT NULL,
			PRIMARY KEY (bucket_ts, src_ip, dst_ip, dst_port, protocol)
		);
		CREATE INDEX IF NOT EXISTS idx_flow_agg_src ON flow_aggregates (src_ip, bytes DESC);
		CREATE INDEX IF NOT EXISTS idx_flow_agg_dst ON flow_aggregates (dst_ip, bytes DESC);
		CREATE INDEX IF NOT EXISTS idx_flow_agg_port ON flow_aggregates (dst_port, bytes DESC);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed schema setup: %w", err)
	}

	r.shards[dateStr] = db
	return db, nil
}

// GetShardsInRange returns list of DB handles active in the date range.
func (r *SQLiteRepository) GetShardsInRange(start, end time.Time) ([]*sql.DB, error) {
	var res []*sql.DB

	curr := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, start.Location())
	limit := time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, end.Location())

	for !curr.After(limit) {
		dateStr := curr.Format("2006-01-02")
		path := filepath.Join(r.dataDir, dateStr+".sqlite")

		exists := false
		r.mu.RLock()
		_, cached := r.shards[dateStr]
		r.mu.RUnlock()

		if cached {
			exists = true
		} else if _, err := os.Stat(path); err == nil {
			exists = true
		}

		if exists {
			db, err := r.getOrCreateShard(dateStr)
			if err != nil {
				return nil, err
			}
			res = append(res, db)
		}

		curr = curr.AddDate(0, 0, 1)
	}

	return res, nil
}

// Helper: Merge raw SQL query rows into a map of keys.
func (r *SQLiteRepository) mergeRows(rows *sql.Rows, merged map[string]*flow.TopResult) {
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
	if len(m) == 0 {
		return []flow.TopResult{}
	}

	slice := make([]flow.TopResult, 0, len(m))
	for _, val := range m {
		slice = append(slice, *val)
	}

	for i := 0; i < len(slice); i++ {
		for j := i + 1; j < len(slice); j++ {
			if slice[i].Bytes < slice[j].Bytes {
				slice[i], slice[j] = slice[j], slice[i]
			}
		}
	}

	if len(slice) > limit {
		return slice[:limit]
	}
	return slice
}

func (r *SQLiteRepository) filterTopResultsToKnownDevices(ctx context.Context, merged map[string]*flow.TopResult) {
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

func sortHeatmapCells(m map[string]*flow.DeviceHeatmapCell) []flow.DeviceHeatmapCell {
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

// RegisterAnomalyCallback registers a callback invoked whenever a new anomaly is saved.
func (r *SQLiteRepository) RegisterAnomalyCallback(cb func(a *Anomaly)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onSaveAnomaly = append(r.onSaveAnomaly, cb)
}

func (r *SQLiteRepository) saveAuditLogLocked(ctx context.Context, action string, details string) error {
	tsStr := time.Now().Format(time.RFC3339)
	_, err := r.metaDB.ExecContext(ctx, `
		INSERT INTO audit_logs (timestamp, action, details) VALUES (?, ?, ?)
	`, tsStr, action, details)
	if err != nil {
		return fmt.Errorf("failed to save audit log: %w", err)
	}
	return nil
}

// SaveAuditLog writes a security or configuration audit record.
func (r *SQLiteRepository) SaveAuditLog(ctx context.Context, action string, details string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.saveAuditLogLocked(ctx, action, details)
}

// ListAuditLogs returns a list of recent audit log records.
func (r *SQLiteRepository) ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.metaDB.QueryContext(ctx, `
		SELECT id, timestamp, action, details FROM audit_logs ORDER BY timestamp DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var list []AuditLog
	for rows.Next() {
		var l AuditLog
		var tsStr string
		if err := rows.Scan(&l.ID, &tsStr, &l.Action, &l.Details); err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}
		tVal, err := time.Parse(time.RFC3339, tsStr)
		if err == nil {
			l.Timestamp = tVal
		} else {
			l.Timestamp = time.Now()
		}
		list = append(list, l)
	}

	if list == nil {
		list = []AuditLog{}
	}
	return list, nil
}

// GetAnomaliesForIP queries recent anomalies associated with a specific IP.
func (r *SQLiteRepository) GetAnomaliesForIP(ctx context.Context, ip string, limit int) ([]Anomaly, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.metaDB.QueryContext(ctx, `
		SELECT id, ip, type, description, severity, status, created_at, updated_at
		FROM anomalies
		WHERE ip = ?
		ORDER BY created_at DESC
		LIMIT ?
	`, ip, limit)
	if err != nil {
		return nil, fmt.Errorf("failed query anomalies for IP: %w", err)
	}
	defer rows.Close()

	var list []Anomaly
	for rows.Next() {
		var a Anomaly
		var createdStr, updatedStr string

		err = rows.Scan(&a.ID, &a.IP, &a.Type, &a.Description, &a.Severity, &a.Status, &createdStr, &updatedStr)
		if err != nil {
			return nil, fmt.Errorf("failed to scan anomaly row: %w", err)
		}

		if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
			a.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, updatedStr); err == nil {
			a.UpdatedAt = t
		}

		list = append(list, a)
	}

	if list == nil {
		list = []Anomaly{}
	}
	return list, nil
}

// GetDeviceTrafficTimeSeries returns total traffic counters for a specific IP grouped into fixed-size bounded time buckets.
func (r *SQLiteRepository) GetDeviceTrafficTimeSeries(ctx context.Context, ip string, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error) {
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
func (r *SQLiteRepository) GetDeviceTopPeers(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error) {
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
func (r *SQLiteRepository) GetDeviceTopPorts(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error) {
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

// SavePolicy persists or updates a custom policy.
func (r *SQLiteRepository) SavePolicy(ctx context.Context, p *Policy) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}

	channelsJSON, err := json.Marshal(p.NotificationChannels)
	if err != nil {
		return fmt.Errorf("failed to marshal channels: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	p.UpdatedAt = now

	if p.ID == 0 {
		p.CreatedAt = now
		query := `INSERT INTO policies (name, scope, target, severity_threshold, suppressed, cooldown_seconds, quiet_hours_start, quiet_hours_end, notification_channels, created_at, updated_at)
		          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		res, err := r.metaDB.ExecContext(ctx, query, p.Name, p.Scope, p.Target, p.SeverityThreshold, boolToInt(p.Suppressed), p.CooldownSeconds, p.QuietHoursStart, p.QuietHoursEnd, string(channelsJSON), p.CreatedAt, p.UpdatedAt)
		if err != nil {
			return fmt.Errorf("failed to insert policy: %w", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("failed to get insert ID: %w", err)
		}
		p.ID = id
		r.logger.Info("Created new policy", slog.Int64("id", p.ID), slog.String("name", p.Name))
	} else {
		query := `UPDATE policies SET name = ?, scope = ?, target = ?, severity_threshold = ?, suppressed = ?, cooldown_seconds = ?, quiet_hours_start = ?, quiet_hours_end = ?, notification_channels = ?, updated_at = ?
		          WHERE id = ?`
		res, err := r.metaDB.ExecContext(ctx, query, p.Name, p.Scope, p.Target, p.SeverityThreshold, boolToInt(p.Suppressed), p.CooldownSeconds, p.QuietHoursStart, p.QuietHoursEnd, string(channelsJSON), p.UpdatedAt, p.ID)
		if err != nil {
			return fmt.Errorf("failed to update policy: %w", err)
		}
		rows, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if rows == 0 {
			return fmt.Errorf("policy not found")
		}
		r.logger.Info("Updated policy", slog.Int64("id", p.ID), slog.String("name", p.Name))
	}

	// Audit change
	auditDetails := fmt.Sprintf("Policy Name: %s, Scope: %s, Target: %s, Suppressed: %t, Cooldown: %d", p.Name, p.Scope, p.Target, p.Suppressed, p.CooldownSeconds)
	_ = r.saveAuditLogLocked(ctx, "save_policy", auditDetails)

	return nil
}

// DeletePolicy removes a policy by ID.
func (r *SQLiteRepository) DeletePolicy(ctx context.Context, id int64) error {
	p, err := r.GetPolicy(ctx, id)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	_, err = r.metaDB.ExecContext(ctx, "DELETE FROM policies WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	r.logger.Info("Deleted policy", slog.Int64("id", id))

	// Audit change
	auditDetails := fmt.Sprintf("Policy Name: %s, Scope: %s, Target: %s", p.Name, p.Scope, p.Target)
	_ = r.saveAuditLogLocked(ctx, "delete_policy", auditDetails)

	return nil
}

// GetPolicy retrieves a policy by ID.
func (r *SQLiteRepository) GetPolicy(ctx context.Context, id int64) (*Policy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	row := r.metaDB.QueryRowContext(ctx, "SELECT id, name, scope, target, severity_threshold, suppressed, cooldown_seconds, quiet_hours_start, quiet_hours_end, notification_channels, created_at, updated_at FROM policies WHERE id = ?", id)

	var p Policy
	var suppressedInt int
	var channelsStr string
	err := row.Scan(&p.ID, &p.Name, &p.Scope, &p.Target, &p.SeverityThreshold, &suppressedInt, &p.CooldownSeconds, &p.QuietHoursStart, &p.QuietHoursEnd, &channelsStr, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("policy not found")
		}
		return nil, fmt.Errorf("failed to scan policy: %w", err)
	}
	p.Suppressed = suppressedInt > 0
	_ = json.Unmarshal([]byte(channelsStr), &p.NotificationChannels)
	if p.NotificationChannels == nil {
		p.NotificationChannels = []string{}
	}

	return &p, nil
}

// ListPolicies lists all active policies.
func (r *SQLiteRepository) ListPolicies(ctx context.Context) ([]Policy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listPoliciesLocked(ctx)
}

func (r *SQLiteRepository) listPoliciesLocked(ctx context.Context) ([]Policy, error) {
	rows, err := r.metaDB.QueryContext(ctx, "SELECT id, name, scope, target, severity_threshold, suppressed, cooldown_seconds, quiet_hours_start, quiet_hours_end, notification_channels, created_at, updated_at FROM policies ORDER BY scope, name")
	if err != nil {
		return nil, fmt.Errorf("failed query policies: %w", err)
	}
	defer rows.Close()

	var policies []Policy
	for rows.Next() {
		var p Policy
		var suppressedInt int
		var channelsStr string
		err := rows.Scan(&p.ID, &p.Name, &p.Scope, &p.Target, &p.SeverityThreshold, &suppressedInt, &p.CooldownSeconds, &p.QuietHoursStart, &p.QuietHoursEnd, &channelsStr, &p.CreatedAt, &p.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed scan policy row: %w", err)
		}
		p.Suppressed = suppressedInt > 0
		_ = json.Unmarshal([]byte(channelsStr), &p.NotificationChannels)
		if p.NotificationChannels == nil {
			p.NotificationChannels = []string{}
		}
		policies = append(policies, p)
	}

	return policies, nil
}

// HasRecentAnomaly checks if an anomaly of matching IP and Type was created within the last cooldown period.
func (r *SQLiteRepository) HasRecentAnomaly(ctx context.Context, ip string, anomalyType string, since time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hasRecentAnomalyLocked(ctx, ip, anomalyType, since)
}

func (r *SQLiteRepository) hasRecentAnomalyLocked(ctx context.Context, ip string, anomalyType string, since time.Time) (bool, error) {
	var count int
	err := r.metaDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM anomalies WHERE ip = ? AND type = ? AND created_at >= ?", ip, anomalyType, since.Format(time.RFC3339)).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// evaluateAnomalyPoliciesLocked checks all policies and updates the anomaly status to "silenced" if matching rules suppress it.
func (r *SQLiteRepository) evaluateAnomalyPoliciesLocked(ctx context.Context, a *Anomaly) error {
	policies, err := r.listPoliciesLocked(ctx)
	if err != nil {
		return err
	}

	// 1. Find matching policies
	var matchedPolicies []Policy
	for _, p := range policies {
		matches := false
		switch p.Scope {
		case "global":
			matches = true
		case "ip":
			matches = p.Target == a.IP
		case "subnet":
			_, ipNet, err := net.ParseCIDR(p.Target)
			if err == nil {
				ipObj := net.ParseIP(a.IP)
				if ipObj != nil && ipNet.Contains(ipObj) {
					matches = true
				}
			}
		case "alert_type":
			matches = p.Target == a.Type
		}

		if matches {
			matchedPolicies = append(matchedPolicies, p)
		}
	}

	if len(matchedPolicies) == 0 {
		return nil
	}

	// 2. Precedence sort
	scopePriority := func(scope string) int {
		switch scope {
		case "ip":
			return 4
		case "subnet":
			return 3
		case "alert_type":
			return 2
		case "global":
			return 1
		default:
			return 0
		}
	}

	var bestPolicy Policy
	bestPriority := -1
	for _, p := range matchedPolicies {
		prio := scopePriority(p.Scope)
		if prio > bestPriority {
			bestPriority = prio
			bestPolicy = p
		} else if prio == bestPriority {
			if p.ID > bestPolicy.ID {
				bestPolicy = p
			}
		}
	}

	// 3. Evaluate bestPolicy
	suppress := false
	if bestPolicy.Suppressed {
		suppress = true
		r.logger.Info("Anomaly suppressed by policy silence rule", slog.Int64("policy_id", bestPolicy.ID), slog.String("policy_name", bestPolicy.Name))
	}

	if !suppress && bestPolicy.SeverityThreshold != "" {
		sevPriority := func(sev string) int {
			switch strings.ToLower(sev) {
			case "high":
				return 3
			case "medium":
				return 2
			case "low":
				return 1
			default:
				return 0
			}
		}
		if sevPriority(a.Severity) < sevPriority(bestPolicy.SeverityThreshold) {
			suppress = true
			r.logger.Info("Anomaly suppressed: severity below policy threshold", slog.Int64("policy_id", bestPolicy.ID), slog.String("severity", a.Severity), slog.String("threshold", bestPolicy.SeverityThreshold))
		}
	}

	if !suppress && bestPolicy.QuietHoursStart != "" && bestPolicy.QuietHoursEnd != "" {
		if isTimeInQuietHours(a.CreatedAt, bestPolicy.QuietHoursStart, bestPolicy.QuietHoursEnd) {
			suppress = true
			r.logger.Info("Anomaly suppressed: triggered during quiet hours", slog.Int64("policy_id", bestPolicy.ID), slog.String("start", bestPolicy.QuietHoursStart), slog.String("end", bestPolicy.QuietHoursEnd))
		}
	}

	if !suppress && bestPolicy.CooldownSeconds > 0 {
		since := a.CreatedAt.Add(-time.Duration(bestPolicy.CooldownSeconds) * time.Second)
		hasRecent, err := r.hasRecentAnomalyLocked(ctx, a.IP, a.Type, since)
		if err == nil && hasRecent {
			suppress = true
			r.logger.Info("Anomaly suppressed: matching anomaly occurred within cooldown period", slog.Int64("policy_id", bestPolicy.ID), slog.Int("cooldown_seconds", bestPolicy.CooldownSeconds))
		}
	}

	if suppress {
		a.Status = "silenced"
	}

	return nil
}

func isTimeInQuietHours(t time.Time, startStr, endStr string) bool {
	if startStr == "" || endStr == "" {
		return false
	}
	startParts := strings.Split(startStr, ":")
	endParts := strings.Split(endStr, ":")
	if len(startParts) != 2 || len(endParts) != 2 {
		return false
	}

	var startH, startM, endH, endM int
	fmt.Sscanf(startStr, "%d:%d", &startH, &startM)
	fmt.Sscanf(endStr, "%d:%d", &endH, &endM)

	curH, curM, _ := t.Clock()
	startVal := startH*60 + startM
	endVal := endH*60 + endM
	curVal := curH*60 + curM

	if startVal <= endVal {
		return curVal >= startVal && curVal <= endVal
	} else {
		return curVal >= startVal || curVal <= endVal
	}
}

// GetPoliciesForIP returns all matching policies (global, subnet, IP) for a specific IP.
func (r *SQLiteRepository) GetPoliciesForIP(ctx context.Context, ip string) ([]Policy, error) {
	policies, err := r.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	var matched []Policy
	for _, p := range policies {
		matches := false
		switch p.Scope {
		case "global":
			matches = true
		case "ip":
			matches = p.Target == ip
		case "subnet":
			_, ipNet, err := net.ParseCIDR(p.Target)
			if err == nil {
				ipObj := net.ParseIP(ip)
				if ipObj != nil && ipNet.Contains(ipObj) {
					matches = true
				}
			}
		}
		if matches {
			matched = append(matched, p)
		}
	}
	return matched, nil
}

// SaveNotificationRule persists or updates a notification rule in SQLite.
func (r *SQLiteRepository) SaveNotificationRule(ctx context.Context, rule *NotificationRule) error {
	if rule.Name == "" {
		return fmt.Errorf("notification rule name cannot be empty")
	}

	alertTypesJSON, err := json.Marshal(rule.AlertTypes)
	if err != nil {
		return fmt.Errorf("failed to marshal alert types: %w", err)
	}

	channelTargetsJSON, err := json.Marshal(rule.ChannelTargets)
	if err != nil {
		return fmt.Errorf("failed to marshal channel targets: %w", err)
	}

	now := time.Now()
	rule.UpdatedAt = now

	r.mu.Lock()
	defer r.mu.Unlock()

	if rule.ID == 0 {
		rule.CreatedAt = now
		query := `INSERT INTO notification_rules (name, enabled, severity_min, alert_types, scope, target, cooldown_seconds, channel_targets, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		res, err := r.metaDB.ExecContext(ctx, query,
			rule.Name,
			boolToInt(rule.Enabled),
			rule.SeverityMin,
			string(alertTypesJSON),
			rule.Scope,
			rule.Target,
			rule.CooldownSeconds,
			string(channelTargetsJSON),
			rule.CreatedAt,
			rule.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert notification rule: %w", err)
		}
		id, err := res.LastInsertId()
		if err == nil {
			rule.ID = id
		}
	} else {
		query := `UPDATE notification_rules SET name = ?, enabled = ?, severity_min = ?, alert_types = ?, scope = ?, target = ?, cooldown_seconds = ?, channel_targets = ?, updated_at = ?
		WHERE id = ?`
		res, err := r.metaDB.ExecContext(ctx, query,
			rule.Name,
			boolToInt(rule.Enabled),
			rule.SeverityMin,
			string(alertTypesJSON),
			rule.Scope,
			rule.Target,
			rule.CooldownSeconds,
			string(channelTargetsJSON),
			rule.UpdatedAt,
			rule.ID,
		)
		if err != nil {
			return fmt.Errorf("failed to update notification rule: %w", err)
		}
		rows, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if rows == 0 {
			return fmt.Errorf("notification rule with ID %d not found", rule.ID)
		}
	}
	return nil
}

// DeleteNotificationRule removes a notification rule by ID from SQLite.
func (r *SQLiteRepository) DeleteNotificationRule(ctx context.Context, id int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	res, err := r.metaDB.ExecContext(ctx, "DELETE FROM notification_rules WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete notification rule: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("notification rule with ID %d not found", id)
	}
	return nil
}

// GetNotificationRule retrieves a notification rule by ID from SQLite.
func (r *SQLiteRepository) GetNotificationRule(ctx context.Context, id int64) (*NotificationRule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	query := `SELECT id, name, enabled, severity_min, alert_types, scope, target, cooldown_seconds, channel_targets, created_at, updated_at
	FROM notification_rules WHERE id = ?`
	row := r.metaDB.QueryRowContext(ctx, query, id)

	var rule NotificationRule
	var enabledInt int
	var alertTypesStr, channelTargetsStr string

	err := row.Scan(
		&rule.ID,
		&rule.Name,
		&enabledInt,
		&rule.SeverityMin,
		&alertTypesStr,
		&rule.Scope,
		&rule.Target,
		&rule.CooldownSeconds,
		&channelTargetsStr,
		&rule.CreatedAt,
		&rule.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("notification rule with ID %d not found", id)
	} else if err != nil {
		return nil, fmt.Errorf("failed to scan notification rule: %w", err)
	}

	rule.Enabled = enabledInt != 0
	_ = json.Unmarshal([]byte(alertTypesStr), &rule.AlertTypes)
	if rule.AlertTypes == nil {
		rule.AlertTypes = []string{}
	}
	_ = json.Unmarshal([]byte(channelTargetsStr), &rule.ChannelTargets)
	if rule.ChannelTargets == nil {
		rule.ChannelTargets = []string{}
	}

	return &rule, nil
}

// ListNotificationRules lists all active notification rules from SQLite.
func (r *SQLiteRepository) ListNotificationRules(ctx context.Context) ([]NotificationRule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	query := `SELECT id, name, enabled, severity_min, alert_types, scope, target, cooldown_seconds, channel_targets, created_at, updated_at
	FROM notification_rules ORDER BY name`
	rows, err := r.metaDB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed querying notification rules: %w", err)
	}
	defer rows.Close()

	var rules []NotificationRule
	for rows.Next() {
		var rule NotificationRule
		var enabledInt int
		var alertTypesStr, channelTargetsStr string

		err := rows.Scan(
			&rule.ID,
			&rule.Name,
			&enabledInt,
			&rule.SeverityMin,
			&alertTypesStr,
			&rule.Scope,
			&rule.Target,
			&rule.CooldownSeconds,
			&channelTargetsStr,
			&rule.CreatedAt,
			&rule.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan notification rule: %w", err)
		}

		rule.Enabled = enabledInt != 0
		_ = json.Unmarshal([]byte(alertTypesStr), &rule.AlertTypes)
		if rule.AlertTypes == nil {
			rule.AlertTypes = []string{}
		}
		_ = json.Unmarshal([]byte(channelTargetsStr), &rule.ChannelTargets)
		if rule.ChannelTargets == nil {
			rule.ChannelTargets = []string{}
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// SaveNotificationLog records a notification dispatch outcome in SQLite.
func (r *SQLiteRepository) SaveNotificationLog(ctx context.Context, l *NotificationLog) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if l.DispatchedAt.IsZero() {
		l.DispatchedAt = time.Now()
	}

	query := `INSERT INTO notification_logs (anomaly_id, rule_id, channel, status, error_message, dispatched_at)
	VALUES (?, ?, ?, ?, ?, ?)`
	res, err := r.metaDB.ExecContext(ctx, query,
		l.AnomalyID,
		l.RuleID,
		l.Channel,
		l.Status,
		l.ErrorMessage,
		l.DispatchedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert notification log: %w", err)
	}

	id, err := res.LastInsertId()
	if err == nil {
		l.ID = id
	}
	return nil
}

// ListNotificationLogs returns recent notification logs from SQLite.
func (r *SQLiteRepository) ListNotificationLogs(ctx context.Context, limit int) ([]NotificationLog, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if limit <= 0 {
		limit = 50
	}

	query := `SELECT id, anomaly_id, rule_id, channel, status, error_message, dispatched_at
	FROM notification_logs ORDER BY dispatched_at DESC LIMIT ?`
	rows, err := r.metaDB.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying notification logs: %w", err)
	}
	defer rows.Close()

	var logs []NotificationLog
	for rows.Next() {
		var l NotificationLog
		err := rows.Scan(
			&l.ID,
			&l.AnomalyID,
			&l.RuleID,
			&l.Channel,
			&l.Status,
			&l.ErrorMessage,
			&l.DispatchedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan notification log: %w", err)
		}
		logs = append(logs, l)
	}

	return logs, nil
}

// HasRecentNotification checks if a notification for the same rule/IP/type was sent recently in SQLite.
func (r *SQLiteRepository) HasRecentNotification(ctx context.Context, ruleID int64, ip string, anomalyType string, since time.Time) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	query := `SELECT COUNT(*) FROM notification_logs nl
	JOIN anomalies a ON nl.anomaly_id = a.id
	WHERE nl.rule_id = ? AND a.ip = ? AND a.type = ? AND nl.status = 'sent' AND nl.dispatched_at >= ?`

	var count int
	err := r.metaDB.QueryRowContext(ctx, query, ruleID, ip, anomalyType, since).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to query recent notifications: %w", err)
	}

	return count > 0, nil
}
