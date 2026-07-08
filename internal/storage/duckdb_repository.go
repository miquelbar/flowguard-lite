package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
	"github.com/flowguard/flowguard/internal/flow"
)

// DuckDBRepository implements the storage.StorageRepository interface using a single DuckDB database.
type DuckDBRepository struct {
	dataDir       string
	logger        *slog.Logger
	db            *sql.DB
	mu            sync.RWMutex
	onSaveAnomaly []func(a *Anomaly)
}

// NewDuckDBRepository creates a new DuckDB storage repository.
func NewDuckDBRepository(dataDir string, logger *slog.Logger) (*DuckDBRepository, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage dir: %w", err)
	}

	dbPath := filepath.Join(dataDir, "flowguard.duckdb")
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open DuckDB database: %w", err)
	}

	// Initialize tables and sequences
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS devices (
			ip VARCHAR PRIMARY KEY,
			label VARCHAR NOT NULL DEFAULT '',
			hostname VARCHAR NOT NULL DEFAULT '',
			vendor VARCHAR NOT NULL DEFAULT '',
			first_seen VARCHAR NOT NULL,
			last_seen VARCHAR NOT NULL
		);

		CREATE TABLE IF NOT EXISTS device_baselines (
			ip VARCHAR PRIMARY KEY,
			mean_bytes DOUBLE NOT NULL DEFAULT 0,
			stddev_bytes DOUBLE NOT NULL DEFAULT 0,
			mean_packets DOUBLE NOT NULL DEFAULT 0,
			stddev_packets DOUBLE NOT NULL DEFAULT 0,
			mean_peers DOUBLE NOT NULL DEFAULT 0,
			stddev_peers DOUBLE NOT NULL DEFAULT 0,
			updated_at TIMESTAMP NOT NULL
		);

		CREATE SEQUENCE IF NOT EXISTS seq_anomalies_id;
		CREATE TABLE IF NOT EXISTS anomalies (
			id INTEGER DEFAULT nextval('seq_anomalies_id') PRIMARY KEY,
			ip VARCHAR NOT NULL,
			type VARCHAR NOT NULL,
			description VARCHAR NOT NULL,
			severity VARCHAR NOT NULL DEFAULT 'medium',
			status VARCHAR NOT NULL DEFAULT 'active',
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);

		CREATE SEQUENCE IF NOT EXISTS seq_audit_logs_id;
		CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER DEFAULT nextval('seq_audit_logs_id') PRIMARY KEY,
			timestamp TIMESTAMP NOT NULL,
			action VARCHAR NOT NULL,
			details VARCHAR NOT NULL
		);

		CREATE SEQUENCE IF NOT EXISTS seq_policies_id;
		CREATE TABLE IF NOT EXISTS policies (
			id INTEGER DEFAULT nextval('seq_policies_id') PRIMARY KEY,
			name VARCHAR NOT NULL,
			scope VARCHAR NOT NULL,
			target VARCHAR NOT NULL,
			severity_threshold VARCHAR NOT NULL DEFAULT '',
			suppressed INTEGER NOT NULL DEFAULT 0,
			cooldown_seconds INTEGER NOT NULL DEFAULT 0,
			quiet_hours_start VARCHAR NOT NULL DEFAULT '',
			quiet_hours_end VARCHAR NOT NULL DEFAULT '',
			notification_channels VARCHAR NOT NULL DEFAULT '[]',
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);

		CREATE TABLE IF NOT EXISTS flow_aggregates (
			bucket_ts BIGINT NOT NULL,
			src_ip VARCHAR NOT NULL,
			dst_ip VARCHAR NOT NULL,
			dst_port INTEGER NOT NULL,
			protocol INTEGER NOT NULL,
			bytes BIGINT NOT NULL,
			packets BIGINT NOT NULL,
			flows BIGINT NOT NULL,
			PRIMARY KEY (bucket_ts, src_ip, dst_ip, dst_port, protocol)
		);

		CREATE SEQUENCE IF NOT EXISTS seq_notification_rules_id;
		CREATE TABLE IF NOT EXISTS notification_rules (
			id INTEGER DEFAULT nextval('seq_notification_rules_id') PRIMARY KEY,
			name VARCHAR NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			severity_min VARCHAR NOT NULL DEFAULT 'low',
			alert_types VARCHAR NOT NULL DEFAULT '[]',
			scope VARCHAR NOT NULL DEFAULT 'global',
			target VARCHAR NOT NULL DEFAULT '',
			cooldown_seconds INTEGER NOT NULL DEFAULT 300,
			channel_targets VARCHAR NOT NULL DEFAULT '[]',
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);

		CREATE SEQUENCE IF NOT EXISTS seq_notification_logs_id;
		CREATE TABLE IF NOT EXISTS notification_logs (
			id INTEGER DEFAULT nextval('seq_notification_logs_id') PRIMARY KEY,
			anomaly_id INTEGER NOT NULL,
			rule_id INTEGER,
			channel VARCHAR NOT NULL,
			status VARCHAR NOT NULL,
			error_message VARCHAR,
			dispatched_at TIMESTAMP NOT NULL
		);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize DuckDB schema: %w", err)
	}

	return &DuckDBRepository{
		dataDir: dataDir,
		logger:  logger,
		db:      db,
	}, nil
}

// Close closes the DuckDB database safely.
func (r *DuckDBRepository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

// CleanupRetention deletes flow aggregates older than the specified retention days.
func (r *DuckDBRepository) CleanupRetention(retentionDays int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().AddDate(0, 0, -retentionDays).Unix()
	_, err := r.db.Exec(`DELETE FROM flow_aggregates WHERE bucket_ts < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("failed to prune flow aggregates in DuckDB: %w", err)
	}
	r.logger.Info("Pruned historical flow aggregates in DuckDB successfully", slog.Int("retention_days", retentionDays))
	return nil
}

// SaveAggregates writes a slice of aggregated flow records to the single flow_aggregates table.
func (r *DuckDBRepository) SaveAggregates(ctx context.Context, ts time.Time, aggregates []flow.FlowEvent) error {
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
		INSERT INTO flow_aggregates (bucket_ts, src_ip, dst_ip, dst_port, protocol, bytes, packets, flows)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (bucket_ts, src_ip, dst_ip, dst_port, protocol) DO UPDATE SET
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
		_, err = stmt.ExecContext(ctx,
			bucketUnix,
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
func (r *DuckDBRepository) GetTopSources(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
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
func (r *DuckDBRepository) GetTopDestinations(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
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
func (r *DuckDBRepository) GetTopPorts(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
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
func (r *DuckDBRepository) GetTopProtocols(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
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
func (r *DuckDBRepository) GetTopDevicesByVolume(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
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
	return sortAndLimit(merged, limit), nil
}

func (r *DuckDBRepository) filterTopResultsToKnownDevices(ctx context.Context, merged map[string]*flow.TopResult) {
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
func (r *DuckDBRepository) GetTrafficTimeSeries(ctx context.Context, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error) {
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

// GetDeviceActivityHeatmap returns hour-of-day traffic activity for the top device-like IPs.
func (r *DuckDBRepository) GetDeviceActivityHeatmap(ctx context.Context, start, end time.Time, limit int) ([]flow.DeviceHeatmapCell, error) {
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

// UpsertDevice inserts or updates device details.
func (r *DuckDBRepository) UpsertDevice(ctx context.Context, ip string, hostname string, lastSeen time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	lastSeenStr := lastSeen.Format(time.RFC3339)

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO devices (ip, hostname, first_seen, last_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (ip) DO UPDATE SET
			last_seen = ?,
			hostname = CASE WHEN ? != '' THEN ? ELSE hostname END
	`, ip, hostname, lastSeenStr, lastSeenStr, lastSeenStr, hostname, hostname)
	if err != nil {
		return fmt.Errorf("failed to upsert device: %w", err)
	}
	return nil
}

// UpdateDeviceLabel updates a device's name label.
func (r *DuckDBRepository) UpdateDeviceLabel(ctx context.Context, ip string, label string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	res, err := r.db.ExecContext(ctx, `UPDATE devices SET label = ? WHERE ip = ?`, label, ip)
	if err != nil {
		return fmt.Errorf("failed to update device label: %w", err)
	}
	rows, err := res.RowsAffected()
	if err == nil && rows == 0 {
		return fmt.Errorf("device not found")
	}
	return nil
}

// GetDevice fetches details of a single device.
func (r *DuckDBRepository) GetDevice(ctx context.Context, ip string) (*Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var d Device
	var firstSeenStr, lastSeenStr string

	err := r.db.QueryRowContext(ctx, `
		SELECT ip, label, hostname, vendor, first_seen, last_seen
		FROM devices
		WHERE ip = ?
	`, ip).Scan(&d.IP, &d.Label, &d.Hostname, &d.Vendor, &firstSeenStr, &lastSeenStr)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query device %s: %w", ip, err)
	}

	if t, err := time.Parse(time.RFC3339, firstSeenStr); err == nil {
		d.FirstSeen = t
	}
	if t, err := time.Parse(time.RFC3339, lastSeenStr); err == nil {
		d.LastSeen = t
	}

	return &d, nil
}

// ListDevices returns all discovered local devices.
func (r *DuckDBRepository) ListDevices(ctx context.Context) ([]Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT ip, label, hostname, vendor, first_seen, last_seen
		FROM devices
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed listing devices from DuckDB: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		var firstSeenStr, lastSeenStr string
		if err := rows.Scan(&d.IP, &d.Label, &d.Hostname, &d.Vendor, &firstSeenStr, &lastSeenStr); err != nil {
			return nil, fmt.Errorf("failed scanning device from DuckDB: %w", err)
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

// SaveBaseline stores baseline statistical behavior limits.
func (r *DuckDBRepository) SaveBaseline(ctx context.Context, b *DeviceBaseline) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO device_baselines (ip, mean_bytes, stddev_bytes, mean_packets, stddev_packets, mean_peers, stddev_peers, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (ip) DO UPDATE SET
			mean_bytes = excluded.mean_bytes,
			stddev_bytes = excluded.stddev_bytes,
			mean_packets = excluded.mean_packets,
			stddev_packets = excluded.stddev_packets,
			mean_peers = excluded.mean_peers,
			stddev_peers = excluded.stddev_peers,
			updated_at = excluded.updated_at
	`, b.IP, b.MeanBytes, b.StdDevBytes, b.MeanPackets, b.StdDevPackets, b.MeanPeers, b.StdDevPeers, b.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed saving baseline: %w", err)
	}
	return nil
}

// GetBaseline retrieves the behavioral baseline profile for a device.
func (r *DuckDBRepository) GetBaseline(ctx context.Context, ip string) (*DeviceBaseline, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	row := r.db.QueryRowContext(ctx, `
		SELECT ip, mean_bytes, stddev_bytes, mean_packets, stddev_packets, mean_peers, stddev_peers, updated_at
		FROM device_baselines WHERE ip = ?
	`, ip)

	var b DeviceBaseline
	err := row.Scan(&b.IP, &b.MeanBytes, &b.StdDevBytes, &b.MeanPackets, &b.StdDevPackets, &b.MeanPeers, &b.StdDevPeers, &b.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("baseline not found")
		}
		return nil, fmt.Errorf("failed fetching baseline: %w", err)
	}
	return &b, nil
}

// SaveAnomaly registers a new behavioral alert in DuckDB.
func (r *DuckDBRepository) SaveAnomaly(ctx context.Context, a *Anomaly) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Evaluate policies to potentially silence the anomaly before saving
	if err := r.evaluateAnomalyPoliciesLocked(ctx, a); err != nil {
		r.logger.Warn("Failed to evaluate anomaly policies in DuckDB", slog.String("ip", a.IP), slog.String("type", a.Type), slog.String("error", err.Error()))
	}

	var lastId int64
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO anomalies (ip, type, description, severity, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		RETURNING id
	`, a.IP, a.Type, a.Description, a.Severity, a.Status, a.CreatedAt, a.UpdatedAt).Scan(&lastId)
	if err != nil {
		return fmt.Errorf("failed saving anomaly: %w", err)
	}
	a.ID = lastId

	// Trigger callbacks in background
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

// UpdateAnomalyStatus updates triage status.
func (r *DuckDBRepository) UpdateAnomalyStatus(ctx context.Context, id int64, status string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	res, err := r.db.ExecContext(ctx, `UPDATE anomalies SET status = ?, updated_at = ? WHERE id = ?`, status, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update anomaly: %w", err)
	}
	rows, err := res.RowsAffected()
	if err == nil && rows == 0 {
		return fmt.Errorf("anomaly not found")
	}
	return nil
}

// ListAnomalies queries recent anomalies triggered.
func (r *DuckDBRepository) ListAnomalies(ctx context.Context, limit int) ([]Anomaly, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, ip, type, description, severity, status, created_at, updated_at
		FROM anomalies ORDER BY created_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying anomalies: %w", err)
	}
	defer rows.Close()

	var list []Anomaly
	for rows.Next() {
		var a Anomaly
		if err := rows.Scan(&a.ID, &a.IP, &a.Type, &a.Description, &a.Severity, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed scanning anomaly: %w", err)
		}
		list = append(list, a)
	}
	if list == nil {
		list = []Anomaly{}
	}
	return list, nil
}

// GetActiveAnomalies queries all active anomalies triggered since a given time.
func (r *DuckDBRepository) GetActiveAnomalies(ctx context.Context, since time.Time) ([]Anomaly, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, ip, type, description, severity, status, created_at, updated_at
		FROM anomalies WHERE status = 'active' AND created_at > ?
	`, since)
	if err != nil {
		return nil, fmt.Errorf("failed querying active anomalies: %w", err)
	}
	defer rows.Close()

	var list []Anomaly
	for rows.Next() {
		var a Anomaly
		if err := rows.Scan(&a.ID, &a.IP, &a.Type, &a.Description, &a.Severity, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed scanning active anomaly: %w", err)
		}
		list = append(list, a)
	}
	if list == nil {
		list = []Anomaly{}
	}
	return list, nil
}

// RegisterAnomalyCallback registers callback handlers.
func (r *DuckDBRepository) RegisterAnomalyCallback(cb func(a *Anomaly)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onSaveAnomaly = append(r.onSaveAnomaly, cb)
}

func (r *DuckDBRepository) saveAuditLogLocked(ctx context.Context, action string, details string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO audit_logs (timestamp, action, details) VALUES (?, ?, ?)
	`, time.Now(), action, details)
	if err != nil {
		return fmt.Errorf("failed to save audit log: %w", err)
	}
	return nil
}

// SaveAuditLog writes a security audit record.
func (r *DuckDBRepository) SaveAuditLog(ctx context.Context, action string, details string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.saveAuditLogLocked(ctx, action, details)
}

// ListAuditLogs returns a list of recent audit log records.
func (r *DuckDBRepository) ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, timestamp, action, details FROM audit_logs ORDER BY timestamp DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying audit logs: %w", err)
	}
	defer rows.Close()

	var list []AuditLog
	for rows.Next() {
		var l AuditLog
		if err := rows.Scan(&l.ID, &l.Timestamp, &l.Action, &l.Details); err != nil {
			return nil, fmt.Errorf("failed scanning audit log: %w", err)
		}
		list = append(list, l)
	}
	if list == nil {
		list = []AuditLog{}
	}
	return list, nil
}

// GetAnomaliesForIP queries recent anomalies associated with a specific IP.
func (r *DuckDBRepository) GetAnomaliesForIP(ctx context.Context, ip string, limit int) ([]Anomaly, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, ip, type, description, severity, status, created_at, updated_at
		FROM anomalies WHERE ip = ? ORDER BY created_at DESC LIMIT ?
	`, ip, limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying anomalies for IP: %w", err)
	}
	defer rows.Close()

	var list []Anomaly
	for rows.Next() {
		var a Anomaly
		if err := rows.Scan(&a.ID, &a.IP, &a.Type, &a.Description, &a.Severity, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed scanning anomaly: %w", err)
		}
		list = append(list, a)
	}
	if list == nil {
		list = []Anomaly{}
	}
	return list, nil
}

// GetDeviceTrafficTimeSeries returns total traffic counters for a specific IP grouped into fixed-size bounded time buckets.
func (r *DuckDBRepository) GetDeviceTrafficTimeSeries(ctx context.Context, ip string, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error) {
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
func (r *DuckDBRepository) GetDeviceTopPeers(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error) {
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
func (r *DuckDBRepository) GetDeviceTopPorts(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error) {
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

// SavePolicy persists or updates a custom policy in DuckDB.
func (r *DuckDBRepository) SavePolicy(ctx context.Context, p *Policy) error {
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
		          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`
		err := r.db.QueryRowContext(ctx, query, p.Name, p.Scope, p.Target, p.SeverityThreshold, boolToInt(p.Suppressed), p.CooldownSeconds, p.QuietHoursStart, p.QuietHoursEnd, string(channelsJSON), p.CreatedAt, p.UpdatedAt).Scan(&p.ID)
		if err != nil {
			return fmt.Errorf("failed to insert policy: %w", err)
		}
		r.logger.Info("Created new policy in DuckDB", slog.Int64("id", p.ID), slog.String("name", p.Name))
	} else {
		query := `UPDATE policies SET name = ?, scope = ?, target = ?, severity_threshold = ?, suppressed = ?, cooldown_seconds = ?, quiet_hours_start = ?, quiet_hours_end = ?, notification_channels = ?, updated_at = ?
		          WHERE id = ?`
		res, err := r.db.ExecContext(ctx, query, p.Name, p.Scope, p.Target, p.SeverityThreshold, boolToInt(p.Suppressed), p.CooldownSeconds, p.QuietHoursStart, p.QuietHoursEnd, string(channelsJSON), p.UpdatedAt, p.ID)
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
		r.logger.Info("Updated policy in DuckDB", slog.Int64("id", p.ID), slog.String("name", p.Name))
	}

	// Audit change
	auditDetails := fmt.Sprintf("Policy Name: %s, Scope: %s, Target: %s, Suppressed: %t, Cooldown: %d", p.Name, p.Scope, p.Target, p.Suppressed, p.CooldownSeconds)
	_ = r.saveAuditLogLocked(ctx, "save_policy", auditDetails)

	return nil
}

// DeletePolicy removes a policy by ID in DuckDB.
func (r *DuckDBRepository) DeletePolicy(ctx context.Context, id int64) error {
	p, err := r.GetPolicy(ctx, id)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	_, err = r.db.ExecContext(ctx, "DELETE FROM policies WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	r.logger.Info("Deleted policy from DuckDB", slog.Int64("id", id))

	// Audit change
	auditDetails := fmt.Sprintf("Policy Name: %s, Scope: %s, Target: %s", p.Name, p.Scope, p.Target)
	_ = r.saveAuditLogLocked(ctx, "delete_policy", auditDetails)

	return nil
}

// GetPolicy retrieves a policy by ID in DuckDB.
func (r *DuckDBRepository) GetPolicy(ctx context.Context, id int64) (*Policy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	row := r.db.QueryRowContext(ctx, "SELECT id, name, scope, target, severity_threshold, suppressed, cooldown_seconds, quiet_hours_start, quiet_hours_end, notification_channels, created_at, updated_at FROM policies WHERE id = ?", id)

	var p Policy
	var suppressedInt int
	var channelsStr string
	err := row.Scan(&p.ID, &p.Name, &p.Scope, &p.Target, &p.SeverityThreshold, &suppressedInt, &p.CooldownSeconds, &p.QuietHoursStart, &p.QuietHoursEnd, &channelsStr, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
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

// ListPolicies lists all active policies in DuckDB.
func (r *DuckDBRepository) ListPolicies(ctx context.Context) ([]Policy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listPoliciesLocked(ctx)
}

func (r *DuckDBRepository) listPoliciesLocked(ctx context.Context) ([]Policy, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, name, scope, target, severity_threshold, suppressed, cooldown_seconds, quiet_hours_start, quiet_hours_end, notification_channels, created_at, updated_at FROM policies ORDER BY scope, name")
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
func (r *DuckDBRepository) HasRecentAnomaly(ctx context.Context, ip string, anomalyType string, since time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hasRecentAnomalyLocked(ctx, ip, anomalyType, since)
}

func (r *DuckDBRepository) hasRecentAnomalyLocked(ctx context.Context, ip string, anomalyType string, since time.Time) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM anomalies WHERE ip = ? AND type = ? AND created_at >= ?", ip, anomalyType, since).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// evaluateAnomalyPoliciesLocked checks all policies and updates the anomaly status to "silenced" if matching rules suppress it.
func (r *DuckDBRepository) evaluateAnomalyPoliciesLocked(ctx context.Context, a *Anomaly) error {
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
		r.logger.Info("Anomaly suppressed by policy silence rule in DuckDB", slog.Int64("policy_id", bestPolicy.ID), slog.String("policy_name", bestPolicy.Name))
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
			r.logger.Info("Anomaly suppressed in DuckDB: severity below policy threshold", slog.Int64("policy_id", bestPolicy.ID), slog.String("severity", a.Severity), slog.String("threshold", bestPolicy.SeverityThreshold))
		}
	}

	if !suppress && bestPolicy.QuietHoursStart != "" && bestPolicy.QuietHoursEnd != "" {
		if isTimeInQuietHours(a.CreatedAt, bestPolicy.QuietHoursStart, bestPolicy.QuietHoursEnd) {
			suppress = true
			r.logger.Info("Anomaly suppressed in DuckDB: triggered during quiet hours", slog.Int64("policy_id", bestPolicy.ID), slog.String("start", bestPolicy.QuietHoursStart), slog.String("end", bestPolicy.QuietHoursEnd))
		}
	}

	if !suppress && bestPolicy.CooldownSeconds > 0 {
		since := a.CreatedAt.Add(-time.Duration(bestPolicy.CooldownSeconds) * time.Second)
		hasRecent, err := r.hasRecentAnomalyLocked(ctx, a.IP, a.Type, since)
		if err == nil && hasRecent {
			suppress = true
			r.logger.Info("Anomaly suppressed in DuckDB: matching anomaly occurred within cooldown period", slog.Int64("policy_id", bestPolicy.ID), slog.Int("cooldown_seconds", bestPolicy.CooldownSeconds))
		}
	}

	if suppress {
		a.Status = "silenced"
	}

	return nil
}

// GetPoliciesForIP returns all matching policies (global, subnet, IP) for a specific IP.
func (r *DuckDBRepository) GetPoliciesForIP(ctx context.Context, ip string) ([]Policy, error) {
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

// SaveNotificationRule persists or updates a notification rule in DuckDB.
func (r *DuckDBRepository) SaveNotificationRule(ctx context.Context, rule *NotificationRule) error {
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
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`
		err := r.db.QueryRowContext(ctx, query,
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
		).Scan(&rule.ID)
		if err != nil {
			return fmt.Errorf("failed to insert notification rule: %w", err)
		}
	} else {
		query := `UPDATE notification_rules SET name = ?, enabled = ?, severity_min = ?, alert_types = ?, scope = ?, target = ?, cooldown_seconds = ?, channel_targets = ?, updated_at = ?
		WHERE id = ?`
		res, err := r.db.ExecContext(ctx, query,
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

// DeleteNotificationRule removes a notification rule by ID from DuckDB.
func (r *DuckDBRepository) DeleteNotificationRule(ctx context.Context, id int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	res, err := r.db.ExecContext(ctx, "DELETE FROM notification_rules WHERE id = ?", id)
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

// GetNotificationRule retrieves a notification rule by ID from DuckDB.
func (r *DuckDBRepository) GetNotificationRule(ctx context.Context, id int64) (*NotificationRule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	query := `SELECT id, name, enabled, severity_min, alert_types, scope, target, cooldown_seconds, channel_targets, created_at, updated_at
	FROM notification_rules WHERE id = ?`
	row := r.db.QueryRowContext(ctx, query, id)

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

// ListNotificationRules lists all active notification rules from DuckDB.
func (r *DuckDBRepository) ListNotificationRules(ctx context.Context) ([]NotificationRule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	query := `SELECT id, name, enabled, severity_min, alert_types, scope, target, cooldown_seconds, channel_targets, created_at, updated_at
	FROM notification_rules ORDER BY name`
	rows, err := r.db.QueryContext(ctx, query)
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

// SaveNotificationLog records a notification dispatch outcome in DuckDB.
func (r *DuckDBRepository) SaveNotificationLog(ctx context.Context, l *NotificationLog) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if l.DispatchedAt.IsZero() {
		l.DispatchedAt = time.Now()
	}

	query := `INSERT INTO notification_logs (anomaly_id, rule_id, channel, status, error_message, dispatched_at)
	VALUES (?, ?, ?, ?, ?, ?) RETURNING id`
	err := r.db.QueryRowContext(ctx, query,
		l.AnomalyID,
		l.RuleID,
		l.Channel,
		l.Status,
		l.ErrorMessage,
		l.DispatchedAt,
	).Scan(&l.ID)
	if err != nil {
		return fmt.Errorf("failed to insert notification log: %w", err)
	}

	return nil
}

// ListNotificationLogs returns recent notification logs from DuckDB.
func (r *DuckDBRepository) ListNotificationLogs(ctx context.Context, limit int) ([]NotificationLog, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if limit <= 0 {
		limit = 50
	}

	query := `SELECT id, anomaly_id, rule_id, channel, status, error_message, dispatched_at
	FROM notification_logs ORDER BY dispatched_at DESC LIMIT ?`
	rows, err := r.db.QueryContext(ctx, query, limit)
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

// HasRecentNotification checks if a notification for the same rule/IP/type was sent recently in DuckDB.
func (r *DuckDBRepository) HasRecentNotification(ctx context.Context, ruleID int64, ip string, anomalyType string, since time.Time) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	query := `SELECT COUNT(*) FROM notification_logs nl
	JOIN anomalies a ON nl.anomaly_id = a.id
	WHERE nl.rule_id = ? AND a.ip = ? AND a.type = ? AND nl.status = 'sent' AND nl.dispatched_at >= ?`

	var count int
	err := r.db.QueryRowContext(ctx, query, ruleID, ip, anomalyType, since).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to query recent notifications: %w", err)
	}

	return count > 0, nil
}
