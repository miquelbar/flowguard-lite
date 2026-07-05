package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

// SaveAuditLog writes a security audit record.
func (r *DuckDBRepository) SaveAuditLog(ctx context.Context, action string, details string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO audit_logs (timestamp, action, details) VALUES (?, ?, ?)
	`, time.Now(), action, details)
	if err != nil {
		return fmt.Errorf("failed to save audit log: %w", err)
	}
	return nil
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
