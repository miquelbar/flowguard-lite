package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
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

// RegisterAnomalyCallback registers a callback invoked whenever a new anomaly is saved.
func (r *SQLiteRepository) RegisterAnomalyCallback(cb func(a *Anomaly)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onSaveAnomaly = append(r.onSaveAnomaly, cb)
}

// SaveAuditLog writes a security or configuration audit record.
func (r *SQLiteRepository) SaveAuditLog(ctx context.Context, action string, details string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	tsStr := time.Now().Format(time.RFC3339)
	_, err := r.metaDB.ExecContext(ctx, `
		INSERT INTO audit_logs (timestamp, action, details) VALUES (?, ?, ?)
	`, tsStr, action, details)
	if err != nil {
		return fmt.Errorf("failed to save audit log: %w", err)
	}
	return nil
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
