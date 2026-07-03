package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flowguard/flowguard/internal/flow"
	_ "modernc.org/sqlite"
)

// SQLiteRepository manages Daily SQLite Shards for aggregated flow data.
type SQLiteRepository struct {
	dataDir string
	logger  *slog.Logger

	mu     sync.RWMutex
	shards map[string]*sql.DB
}

// NewSQLiteRepository creates a new SQLite daily shard storage repository.
func NewSQLiteRepository(dataDir string, logger *slog.Logger) (*SQLiteRepository, error) {
	// Create flows directory if not exists
	flowsDir := filepath.Join(dataDir, "flows")
	if err := os.MkdirAll(flowsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create flows storage dir: %w", err)
	}

	return &SQLiteRepository{
		dataDir: flowsDir,
		logger:  logger,
		shards:  make(map[string]*sql.DB),
	}, nil
}

// Close closes all open database connections.
func (r *SQLiteRepository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var firstErr error
	for date, db := range r.shards {
		r.logger.Debug("Closing SQLite shard connection", slog.String("date", date))
		if err := db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	r.shards = make(map[string]*sql.DB)
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
		// Convert time to unix timestamp
		unixTs := agg.Timestamp.Unix()
		_, err := stmt.ExecContext(ctx,
			unixTs,
			agg.SrcIP,
			agg.DstIP,
			agg.DstPort,
			agg.Protocol,
			agg.Bytes,
			agg.Packets,
			agg.Packets, // Flow count initially matches packet count or is 1 for aggregates
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
	dbs, err := r.getShardsInRange(start, end)
	if err != nil {
		return nil, err
	}

	// Query each shard, combine results in memory
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
	dbs, err := r.getShardsInRange(start, end)
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
	dbs, err := r.getShardsInRange(start, end)
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

	// 1. Optimize SQLite performance for high aggregates writes
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

	// 2. Initialize schema tables
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

// Helper: Get list of DB handles active in the date range.
func (r *SQLiteRepository) getShardsInRange(start, end time.Time) ([]*sql.DB, error) {
	var res []*sql.DB

	// Iterate daily step from start date to end date
	curr := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, start.Location())
	limit := time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, end.Location())

	for !curr.After(limit) {
		dateStr := curr.Format("2006-01-02")
		path := filepath.Join(r.dataDir, dateStr+".sqlite")

		// Only query if the file exists on disk, or is already cached
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

		// Convert key (can be string or int) to string key representation
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

	// Map values to slice
	slice := make([]flow.TopResult, 0, len(m))
	for _, val := range m {
		slice = append(slice, *val)
	}

	// Bubble sort or sort package. Bubble/Selection sort here or custom sort to avoid import overhead.
	// Go standard sorting is simple:
	// We can use slices.SortFunc or a simple sorting loop. Let's do a simple sort:
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
