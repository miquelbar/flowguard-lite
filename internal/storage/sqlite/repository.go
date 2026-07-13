package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/storage/callbacks"

	_ "modernc.org/sqlite"
)

// Repository manages Daily SQLite Shards for aggregated flow data and metadata.
type Repository struct {
	dataDir string
	logger  *slog.Logger

	// Persistent Metadata Database
	metaDB *sql.DB

	mu            sync.RWMutex
	shards        map[string]*sql.DB
	onSaveAnomaly []func(a *Anomaly)
	callbacks     callbacks.Dispatcher
}

// NewRepository creates a new SQLite daily shard storage repository.
func NewRepository(dataDir string, logger *slog.Logger) (*Repository, error) {
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
			destination_ip TEXT NOT NULL DEFAULT '',
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

		CREATE TABLE IF NOT EXISTS unifi_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME NOT NULL,
			source_gateway TEXT NOT NULL,
			category TEXT NOT NULL,
			severity TEXT NOT NULL,
			client_ip TEXT NOT NULL DEFAULT '',
			summary TEXT NOT NULL,
			attributes TEXT NOT NULL DEFAULT '{}'
		);
		CREATE INDEX IF NOT EXISTS idx_unifi_events_timestamp ON unifi_events (timestamp DESC);
		CREATE INDEX IF NOT EXISTS idx_unifi_events_client_ip ON unifi_events (client_ip);
	`)
	if err != nil {
		metaDB.Close()
		return nil, fmt.Errorf("failed schema metadata setup: %w", err)
	}
	if _, err := metaDB.Exec(`ALTER TABLE anomalies ADD COLUMN destination_ip TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
		metaDB.Close()
		return nil, fmt.Errorf("failed to migrate anomalies destination_ip column: %w", err)
	}
	if _, err := metaDB.Exec(`CREATE INDEX IF NOT EXISTS idx_anomalies_destination_ip ON anomalies (destination_ip)`); err != nil {
		metaDB.Close()
		return nil, fmt.Errorf("failed to create anomalies destination index: %w", err)
	}

	return &Repository{
		dataDir:   flowsDir,
		logger:    logger,
		metaDB:    metaDB,
		shards:    make(map[string]*sql.DB),
		callbacks: callbacks.NewDispatcher(),
	}, nil
}

// Close closes all open database connections.
func (r *Repository) Close() error {
	r.callbacks.Shutdown(r.logger)

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
func (r *Repository) CleanupRetention(retentionDays int) error {
	r.logger.Info("Running storage retention cleanup...", slog.Int("retention_days", retentionDays))

	// Prune metadata-based unifi_events table
	cutoffTime := time.Now().AddDate(0, 0, -retentionDays).Format(time.RFC3339)
	if _, err := r.metaDB.Exec(`DELETE FROM unifi_events WHERE timestamp < ?`, cutoffTime); err != nil {
		r.logger.Error("Failed to prune expired unifi_events", slog.String("error", err.Error()))
	}

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

// ResetDevelopmentSeed clears demo data so repeated -seed runs stay deterministic.
func (r *Repository) ResetDevelopmentSeed(ctx context.Context) error {
	if err := func() error {
		r.mu.Lock()
		defer r.mu.Unlock()

		tx, err := r.metaDB.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to start development seed metadata transaction: %w", err)
		}
		defer tx.Rollback()

		metaDeletes := []string{
			"DELETE FROM notification_logs",
			"DELETE FROM notification_rules",
			"DELETE FROM policies",
			"DELETE FROM audit_logs",
			"DELETE FROM anomalies",
			"DELETE FROM device_baselines",
			"DELETE FROM devices",
			"DELETE FROM unifi_events",
			"DELETE FROM sqlite_sequence WHERE name IN ('notification_logs', 'notification_rules', 'policies', 'audit_logs', 'anomalies', 'unifi_events')",
		}

		for _, stmt := range metaDeletes {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("failed to clear development seed metadata: %w", err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit development seed metadata reset: %w", err)
		}
		return nil
	}(); err != nil {
		return err
	}

	files, err := os.ReadDir(r.dataDir)
	if err != nil {
		return fmt.Errorf("failed to read flow shard directory: %w", err)
	}
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sqlite") {
			continue
		}
		dateStr := strings.TrimSuffix(file.Name(), ".sqlite")
		db, err := r.getOrCreateShard(dateStr)
		if err != nil {
			return fmt.Errorf("failed to open development seed shard %s: %w", dateStr, err)
		}
		if _, err := db.ExecContext(ctx, "DELETE FROM flow_aggregates"); err != nil {
			return fmt.Errorf("failed to clear development seed shard %s: %w", dateStr, err)
		}
	}

	return nil
}

// Helper: Open / cache daily SQLite shards and verify table schema.
func (r *Repository) getOrCreateShard(dateStr string) (*sql.DB, error) {
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

	if err := createFlowAggregateSchema(context.Background(), db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed schema setup: %w", err)
	}

	r.shards[dateStr] = db
	return db, nil
}

// GetShardsInRange returns list of DB handles active in the date range.
func (r *Repository) GetShardsInRange(start, end time.Time) ([]*sql.DB, error) {
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
