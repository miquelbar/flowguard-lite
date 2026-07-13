package duckdb

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

	_ "github.com/duckdb/duckdb-go/v2"
)

// Repository implements the storage.StorageRepository interface using a single DuckDB database.
type Repository struct {
	dataDir       string
	logger        *slog.Logger
	db            *sql.DB
	mu            sync.RWMutex
	onSaveAnomaly []func(a *Anomaly)
	callbacks     callbacks.Dispatcher
}

// NewRepository creates a new DuckDB storage repository.
func NewRepository(dataDir string, logger *slog.Logger) (*Repository, error) {
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
			destination_ip VARCHAR NOT NULL DEFAULT '',
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
			collector_kind VARCHAR NOT NULL DEFAULT 'unknown',
			collector_id VARCHAR NOT NULL DEFAULT 'unknown',
			src_ip VARCHAR NOT NULL,
			dst_ip VARCHAR NOT NULL,
			dst_port INTEGER NOT NULL,
			protocol INTEGER NOT NULL,
			bytes BIGINT NOT NULL,
			packets BIGINT NOT NULL,
			flows BIGINT NOT NULL,
			PRIMARY KEY (bucket_ts, collector_kind, collector_id, src_ip, dst_ip, dst_port, protocol)
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

		CREATE SEQUENCE IF NOT EXISTS seq_unifi_events_id;
		CREATE TABLE IF NOT EXISTS unifi_events (
			id INTEGER DEFAULT nextval('seq_unifi_events_id') PRIMARY KEY,
			timestamp TIMESTAMP NOT NULL,
			source_gateway VARCHAR NOT NULL,
			category VARCHAR NOT NULL,
			severity VARCHAR NOT NULL,
			client_ip VARCHAR NOT NULL DEFAULT '',
			summary VARCHAR NOT NULL,
			attributes VARCHAR NOT NULL DEFAULT '{}'
		);
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize DuckDB schema: %w", err)
	}
	if err := migrateFlowAggregateCollectorColumns(context.Background(), db); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`ALTER TABLE anomalies ADD COLUMN destination_ip VARCHAR DEFAULT ''`); err != nil && !strings.Contains(strings.ToLower(err.Error()), "already exists") && !strings.Contains(strings.ToLower(err.Error()), "duplicate") {
		db.Close()
		return nil, fmt.Errorf("failed to migrate DuckDB anomalies destination_ip column: %w", err)
	}

	return &Repository{
		dataDir:   dataDir,
		logger:    logger,
		db:        db,
		callbacks: callbacks.NewDispatcher(),
	}, nil
}

// Close closes the DuckDB database safely.
func (r *Repository) Close() error {
	r.callbacks.Shutdown(r.logger)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

// CleanupRetention deletes flow aggregates older than the specified retention days.
func (r *Repository) CleanupRetention(retentionDays int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().AddDate(0, 0, -retentionDays).Unix()
	_, err := r.db.Exec(`DELETE FROM flow_aggregates WHERE bucket_ts < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("failed to prune flow aggregates in DuckDB: %w", err)
	}

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)
	_, err = r.db.Exec(`DELETE FROM unifi_events WHERE timestamp < ?`, cutoffTime)
	if err != nil {
		return fmt.Errorf("failed to prune unifi_events in DuckDB: %w", err)
	}

	r.logger.Info("Pruned historical flow aggregates and unifi_events in DuckDB successfully", slog.Int("retention_days", retentionDays))
	return nil
}

// ResetDevelopmentSeed clears demo data so repeated -seed runs stay deterministic.
func (r *Repository) ResetDevelopmentSeed(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	deletes := []string{
		"DELETE FROM notification_logs",
		"DELETE FROM notification_rules",
		"DELETE FROM policies",
		"DELETE FROM audit_logs",
		"DELETE FROM anomalies",
		"DELETE FROM device_baselines",
		"DELETE FROM devices",
		"DELETE FROM flow_aggregates",
		"DELETE FROM unifi_events",
	}
	for _, stmt := range deletes {
		if _, err := r.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to clear development seed data in DuckDB: %w", err)
		}
	}

	return nil
}

// SaveAggregates writes a slice of aggregated flow records to the single flow_aggregates table.
