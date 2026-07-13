package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

func createFlowAggregateSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS flow_aggregates (
			bucket_ts INTEGER NOT NULL,
			collector_kind TEXT NOT NULL DEFAULT 'unknown',
			collector_id TEXT NOT NULL DEFAULT 'unknown',
			src_ip TEXT NOT NULL,
			dst_ip TEXT NOT NULL,
			dst_port INTEGER NOT NULL,
			protocol INTEGER NOT NULL,
			bytes INTEGER NOT NULL,
			packets INTEGER NOT NULL,
			flows INTEGER NOT NULL,
			PRIMARY KEY (bucket_ts, collector_kind, collector_id, src_ip, dst_ip, dst_port, protocol)
		);
	`)
	if err != nil {
		return fmt.Errorf("create flow aggregate schema: %w", err)
	}
	if err := migrateFlowAggregateCollectorColumns(ctx, db); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_flow_agg_src ON flow_aggregates (src_ip, bytes DESC);
		CREATE INDEX IF NOT EXISTS idx_flow_agg_dst ON flow_aggregates (dst_ip, bytes DESC);
		CREATE INDEX IF NOT EXISTS idx_flow_agg_port ON flow_aggregates (dst_port, bytes DESC);
		CREATE INDEX IF NOT EXISTS idx_flow_agg_collector ON flow_aggregates (collector_kind, collector_id, bucket_ts);
	`)
	if err != nil {
		return fmt.Errorf("create flow aggregate indexes: %w", err)
	}
	return nil
}

func migrateFlowAggregateCollectorColumns(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(flow_aggregates)`)
	if err != nil {
		return fmt.Errorf("inspect flow aggregate schema: %w", err)
	}
	defer rows.Close()

	hasCollectorKind := false
	hasCollectorID := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue interface{}
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return fmt.Errorf("scan flow aggregate schema: %w", err)
		}
		switch name {
		case "collector_kind":
			hasCollectorKind = true
		case "collector_id":
			hasCollectorID = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate flow aggregate schema: %w", err)
	}
	if hasCollectorKind && hasCollectorID {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin flow aggregate schema migration: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `ALTER TABLE flow_aggregates RENAME TO flow_aggregates_legacy`); err != nil {
		return fmt.Errorf("rename legacy flow aggregates: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE flow_aggregates (
			bucket_ts INTEGER NOT NULL,
			collector_kind TEXT NOT NULL DEFAULT 'unknown',
			collector_id TEXT NOT NULL DEFAULT 'unknown',
			src_ip TEXT NOT NULL,
			dst_ip TEXT NOT NULL,
			dst_port INTEGER NOT NULL,
			protocol INTEGER NOT NULL,
			bytes INTEGER NOT NULL,
			packets INTEGER NOT NULL,
			flows INTEGER NOT NULL,
			PRIMARY KEY (bucket_ts, collector_kind, collector_id, src_ip, dst_ip, dst_port, protocol)
		)
	`); err != nil {
		return fmt.Errorf("create migrated flow aggregates: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO flow_aggregates (
			bucket_ts, collector_kind, collector_id, src_ip, dst_ip, dst_port, protocol, bytes, packets, flows
		)
		SELECT bucket_ts, 'unknown', 'unknown', src_ip, dst_ip, dst_port, protocol, bytes, packets, flows
		FROM flow_aggregates_legacy
	`); err != nil {
		return fmt.Errorf("copy legacy flow aggregates: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE flow_aggregates_legacy`); err != nil {
		return fmt.Errorf("drop legacy flow aggregates: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit flow aggregate schema migration: %w", err)
	}
	_, err = db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_flow_agg_src ON flow_aggregates (src_ip, bytes DESC);
		CREATE INDEX IF NOT EXISTS idx_flow_agg_dst ON flow_aggregates (dst_ip, bytes DESC);
		CREATE INDEX IF NOT EXISTS idx_flow_agg_port ON flow_aggregates (dst_port, bytes DESC);
		CREATE INDEX IF NOT EXISTS idx_flow_agg_collector ON flow_aggregates (collector_kind, collector_id, bucket_ts);
	`)
	if err != nil {
		return fmt.Errorf("recreate flow aggregate indexes: %w", err)
	}
	return nil
}
