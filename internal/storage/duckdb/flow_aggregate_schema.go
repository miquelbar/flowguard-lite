package duckdb

import (
	"context"
	"database/sql"
	"fmt"
)

func migrateFlowAggregateCollectorColumns(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_name = 'flow_aggregates'
	`)
	if err != nil {
		return fmt.Errorf("inspect DuckDB flow aggregate schema: %w", err)
	}
	defer rows.Close()

	hasCollectorKind := false
	hasCollectorID := false
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("scan DuckDB flow aggregate schema: %w", err)
		}
		switch name {
		case "collector_kind":
			hasCollectorKind = true
		case "collector_id":
			hasCollectorID = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate DuckDB flow aggregate schema: %w", err)
	}
	if hasCollectorKind && hasCollectorID {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin DuckDB flow aggregate schema migration: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `ALTER TABLE flow_aggregates RENAME TO flow_aggregates_legacy`); err != nil {
		return fmt.Errorf("rename DuckDB legacy flow aggregates: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE flow_aggregates (
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
		)
	`); err != nil {
		return fmt.Errorf("create migrated DuckDB flow aggregates: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO flow_aggregates (
			bucket_ts, collector_kind, collector_id, src_ip, dst_ip, dst_port, protocol, bytes, packets, flows
		)
		SELECT bucket_ts, 'unknown', 'unknown', src_ip, dst_ip, dst_port, protocol, bytes, packets, flows
		FROM flow_aggregates_legacy
	`); err != nil {
		return fmt.Errorf("copy DuckDB legacy flow aggregates: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE flow_aggregates_legacy`); err != nil {
		return fmt.Errorf("drop DuckDB legacy flow aggregates: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit DuckDB flow aggregate schema migration: %w", err)
	}
	return nil
}
