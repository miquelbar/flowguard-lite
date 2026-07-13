package duckdb

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type duckDBAuditExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func saveDuckDBAuditLog(ctx context.Context, execer duckDBAuditExecutor, action string, details string) error {
	_, err := execer.ExecContext(ctx, `
		INSERT INTO audit_logs (timestamp, action, details) VALUES (?, ?, ?)
	`, time.Now(), action, details)
	if err != nil {
		return fmt.Errorf("failed to save audit log: %w", err)
	}
	return nil
}

func (r *Repository) saveAuditLogLocked(ctx context.Context, action string, details string) error {
	return saveDuckDBAuditLog(ctx, r.db, action, details)
}

// SaveAuditLog writes a security audit record.
func (r *Repository) SaveAuditLog(ctx context.Context, action string, details string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.saveAuditLogLocked(ctx, action, details)
}

// ListAuditLogs returns a list of recent audit log records.
func (r *Repository) ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error) {
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating audit logs: %w", err)
	}
	if list == nil {
		list = []AuditLog{}
	}
	return list, nil
}
