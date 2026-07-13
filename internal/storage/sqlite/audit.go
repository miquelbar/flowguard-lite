package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type sqliteAuditExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func saveSQLiteAuditLog(ctx context.Context, execer sqliteAuditExecutor, action string, details string) error {
	tsStr := time.Now().Format(time.RFC3339)
	_, err := execer.ExecContext(ctx, `
		INSERT INTO audit_logs (timestamp, action, details) VALUES (?, ?, ?)
	`, tsStr, action, details)
	if err != nil {
		return fmt.Errorf("failed to save audit log: %w", err)
	}
	return nil
}

func (r *Repository) saveAuditLogLocked(ctx context.Context, action string, details string) error {
	return saveSQLiteAuditLog(ctx, r.metaDB, action, details)
}

// SaveAuditLog writes a security or configuration audit record.
func (r *Repository) SaveAuditLog(ctx context.Context, action string, details string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.saveAuditLogLocked(ctx, action, details)
}

// ListAuditLogs returns a list of recent security audit log records.
func (r *Repository) ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error) {
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating audit logs: %w", err)
	}

	if list == nil {
		list = []AuditLog{}
	}
	return list, nil
}
