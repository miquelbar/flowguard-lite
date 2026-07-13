package duckdb

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/storage/codec"
)

// SavePolicy persists or updates a custom policy in DuckDB.
func (r *Repository) SavePolicy(ctx context.Context, p *Policy) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}

	channelsJSON, err := codec.MarshalStringArray("policy notification_channels", p.NotificationChannels)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	p.UpdatedAt = now

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start DuckDB policy transaction: %w", err)
	}
	defer tx.Rollback()

	if p.ID == 0 {
		p.CreatedAt = now
		query := `INSERT INTO policies (name, scope, target, severity_threshold, suppressed, cooldown_seconds, quiet_hours_start, quiet_hours_end, notification_channels, created_at, updated_at)
		          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`
		err := tx.QueryRowContext(ctx, query, p.Name, p.Scope, p.Target, p.SeverityThreshold, boolToInt(p.Suppressed), p.CooldownSeconds, p.QuietHoursStart, p.QuietHoursEnd, channelsJSON, p.CreatedAt, p.UpdatedAt).Scan(&p.ID)
		if err != nil {
			return fmt.Errorf("failed to insert policy: %w", err)
		}
		r.logger.Info("Created new policy in DuckDB", slog.Int64("id", p.ID), slog.String("name", p.Name))
	} else {
		query := `UPDATE policies SET name = ?, scope = ?, target = ?, severity_threshold = ?, suppressed = ?, cooldown_seconds = ?, quiet_hours_start = ?, quiet_hours_end = ?, notification_channels = ?, updated_at = ?
		          WHERE id = ?`
		res, err := tx.ExecContext(ctx, query, p.Name, p.Scope, p.Target, p.SeverityThreshold, boolToInt(p.Suppressed), p.CooldownSeconds, p.QuietHoursStart, p.QuietHoursEnd, channelsJSON, p.UpdatedAt, p.ID)
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

	auditDetails := fmt.Sprintf("Policy Name: %s, Scope: %s, Target: %s, Suppressed: %t, Cooldown: %d", p.Name, p.Scope, p.Target, p.Suppressed, p.CooldownSeconds)
	if err := saveDuckDBAuditLog(ctx, tx, "save_policy", auditDetails); err != nil {
		return err
	}

	return tx.Commit()
}

// DeletePolicy removes a policy by ID in DuckDB.
func (r *Repository) DeletePolicy(ctx context.Context, id int64) error {
	p, err := r.GetPolicy(ctx, id)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start DuckDB policy delete transaction: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, "DELETE FROM policies WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("policy not found")
	}

	r.logger.Info("Deleted policy from DuckDB", slog.Int64("id", id))

	auditDetails := fmt.Sprintf("Policy Name: %s, Scope: %s, Target: %s", p.Name, p.Scope, p.Target)
	if err := saveDuckDBAuditLog(ctx, tx, "delete_policy", auditDetails); err != nil {
		return err
	}

	return tx.Commit()
}

// GetPolicy retrieves a policy by ID in DuckDB.
func (r *Repository) GetPolicy(ctx context.Context, id int64) (*Policy, error) {
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
	p.NotificationChannels, err = codec.UnmarshalStringArray("policy notification_channels", channelsStr)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

// ListPolicies lists all active policies in DuckDB.
func (r *Repository) ListPolicies(ctx context.Context) ([]Policy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listPoliciesLocked(ctx)
}

func (r *Repository) listPoliciesLocked(ctx context.Context) ([]Policy, error) {
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
		p.NotificationChannels, err = codec.UnmarshalStringArray("policy notification_channels", channelsStr)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating policies: %w", err)
	}

	return policies, nil
}

// GetPoliciesForIP returns all matching policies (global, subnet, IP) for a specific IP.
func (r *Repository) GetPoliciesForIP(ctx context.Context, ip string) ([]Policy, error) {
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
