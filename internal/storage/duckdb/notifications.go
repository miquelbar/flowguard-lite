package duckdb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/storage/codec"
)

// SaveNotificationRule persists or updates a notification rule in DuckDB.
func (r *Repository) SaveNotificationRule(ctx context.Context, rule *NotificationRule) error {
	if rule.Name == "" {
		return fmt.Errorf("notification rule name cannot be empty")
	}

	alertTypesJSON, err := codec.MarshalStringArray("notification rule alert_types", rule.AlertTypes)
	if err != nil {
		return err
	}

	channelTargetsJSON, err := codec.MarshalStringArray("notification rule channel_targets", rule.ChannelTargets)
	if err != nil {
		return err
	}

	now := time.Now()
	rule.UpdatedAt = now

	r.mu.Lock()
	defer r.mu.Unlock()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start DuckDB notification rule transaction: %w", err)
	}
	defer tx.Rollback()

	if rule.ID == 0 {
		rule.CreatedAt = now
		query := `INSERT INTO notification_rules (name, enabled, severity_min, alert_types, scope, target, cooldown_seconds, channel_targets, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`
		err := tx.QueryRowContext(ctx, query,
			rule.Name,
			boolToInt(rule.Enabled),
			rule.SeverityMin,
			alertTypesJSON,
			rule.Scope,
			rule.Target,
			rule.CooldownSeconds,
			channelTargetsJSON,
			rule.CreatedAt,
			rule.UpdatedAt,
		).Scan(&rule.ID)
		if err != nil {
			return fmt.Errorf("failed to insert notification rule: %w", err)
		}
	} else {
		query := `UPDATE notification_rules SET name = ?, enabled = ?, severity_min = ?, alert_types = ?, scope = ?, target = ?, cooldown_seconds = ?, channel_targets = ?, updated_at = ?
		WHERE id = ?`
		res, err := tx.ExecContext(ctx, query,
			rule.Name,
			boolToInt(rule.Enabled),
			rule.SeverityMin,
			alertTypesJSON,
			rule.Scope,
			rule.Target,
			rule.CooldownSeconds,
			channelTargetsJSON,
			rule.UpdatedAt,
			rule.ID,
		)
		if err != nil {
			return fmt.Errorf("failed to update notification rule: %w", err)
		}
		rows, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if rows == 0 {
			return fmt.Errorf("notification rule with ID %d not found", rule.ID)
		}
	}

	auditDetails := fmt.Sprintf("Notification Rule Name: %s, Scope: %s, Target: %s, Channels: %v", rule.Name, rule.Scope, rule.Target, rule.ChannelTargets)
	if err := saveDuckDBAuditLog(ctx, tx, "save_notification_rule", auditDetails); err != nil {
		return err
	}

	return tx.Commit()
}

// DeleteNotificationRule removes a notification rule by ID from DuckDB.
func (r *Repository) DeleteNotificationRule(ctx context.Context, id int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	rule, err := r.getNotificationRuleLocked(ctx, id)
	if err != nil {
		return err
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start DuckDB notification rule delete transaction: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, "DELETE FROM notification_rules WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete notification rule: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("notification rule with ID %d not found", id)
	}

	auditDetails := fmt.Sprintf("Notification Rule Name: %s, Scope: %s, Target: %s", rule.Name, rule.Scope, rule.Target)
	if err := saveDuckDBAuditLog(ctx, tx, "delete_notification_rule", auditDetails); err != nil {
		return err
	}

	return tx.Commit()
}

// GetNotificationRule retrieves a notification rule by ID from DuckDB.
func (r *Repository) GetNotificationRule(ctx context.Context, id int64) (*NotificationRule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.getNotificationRuleLocked(ctx, id)
}

func (r *Repository) getNotificationRuleLocked(ctx context.Context, id int64) (*NotificationRule, error) {
	query := `SELECT id, name, enabled, severity_min, alert_types, scope, target, cooldown_seconds, channel_targets, created_at, updated_at
	FROM notification_rules WHERE id = ?`
	row := r.db.QueryRowContext(ctx, query, id)

	var rule NotificationRule
	var enabledInt int
	var alertTypesStr, channelTargetsStr string

	err := row.Scan(
		&rule.ID,
		&rule.Name,
		&enabledInt,
		&rule.SeverityMin,
		&alertTypesStr,
		&rule.Scope,
		&rule.Target,
		&rule.CooldownSeconds,
		&channelTargetsStr,
		&rule.CreatedAt,
		&rule.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("notification rule with ID %d not found", id)
	} else if err != nil {
		return nil, fmt.Errorf("failed to scan notification rule: %w", err)
	}

	rule.Enabled = enabledInt != 0
	rule.AlertTypes, err = codec.UnmarshalStringArray("notification rule alert_types", alertTypesStr)
	if err != nil {
		return nil, err
	}
	rule.ChannelTargets, err = codec.UnmarshalStringArray("notification rule channel_targets", channelTargetsStr)
	if err != nil {
		return nil, err
	}

	return &rule, nil
}

// ListNotificationRules lists all active notification rules from DuckDB.
func (r *Repository) ListNotificationRules(ctx context.Context) ([]NotificationRule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	query := `SELECT id, name, enabled, severity_min, alert_types, scope, target, cooldown_seconds, channel_targets, created_at, updated_at
	FROM notification_rules ORDER BY name`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed querying notification rules: %w", err)
	}
	defer rows.Close()

	var rules []NotificationRule
	for rows.Next() {
		var rule NotificationRule
		var enabledInt int
		var alertTypesStr, channelTargetsStr string

		err := rows.Scan(
			&rule.ID,
			&rule.Name,
			&enabledInt,
			&rule.SeverityMin,
			&alertTypesStr,
			&rule.Scope,
			&rule.Target,
			&rule.CooldownSeconds,
			&channelTargetsStr,
			&rule.CreatedAt,
			&rule.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan notification rule: %w", err)
		}

		rule.Enabled = enabledInt != 0
		rule.AlertTypes, err = codec.UnmarshalStringArray("notification rule alert_types", alertTypesStr)
		if err != nil {
			return nil, err
		}
		rule.ChannelTargets, err = codec.UnmarshalStringArray("notification rule channel_targets", channelTargetsStr)
		if err != nil {
			return nil, err
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// SaveNotificationLog records a notification dispatch outcome in DuckDB.
func (r *Repository) SaveNotificationLog(ctx context.Context, l *NotificationLog) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if l.DispatchedAt.IsZero() {
		l.DispatchedAt = time.Now()
	}

	query := `INSERT INTO notification_logs (anomaly_id, rule_id, channel, status, error_message, dispatched_at)
	VALUES (?, ?, ?, ?, ?, ?) RETURNING id`
	err := r.db.QueryRowContext(ctx, query,
		l.AnomalyID,
		l.RuleID,
		l.Channel,
		l.Status,
		l.ErrorMessage,
		l.DispatchedAt,
	).Scan(&l.ID)
	if err != nil {
		return fmt.Errorf("failed to insert notification log: %w", err)
	}

	return nil
}

// ListNotificationLogs returns recent notification logs from DuckDB.
func (r *Repository) ListNotificationLogs(ctx context.Context, limit int) ([]NotificationLog, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if limit <= 0 {
		limit = 50
	}

	query := `SELECT id, anomaly_id, rule_id, channel, status, error_message, dispatched_at
	FROM notification_logs ORDER BY dispatched_at DESC LIMIT ?`
	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying notification logs: %w", err)
	}
	defer rows.Close()

	var logs []NotificationLog
	for rows.Next() {
		var l NotificationLog
		err := rows.Scan(
			&l.ID,
			&l.AnomalyID,
			&l.RuleID,
			&l.Channel,
			&l.Status,
			&l.ErrorMessage,
			&l.DispatchedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan notification log: %w", err)
		}
		logs = append(logs, l)
	}

	return logs, nil
}

// HasRecentNotification checks if a notification for the same rule/IP/type was sent recently in DuckDB.
func (r *Repository) HasRecentNotification(ctx context.Context, ruleID int64, ip string, anomalyType string, since time.Time) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	query := `SELECT COUNT(*) FROM notification_logs nl
	JOIN anomalies a ON nl.anomaly_id = a.id
	WHERE nl.rule_id = ? AND a.ip = ? AND a.type = ? AND nl.status = 'sent' AND nl.dispatched_at >= ?`

	var count int
	err := r.db.QueryRowContext(ctx, query, ruleID, ip, anomalyType, since).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to query recent notifications: %w", err)
	}

	return count > 0, nil
}
