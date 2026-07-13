package duckdb

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	storagepkg "github.com/miquelbar/flowguard-lite/internal/storage"
)

// SaveAnomaly registers a new behavioral alert in DuckDB.
func (r *Repository) SaveAnomaly(ctx context.Context, a *Anomaly) error {
	r.mu.Lock()

	if err := r.evaluateAnomalyPoliciesLocked(ctx, a); err != nil {
		r.mu.Unlock()
		return fmt.Errorf("failed to evaluate anomaly policies for IP %s: %w", a.IP, err)
	}

	var lastId int64
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO anomalies (ip, destination_ip, type, description, severity, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		RETURNING id
	`, a.IP, a.DestinationIP, a.Type, a.Description, a.Severity, a.Status, a.CreatedAt, a.UpdatedAt).Scan(&lastId)
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("failed saving anomaly: %w", err)
	}
	a.ID = lastId

	callbacks := append([]func(a *Anomaly){}, r.onSaveAnomaly...)
	saved := *a
	r.mu.Unlock()

	r.callbacks.Dispatch(r.logger, callbacks, &saved)

	return nil
}

// UpdateAnomalyStatus updates triage status.
func (r *Repository) UpdateAnomalyStatus(ctx context.Context, id int64, status string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	res, err := r.db.ExecContext(ctx, `UPDATE anomalies SET status = ?, updated_at = ? WHERE id = ?`, status, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update anomaly: %w", err)
	}
	rows, err := res.RowsAffected()
	if err == nil && rows == 0 {
		return fmt.Errorf("anomaly not found")
	}
	return nil
}

// ListAnomalies queries recent anomalies triggered.
func (r *Repository) ListAnomalies(ctx context.Context, limit int) ([]Anomaly, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, ip, COALESCE(destination_ip, ''), type, description, severity, status, created_at, updated_at
		FROM anomalies ORDER BY created_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying anomalies: %w", err)
	}
	defer rows.Close()

	var list []Anomaly
	for rows.Next() {
		var a Anomaly
		if err := rows.Scan(&a.ID, &a.IP, &a.DestinationIP, &a.Type, &a.Description, &a.Severity, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed scanning anomaly: %w", err)
		}
		list = append(list, a)
	}
	if list == nil {
		list = []Anomaly{}
	}
	return list, nil
}

// GetActiveAnomalies queries all active anomalies triggered since a given time.
func (r *Repository) GetActiveAnomalies(ctx context.Context, since time.Time) ([]Anomaly, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, ip, COALESCE(destination_ip, ''), type, description, severity, status, created_at, updated_at
		FROM anomalies WHERE status = 'active' AND created_at > ?
	`, since)
	if err != nil {
		return nil, fmt.Errorf("failed querying active anomalies: %w", err)
	}
	defer rows.Close()

	var list []Anomaly
	for rows.Next() {
		var a Anomaly
		if err := rows.Scan(&a.ID, &a.IP, &a.DestinationIP, &a.Type, &a.Description, &a.Severity, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed scanning active anomaly: %w", err)
		}
		list = append(list, a)
	}
	if list == nil {
		list = []Anomaly{}
	}
	return list, nil
}

// RegisterAnomalyCallback registers callback handlers.
func (r *Repository) RegisterAnomalyCallback(cb func(a *Anomaly)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onSaveAnomaly = append(r.onSaveAnomaly, cb)
}

// GetAnomaliesForIP queries recent anomalies associated with a specific IP.
func (r *Repository) GetAnomaliesForIP(ctx context.Context, ip string, limit int) ([]Anomaly, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, ip, COALESCE(destination_ip, ''), type, description, severity, status, created_at, updated_at
		FROM anomalies WHERE ip = ? ORDER BY created_at DESC LIMIT ?
	`, ip, limit)
	if err != nil {
		return nil, fmt.Errorf("failed querying anomalies for IP: %w", err)
	}
	defer rows.Close()

	var list []Anomaly
	for rows.Next() {
		var a Anomaly
		if err := rows.Scan(&a.ID, &a.IP, &a.DestinationIP, &a.Type, &a.Description, &a.Severity, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed scanning anomaly: %w", err)
		}
		list = append(list, a)
	}
	if list == nil {
		list = []Anomaly{}
	}
	return list, nil
}

// HasRecentAnomaly checks if an anomaly of matching IP and Type was created within the last cooldown period.
func (r *Repository) HasRecentAnomaly(ctx context.Context, ip string, anomalyType string, since time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hasRecentAnomalyLocked(ctx, ip, anomalyType, since)
}

func (r *Repository) hasRecentAnomalyLocked(ctx context.Context, ip string, anomalyType string, since time.Time) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM anomalies WHERE ip = ? AND type = ? AND created_at >= ?", ip, anomalyType, since).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// evaluateAnomalyPoliciesLocked checks all policies and updates the anomaly status to "silenced" if matching rules suppress it.
func (r *Repository) evaluateAnomalyPoliciesLocked(ctx context.Context, a *Anomaly) error {
	policies, err := r.listPoliciesLocked(ctx)
	if err != nil {
		return err
	}

	var matchedPolicies []Policy
	for _, p := range policies {
		if p.MatchesAnomaly(a) {
			matchedPolicies = append(matchedPolicies, p)
		}
	}

	if len(matchedPolicies) == 0 {
		return nil
	}

	scopePriority := func(scope string) int {
		switch scope {
		case "ip":
			return 4
		case "subnet":
			return 3
		case "alert_type":
			return 2
		case "global":
			return 1
		default:
			return 0
		}
	}

	var bestPolicy Policy
	bestPriority := -1
	for _, p := range matchedPolicies {
		prio := scopePriority(p.Scope)
		if prio > bestPriority {
			bestPriority = prio
			bestPolicy = p
		} else if prio == bestPriority {
			if p.ID > bestPolicy.ID {
				bestPolicy = p
			}
		}
	}

	suppress := false
	if bestPolicy.Suppressed {
		suppress = true
		r.logger.Info("Anomaly suppressed by policy silence rule in DuckDB", slog.Int64("policy_id", bestPolicy.ID), slog.String("policy_name", bestPolicy.Name))
	}

	if !suppress && bestPolicy.SeverityThreshold != "" {
		sevPriority := func(sev string) int {
			switch strings.ToLower(sev) {
			case "high":
				return 3
			case "medium":
				return 2
			case "low":
				return 1
			default:
				return 0
			}
		}
		if sevPriority(a.Severity) < sevPriority(bestPolicy.SeverityThreshold) {
			suppress = true
			r.logger.Info("Anomaly suppressed in DuckDB: severity below policy threshold", slog.Int64("policy_id", bestPolicy.ID), slog.String("severity", a.Severity), slog.String("threshold", bestPolicy.SeverityThreshold))
		}
	}

	if !suppress && bestPolicy.QuietHoursStart != "" && bestPolicy.QuietHoursEnd != "" {
		if storagepkg.IsTimeInQuietHours(a.CreatedAt, bestPolicy.QuietHoursStart, bestPolicy.QuietHoursEnd) {
			suppress = true
			r.logger.Info("Anomaly suppressed in DuckDB: triggered during quiet hours", slog.Int64("policy_id", bestPolicy.ID), slog.String("start", bestPolicy.QuietHoursStart), slog.String("end", bestPolicy.QuietHoursEnd))
		}
	}

	if !suppress && bestPolicy.CooldownSeconds > 0 {
		since := a.CreatedAt.Add(-time.Duration(bestPolicy.CooldownSeconds) * time.Second)
		hasRecent, err := r.hasRecentAnomalyLocked(ctx, a.IP, a.Type, since)
		if err != nil {
			return err
		}
		if hasRecent {
			suppress = true
			r.logger.Info("Anomaly suppressed in DuckDB: matching anomaly occurred within cooldown period", slog.Int64("policy_id", bestPolicy.ID), slog.Int("cooldown_seconds", bestPolicy.CooldownSeconds))
		}
	}

	if suppress {
		a.Status = "silenced"
	}

	return nil
}
