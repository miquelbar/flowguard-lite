package duckdb

import (
	"context"
	"encoding/json"
	"fmt"
)

// SaveUniFiEvent persists a reduced UniFi SIEM event to the database.
func (r *Repository) SaveUniFiEvent(ctx context.Context, e *UniFiEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	attrBytes, err := json.Marshal(e.Attributes)
	if err != nil {
		return fmt.Errorf("failed to marshal UniFi event attributes: %w", err)
	}
	if e.Attributes == nil {
		attrBytes = []byte("{}")
	}

	var lastId int64
	err = r.db.QueryRowContext(ctx, `
		INSERT INTO unifi_events (timestamp, source_gateway, category, severity, client_ip, summary, attributes)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		RETURNING id
	`, e.Timestamp, e.SourceGateway, e.Category, e.Severity, e.ClientIP, e.Summary, string(attrBytes)).Scan(&lastId)
	if err != nil {
		return fmt.Errorf("failed to save UniFi event in DuckDB: %w", err)
	}
	e.ID = lastId

	return nil
}

// ListUniFiEvents queries recent UniFi SIEM events.
func (r *Repository) ListUniFiEvents(ctx context.Context, limit int) ([]UniFiEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, timestamp, source_gateway, category, severity, client_ip, summary, attributes
		FROM unifi_events
		ORDER BY timestamp DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query UniFi events in DuckDB: %w", err)
	}
	defer rows.Close()

	var events []UniFiEvent
	for rows.Next() {
		var e UniFiEvent
		var attrStr string
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.SourceGateway, &e.Category, &e.Severity, &e.ClientIP, &e.Summary, &attrStr); err != nil {
			return nil, fmt.Errorf("failed to scan UniFi event: %w", err)
		}
		e.Timestamp = e.Timestamp.UTC()
		if err := json.Unmarshal([]byte(attrStr), &e.Attributes); err != nil {
			e.Attributes = make(map[string]string)
		}
		events = append(events, e)
	}
	if events == nil {
		events = []UniFiEvent{}
	}
	return events, nil
}

// GetUniFiEventsForIP queries recent UniFi SIEM events associated with a specific client IP.
func (r *Repository) GetUniFiEventsForIP(ctx context.Context, ip string, limit int) ([]UniFiEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, timestamp, source_gateway, category, severity, client_ip, summary, attributes
		FROM unifi_events
		WHERE client_ip = ?
		ORDER BY timestamp DESC
		LIMIT ?
	`, ip, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query UniFi events for IP in DuckDB: %w", err)
	}
	defer rows.Close()

	var events []UniFiEvent
	for rows.Next() {
		var e UniFiEvent
		var attrStr string
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.SourceGateway, &e.Category, &e.Severity, &e.ClientIP, &e.Summary, &attrStr); err != nil {
			return nil, fmt.Errorf("failed to scan UniFi event: %w", err)
		}
		e.Timestamp = e.Timestamp.UTC()
		if err := json.Unmarshal([]byte(attrStr), &e.Attributes); err != nil {
			e.Attributes = make(map[string]string)
		}
		events = append(events, e)
	}
	if events == nil {
		events = []UniFiEvent{}
	}
	return events, nil
}
