package duckdb

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// UpsertDevice inserts or updates device details.
func (r *Repository) UpsertDevice(ctx context.Context, ip string, hostname string, lastSeen time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	lastSeenStr := lastSeen.Format(time.RFC3339)

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO devices (ip, hostname, first_seen, last_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (ip) DO UPDATE SET
			last_seen = ?,
			hostname = CASE WHEN ? != '' THEN ? ELSE hostname END
	`, ip, hostname, lastSeenStr, lastSeenStr, lastSeenStr, hostname, hostname)
	if err != nil {
		return fmt.Errorf("failed to upsert device: %w", err)
	}
	return nil
}

// UpdateDeviceLabel updates a device's name label.
func (r *Repository) UpdateDeviceLabel(ctx context.Context, ip string, label string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	res, err := r.db.ExecContext(ctx, `UPDATE devices SET label = ? WHERE ip = ?`, label, ip)
	if err != nil {
		return fmt.Errorf("failed to update device label: %w", err)
	}
	rows, err := res.RowsAffected()
	if err == nil && rows == 0 {
		return fmt.Errorf("device not found")
	}
	return nil
}

// GetDevice fetches details of a single device.
func (r *Repository) GetDevice(ctx context.Context, ip string) (*Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var d Device
	var firstSeenStr, lastSeenStr string

	err := r.db.QueryRowContext(ctx, `
		SELECT ip, label, hostname, vendor, first_seen, last_seen
		FROM devices
		WHERE ip = ?
	`, ip).Scan(&d.IP, &d.Label, &d.Hostname, &d.Vendor, &firstSeenStr, &lastSeenStr)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query device %s: %w", ip, err)
	}

	if t, err := time.Parse(time.RFC3339, firstSeenStr); err == nil {
		d.FirstSeen = t
	}
	if t, err := time.Parse(time.RFC3339, lastSeenStr); err == nil {
		d.LastSeen = t
	}

	return &d, nil
}

// ListDevices returns all discovered local devices.
func (r *Repository) ListDevices(ctx context.Context) ([]Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, `
		SELECT ip, label, hostname, vendor, first_seen, last_seen
		FROM devices
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed listing devices from DuckDB: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		var firstSeenStr, lastSeenStr string
		if err := rows.Scan(&d.IP, &d.Label, &d.Hostname, &d.Vendor, &firstSeenStr, &lastSeenStr); err != nil {
			return nil, fmt.Errorf("failed scanning device from DuckDB: %w", err)
		}
		if t, err := time.Parse(time.RFC3339, firstSeenStr); err == nil {
			d.FirstSeen = t
		}
		if t, err := time.Parse(time.RFC3339, lastSeenStr); err == nil {
			d.LastSeen = t
		}
		devices = append(devices, d)
	}
	if devices == nil {
		devices = []Device{}
	}
	return devices, nil
}

// SaveBaseline stores baseline statistical behavior limits.
func (r *Repository) SaveBaseline(ctx context.Context, b *DeviceBaseline) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO device_baselines (ip, mean_bytes, stddev_bytes, mean_packets, stddev_packets, mean_peers, stddev_peers, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (ip) DO UPDATE SET
			mean_bytes = excluded.mean_bytes,
			stddev_bytes = excluded.stddev_bytes,
			mean_packets = excluded.mean_packets,
			stddev_packets = excluded.stddev_packets,
			mean_peers = excluded.mean_peers,
			stddev_peers = excluded.stddev_peers,
			updated_at = excluded.updated_at
	`, b.IP, b.MeanBytes, b.StdDevBytes, b.MeanPackets, b.StdDevPackets, b.MeanPeers, b.StdDevPeers, b.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed saving baseline: %w", err)
	}
	return nil
}

// GetBaseline retrieves the behavioral baseline profile for a device.
func (r *Repository) GetBaseline(ctx context.Context, ip string) (*DeviceBaseline, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	row := r.db.QueryRowContext(ctx, `
		SELECT ip, mean_bytes, stddev_bytes, mean_packets, stddev_packets, mean_peers, stddev_peers, updated_at
		FROM device_baselines WHERE ip = ?
	`, ip)

	var b DeviceBaseline
	err := row.Scan(&b.IP, &b.MeanBytes, &b.StdDevBytes, &b.MeanPackets, &b.StdDevPackets, &b.MeanPeers, &b.StdDevPeers, &b.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("baseline not found")
		}
		return nil, fmt.Errorf("failed fetching baseline: %w", err)
	}
	return &b, nil
}
