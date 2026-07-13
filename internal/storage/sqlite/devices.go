package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// UpsertDevice registers or updates a device's last-seen status and hostname.
func (r *Repository) UpsertDevice(ctx context.Context, ip string, hostname string, lastSeen time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	lastSeenUnix := lastSeen.Format(time.RFC3339)

	// If hostname is empty, we don't want to overwrite an existing hostname with an empty string!
	// We handle this conditionally using CASE WHEN.
	_, err := r.metaDB.ExecContext(ctx, `
		INSERT INTO devices (ip, hostname, first_seen, last_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			last_seen = ?,
			hostname = CASE WHEN ? != '' THEN ? ELSE hostname END
	`, ip, hostname, lastSeenUnix, lastSeenUnix, lastSeenUnix, hostname, hostname)
	if err != nil {
		return fmt.Errorf("failed to upsert device IP %s: %w", ip, err)
	}
	return nil
}

// UpdateDeviceLabel manually sets the descriptive label for a device.
func (r *Repository) UpdateDeviceLabel(ctx context.Context, ip string, label string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	res, err := r.metaDB.ExecContext(ctx, `
		UPDATE devices SET label = ? WHERE ip = ?
	`, label, ip)
	if err != nil {
		return fmt.Errorf("failed to update device label: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("device not found")
	}
	return nil
}

// GetDevice fetches details of a single device.
func (r *Repository) GetDevice(ctx context.Context, ip string) (*Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var d Device
	var firstSeenStr, lastSeenStr string

	err := r.metaDB.QueryRowContext(ctx, `
		SELECT ip, label, hostname, vendor, first_seen, last_seen
		FROM devices
		WHERE ip = ?
	`, ip).Scan(&d.IP, &d.Label, &d.Hostname, &d.Vendor, &firstSeenStr, &lastSeenStr)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Return nil, nil when device is not found
		}
		return nil, fmt.Errorf("failed to query device %s: %w", ip, err)
	}

	// Parse timestamps
	if t, err := time.Parse(time.RFC3339, firstSeenStr); err == nil {
		d.FirstSeen = t
	}
	if t, err := time.Parse(time.RFC3339, lastSeenStr); err == nil {
		d.LastSeen = t
	}

	return &d, nil
}

// ListDevices lists all discovered network devices.
func (r *Repository) ListDevices(ctx context.Context) ([]Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.metaDB.QueryContext(ctx, `
		SELECT ip, label, hostname, vendor, first_seen, last_seen
		FROM devices
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query devices: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		var firstSeenStr, lastSeenStr string

		if err := rows.Scan(&d.IP, &d.Label, &d.Hostname, &d.Vendor, &firstSeenStr, &lastSeenStr); err != nil {
			return nil, fmt.Errorf("failed to scan device: %w", err)
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

// SaveBaseline persists/updates the historical behavioral baseline profile for a device.
func (r *Repository) SaveBaseline(ctx context.Context, b *DeviceBaseline) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	updatedAtStr := b.UpdatedAt.Format(time.RFC3339)

	_, err := r.metaDB.ExecContext(ctx, `
		INSERT INTO device_baselines (ip, mean_bytes, stddev_bytes, mean_packets, stddev_packets, mean_peers, stddev_peers, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			mean_bytes = excluded.mean_bytes,
			stddev_bytes = excluded.stddev_bytes,
			mean_packets = excluded.mean_packets,
			stddev_packets = excluded.stddev_packets,
			mean_peers = excluded.mean_peers,
			stddev_peers = excluded.stddev_peers,
			updated_at = excluded.updated_at
	`, b.IP, b.MeanBytes, b.StdDevBytes, b.MeanPackets, b.StdDevPackets, b.MeanPeers, b.StdDevPeers, updatedAtStr)
	if err != nil {
		return fmt.Errorf("failed to save baseline for IP %s: %w", b.IP, err)
	}
	return nil
}

// GetBaseline retrieves the cached historical baseline profile for a device.
func (r *Repository) GetBaseline(ctx context.Context, ip string) (*DeviceBaseline, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var b DeviceBaseline
	var updatedAtStr string

	err := r.metaDB.QueryRowContext(ctx, `
		SELECT ip, mean_bytes, stddev_bytes, mean_packets, stddev_packets, mean_peers, stddev_peers, updated_at
		FROM device_baselines
		WHERE ip = ?
	`, ip).Scan(&b.IP, &b.MeanBytes, &b.StdDevBytes, &b.MeanPackets, &b.StdDevPackets, &b.MeanPeers, &b.StdDevPeers, &updatedAtStr)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Return nil, nil when baseline is not found
		}
		return nil, fmt.Errorf("failed to query baseline %s: %w", ip, err)
	}

	if t, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
		b.UpdatedAt = t
	}

	return &b, nil
}
