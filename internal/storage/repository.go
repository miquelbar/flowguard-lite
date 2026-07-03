package storage

import (
	"context"
	"time"

	"github.com/flowguard/flowguard/internal/flow"
)

// Device represents a discovered local network node.
type Device struct {
	IP        string    `json:"ip"`
	Label     string    `json:"label"`
	Hostname  string    `json:"hostname"`
	Vendor    string    `json:"vendor"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// FlowRepository defines the interface for reading and writing flow aggregates.
type FlowRepository interface {
	// SaveAggregates writes a slice of aggregated flow records to the shard matching the bucket timestamp.
	SaveAggregates(ctx context.Context, ts time.Time, aggregates []flow.FlowEvent) error

	// GetTopSources returns the source IPs with the most bytes in the given time range.
	GetTopSources(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error)

	// GetTopDestinations returns the destination IPs with the most bytes in the given time range.
	GetTopDestinations(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error)

	// GetTopPorts returns the destination ports with the most bytes in the given time range.
	GetTopPorts(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error)
}

// DeviceRepository defines the operations on local device metadata.
type DeviceRepository interface {
	// UpsertDevice registers or updates a device's last-seen status and hostname.
	UpsertDevice(ctx context.Context, ip string, hostname string, lastSeen time.Time) error

	// UpdateDeviceLabel manually sets the descriptive label for a device.
	UpdateDeviceLabel(ctx context.Context, ip string, label string) error

	// GetDevice fetches details of a single device.
	GetDevice(ctx context.Context, ip string) (*Device, error)

	// ListDevices lists all discovered network devices.
	ListDevices(ctx context.Context) ([]Device, error)
}

// Manager defines the interface for managing database shards and schema maintenance.
type Manager interface {
	// Close closes all open SQLite connection shards safely.
	Close() error

	// CleanupRetention prunes shard files older than the specified retention days.
	CleanupRetention(retentionDays int) error
}
