package storage

import (
	"context"
	"time"

	"github.com/flowguard/flowguard/internal/flow"
)

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

// Manager defines the interface for managing database shards and schema maintenance.
type Manager interface {
	// Close closes all open SQLite connection shards safely.
	Close() error

	// CleanupRetention prunes shard files older than the specified retention days.
	CleanupRetention(retentionDays int) error
}
