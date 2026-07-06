package storage

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/flowguard/flowguard/internal/flow"
)

// Validate checks policy properties against safety rules to prevent unbounded queries or destructive loops.
func (p *Policy) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("policy name cannot be empty")
	}
	if len(p.Name) > 100 {
		return fmt.Errorf("policy name exceeds maximum length of 100 characters")
	}
	switch p.Scope {
	case "global":
		if p.Target != "" {
			return fmt.Errorf("global policy target must be empty")
		}
	case "ip":
		if net.ParseIP(p.Target) == nil {
			return fmt.Errorf("invalid target IP address: %s", p.Target)
		}
	case "subnet":
		_, _, err := net.ParseCIDR(p.Target)
		if err != nil {
			return fmt.Errorf("invalid target CIDR subnet: %s, error: %w", p.Target, err)
		}
	case "alert_type":
		if p.Target == "" {
			return fmt.Errorf("alert_type policy target cannot be empty")
		}
		if len(p.Target) > 100 {
			return fmt.Errorf("target alert type exceeds maximum length of 100 characters")
		}
	default:
		return fmt.Errorf("invalid policy scope: %s", p.Scope)
	}

	switch p.SeverityThreshold {
	case "", "low", "medium", "high":
		// OK
	default:
		return fmt.Errorf("invalid severity threshold: %s", p.SeverityThreshold)
	}

	if p.CooldownSeconds < 0 || p.CooldownSeconds > 2592000 {
		return fmt.Errorf("cooldown period must be between 0 and 30 days (2,592,000 seconds)")
	}

	timeRegex := regexp.MustCompile(`^(?:[01]\d|2[0-3]):[0-5]\d$`)
	if p.QuietHoursStart != "" && !timeRegex.MatchString(p.QuietHoursStart) {
		return fmt.Errorf("invalid quiet hours start format, must be HH:MM")
	}
	if p.QuietHoursEnd != "" && !timeRegex.MatchString(p.QuietHoursEnd) {
		return fmt.Errorf("invalid quiet hours end format, must be HH:MM")
	}
	if (p.QuietHoursStart != "" && p.QuietHoursEnd == "") || (p.QuietHoursStart == "" && p.QuietHoursEnd != "") {
		return fmt.Errorf("both quiet hours start and end must be set, or both empty")
	}

	return nil
}

// Device represents a discovered local network node.
type Device struct {
	IP        string    `json:"ip"`
	Label     string    `json:"label"`
	Hostname  string    `json:"hostname"`
	Vendor    string    `json:"vendor"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// DeviceBaseline represents the normal statistical traffic limits for a local device.
type DeviceBaseline struct {
	IP            string    `json:"ip"`
	MeanBytes     float64   `json:"mean_bytes"`
	StdDevBytes   float64   `json:"stddev_bytes"`
	MeanPackets   float64   `json:"mean_packets"`
	StdDevPackets float64   `json:"stddev_packets"`
	MeanPeers     float64   `json:"mean_peers"`
	StdDevPeers   float64   `json:"stddev_peers"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Anomaly represents a detected behavioral deviance.
type Anomaly struct {
	ID          int64     `json:"id"`
	IP          string    `json:"ip"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"` // "active", "acknowledged", "silenced"
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Policy represents a user-defined rule specifying how FlowGuard handles alerts/devices in scopes.
type Policy struct {
	ID                   int64     `json:"id"`
	Name                 string    `json:"name"`
	Scope                string    `json:"scope"`              // "global", "subnet", "ip", "alert_type"
	Target               string    `json:"target"`             // IP, subnet CIDR, or alert type
	SeverityThreshold    string    `json:"severity_threshold"` // "low", "medium", "high", or ""
	Suppressed           bool      `json:"suppressed"`
	CooldownSeconds      int       `json:"cooldown_seconds"`
	QuietHoursStart      string    `json:"quiet_hours_start"`     // "HH:MM"
	QuietHoursEnd        string    `json:"quiet_hours_end"`       // "HH:MM"
	NotificationChannels []string  `json:"notification_channels"` // serialized as JSON array text in DB
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// AuditLog represents a security review or configuration action logged for auditing.
type AuditLog struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
}

// NotificationRule represents a user-defined routing rule for alert dispatches.
type NotificationRule struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	Enabled         bool      `json:"enabled"`
	SeverityMin     string    `json:"severity_min"`     // "low", "medium", "high"
	AlertTypes      []string  `json:"alert_types"`      // JSON array of strings (empty means all)
	Scope           string    `json:"scope"`            // "global", "ip", "subnet"
	Target          string    `json:"target"`           // IP address, CIDR range, or empty
	CooldownSeconds int       `json:"cooldown_seconds"` // Deduplication period
	ChannelTargets  []string  `json:"channel_targets"`  // "webhook", "slack", "telegram"
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// NotificationLog tracks the dispatch outcome of alert routing rules.
type NotificationLog struct {
	ID           int64     `json:"id"`
	AnomalyID    int64     `json:"anomaly_id"`
	RuleID       *int64    `json:"rule_id,omitempty"` // NULL if fallback/manual alert
	Channel      string    `json:"channel"`           // "webhook", "slack", "telegram"
	Status       string    `json:"status"`            // "sent", "suppressed", "deduplicated", "failed"
	ErrorMessage string    `json:"error_message,omitempty"`
	DispatchedAt time.Time `json:"dispatched_at"`
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

	// GetTopProtocols returns transport protocols with the most bytes in the given time range.
	GetTopProtocols(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error)

	// GetTrafficTimeSeries returns total traffic counters grouped into fixed-size bounded time buckets.
	GetTrafficTimeSeries(ctx context.Context, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error)

	// GetDeviceTrafficTimeSeries returns total traffic counters for a specific IP grouped into fixed-size bounded time buckets.
	GetDeviceTrafficTimeSeries(ctx context.Context, ip string, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error)

	// GetDeviceTopPeers returns the top communicating peer IPs for a device sorted by byte volume.
	GetDeviceTopPeers(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error)

	// GetDeviceTopPorts returns the top destination/service ports for a device sorted by byte volume.
	GetDeviceTopPorts(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error)
}

// DeviceRepository defines the operations on local device metadata, baselines, and anomalies.
type DeviceRepository interface {
	// UpsertDevice registers or updates a device's last-seen status and hostname.
	UpsertDevice(ctx context.Context, ip string, hostname string, lastSeen time.Time) error

	// UpdateDeviceLabel manually sets the descriptive label for a device.
	UpdateDeviceLabel(ctx context.Context, ip string, label string) error

	// GetDevice fetches details of a single device.
	GetDevice(ctx context.Context, ip string) (*Device, error)

	// ListDevices lists all discovered network devices.
	ListDevices(ctx context.Context) ([]Device, error)

	// SaveBaseline persists/updates the historical behavioral baseline profile for a device.
	SaveBaseline(ctx context.Context, b *DeviceBaseline) error

	// GetBaseline retrieves the cached historical baseline profile for a device.
	GetBaseline(ctx context.Context, ip string) (*DeviceBaseline, error)

	// SaveAnomaly registers a new behavioral alert.
	SaveAnomaly(ctx context.Context, a *Anomaly) error

	// UpdateAnomalyStatus reviews, silences, or acknowledges an alert.
	UpdateAnomalyStatus(ctx context.Context, id int64, status string) error

	// ListAnomalies queries recent anomalies triggered.
	ListAnomalies(ctx context.Context, limit int) ([]Anomaly, error)

	// GetActiveAnomalies queries all active anomalies triggered since a given time.
	GetActiveAnomalies(ctx context.Context, since time.Time) ([]Anomaly, error)

	// SaveAuditLog writes a security or configuration audit record.
	SaveAuditLog(ctx context.Context, action string, details string) error

	// ListAuditLogs returns a list of recent audit log records.
	ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error)

	// GetAnomaliesForIP queries recent anomalies associated with a specific IP.
	GetAnomaliesForIP(ctx context.Context, ip string, limit int) ([]Anomaly, error)

	// SavePolicy persists or updates a custom policy.
	SavePolicy(ctx context.Context, p *Policy) error

	// DeletePolicy removes a policy by ID.
	DeletePolicy(ctx context.Context, id int64) error

	// GetPolicy retrieves a policy by ID.
	GetPolicy(ctx context.Context, id int64) (*Policy, error)

	// ListPolicies lists all active policies.
	ListPolicies(ctx context.Context) ([]Policy, error)

	// HasRecentAnomaly checks if an anomaly of matching IP and Type was created within the last cooldown period.
	HasRecentAnomaly(ctx context.Context, ip string, anomalyType string, since time.Time) (bool, error)

	// GetPoliciesForIP returns all matching policies (global, subnet, IP) for a specific IP.
	GetPoliciesForIP(ctx context.Context, ip string) ([]Policy, error)

	// SaveNotificationRule persists or updates a notification rule.
	SaveNotificationRule(ctx context.Context, r *NotificationRule) error

	// DeleteNotificationRule removes a notification rule by ID.
	DeleteNotificationRule(ctx context.Context, id int64) error

	// GetNotificationRule retrieves a notification rule by ID.
	GetNotificationRule(ctx context.Context, id int64) (*NotificationRule, error)

	// ListNotificationRules lists all active notification rules.
	ListNotificationRules(ctx context.Context) ([]NotificationRule, error)

	// SaveNotificationLog records a notification dispatch outcome.
	SaveNotificationLog(ctx context.Context, l *NotificationLog) error

	// ListNotificationLogs returns recent notification logs.
	ListNotificationLogs(ctx context.Context, limit int) ([]NotificationLog, error)

	// HasRecentNotification checks if a notification for the same rule/IP/type was sent recently.
	HasRecentNotification(ctx context.Context, ruleID int64, ip string, anomalyType string, since time.Time) (bool, error)
}

// Manager defines the interface for managing database shards and schema maintenance.
type Manager interface {
	// Close closes all open SQLite connection shards safely.
	Close() error

	// CleanupRetention prunes shard files older than the specified retention days.
	CleanupRetention(retentionDays int) error
}

// StorageRepository combines all storage operations under a single unified interface.
type StorageRepository interface {
	FlowRepository
	DeviceRepository
	Manager
	RegisterAnomalyCallback(cb func(a *Anomaly))
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
