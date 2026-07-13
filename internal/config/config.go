//go:generate go run ../../cmd/docgen/main.go
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	StorageBackendSQLite = "sqlite"
	StorageBackendDuckDB = "duckdb"

	WebhookFormatGeneric  = "generic"
	WebhookFormatSlack    = "slack"
	WebhookFormatTelegram = "telegram"

	MinRetentionDays = 1
	MaxRetentionDays = 60
)

// Config represents the application configuration.
type Config struct {
	Port                  string            `yaml:"port"`
	NetflowPort           int               `yaml:"netflow_port"`
	SflowPort             int               `yaml:"sflow_port"`
	CaptureInterface      string            `yaml:"capture_interface"`
	CaptureBPFFilter      string            `yaml:"capture_bpf_filter"`
	CapturePromiscuous    bool              `yaml:"capture_promiscuous"`
	UniFiSyslogEnabled    bool              `yaml:"unifi_syslog_enabled"`
	UniFiSyslogPort       int               `yaml:"unifi_syslog_port"`
	UniFiSyslogAllowedIPs []string          `yaml:"unifi_syslog_allowed_ips"`
	StorageDir            string            `yaml:"storage_dir"`
	LogLevel              string            `yaml:"log_level"`
	Environment           string            `yaml:"environment"`
	LocalSubnets          []string          `yaml:"local_subnets"`
	DDoSThresholdPPS      int               `yaml:"ddos_threshold_pps"`
	DDoSThresholdBPS      int               `yaml:"ddos_threshold_bps"`
	DDoSThresholdFPS      int               `yaml:"ddos_threshold_fps"`
	SYNFloodThresholdPPS  int               `yaml:"syn_flood_threshold_pps"`
	UDPFloodThresholdPPS  int               `yaml:"udp_flood_threshold_pps"`
	ICMPFloodThresholdPPS int               `yaml:"icmp_flood_threshold_pps"`
	SuricataEvePath       string            `yaml:"suricata_eve_path"`
	WebhookURL            string            `yaml:"webhook_url"`
	WebhookFormat         string            `yaml:"webhook_format"` // "generic", "slack", "telegram"
	WebhookHeaders        map[string]string `yaml:"webhook_headers"`
	TelegramEnabled       bool              `yaml:"telegram_enabled"`
	TelegramToken         string            `yaml:"telegram_token"`
	TelegramChatID        string            `yaml:"telegram_chat_id"`
	StorageBackend        string            `yaml:"storage_backend"` // "sqlite" or "duckdb"
	FirstRunCompleted     bool              `yaml:"first_run_completed"`
	AdminPasswordHash     string            `yaml:"admin_password_hash"`
	SessionSecret         string            `yaml:"session_secret"`
	RetentionDays         int               `yaml:"retention_days"`
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() *Config {
	return &Config{
		Port:                  "8080",
		NetflowPort:           2055,
		SflowPort:             6343,
		CaptureInterface:      "",
		CaptureBPFFilter:      "ip or ip6",
		CapturePromiscuous:    false,
		UniFiSyslogEnabled:    false,
		UniFiSyslogPort:       5514,
		UniFiSyslogAllowedIPs: []string{},
		StorageDir:            "/data",
		LogLevel:              "info",
		Environment:           "production",
		LocalSubnets:          []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"},
		DDoSThresholdPPS:      5000,
		DDoSThresholdBPS:      10 * 1024 * 1024, // 10 MB/s
		DDoSThresholdFPS:      1000,
		SYNFloodThresholdPPS:  1000,
		UDPFloodThresholdPPS:  3000,
		ICMPFloodThresholdPPS: 500,
		SuricataEvePath:       "",
		WebhookURL:            "",
		WebhookFormat:         WebhookFormatGeneric,
		WebhookHeaders:        make(map[string]string),
		TelegramEnabled:       false,
		TelegramToken:         "",
		TelegramChatID:        "",
		StorageBackend:        StorageBackendSQLite,
		FirstRunCompleted:     false,
		AdminPasswordHash:     "",
		SessionSecret:         "",
		RetentionDays:         7,
	}
}

// LoadConfig loads configuration from a YAML file and overrides values with environment variables.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	// If YAML file exists, parse it
	if _, err := os.Stat(path); err == nil {
		file, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(file, cfg); err != nil {
			return nil, err
		}
	}

	// Override with environment variables if present
	if val := os.Getenv("FLOWGUARD_PORT"); val != "" {
		cfg.Port = val
	}
	if val := os.Getenv("FLOWGUARD_NETFLOW_PORT"); val != "" {
		p, err := parseEnvInt("FLOWGUARD_NETFLOW_PORT", val)
		if err != nil {
			return nil, err
		}
		cfg.NetflowPort = p
	}
	if val := os.Getenv("FLOWGUARD_SFLOW_PORT"); val != "" {
		p, err := parseEnvInt("FLOWGUARD_SFLOW_PORT", val)
		if err != nil {
			return nil, err
		}
		cfg.SflowPort = p
	}
	if val := os.Getenv("FLOWGUARD_CAPTURE_INTERFACE"); val != "" {
		cfg.CaptureInterface = val
	}
	if val := os.Getenv("FLOWGUARD_CAPTURE_BPF_FILTER"); val != "" {
		cfg.CaptureBPFFilter = val
	}
	if val := os.Getenv("FLOWGUARD_CAPTURE_PROMISCUOUS"); val != "" {
		enabled, err := parseEnvBool("FLOWGUARD_CAPTURE_PROMISCUOUS", val)
		if err != nil {
			return nil, err
		}
		cfg.CapturePromiscuous = enabled
	}
	if val := os.Getenv("FLOWGUARD_UNIFI_SYSLOG_ENABLED"); val != "" {
		enabled, err := parseEnvBool("FLOWGUARD_UNIFI_SYSLOG_ENABLED", val)
		if err != nil {
			return nil, err
		}
		cfg.UniFiSyslogEnabled = enabled
	}
	if val := os.Getenv("FLOWGUARD_UNIFI_SYSLOG_PORT"); val != "" {
		p, err := parseEnvInt("FLOWGUARD_UNIFI_SYSLOG_PORT", val)
		if err != nil {
			return nil, err
		}
		cfg.UniFiSyslogPort = p
	}
	if val := os.Getenv("FLOWGUARD_UNIFI_SYSLOG_ALLOWED_IPS"); val != "" {
		cfg.UniFiSyslogAllowedIPs = splitCSV(val)
	}
	if val := os.Getenv("FLOWGUARD_STORAGE_DIR"); val != "" {
		cfg.StorageDir = val
	}
	if val := os.Getenv("FLOWGUARD_LOG_LEVEL"); val != "" {
		cfg.LogLevel = val
	}
	if val := os.Getenv("FLOWGUARD_ENV"); val != "" {
		cfg.Environment = val
	}
	if val := os.Getenv("FLOWGUARD_LOCAL_SUBNETS"); val != "" {
		cfg.LocalSubnets = strings.Split(val, ",")
	}
	if val := os.Getenv("FLOWGUARD_DDOS_THRESHOLD_PPS"); val != "" {
		p, err := parseEnvInt("FLOWGUARD_DDOS_THRESHOLD_PPS", val)
		if err != nil {
			return nil, err
		}
		cfg.DDoSThresholdPPS = p
	}
	if val := os.Getenv("FLOWGUARD_DDOS_THRESHOLD_BPS"); val != "" {
		b, err := parseEnvInt("FLOWGUARD_DDOS_THRESHOLD_BPS", val)
		if err != nil {
			return nil, err
		}
		cfg.DDoSThresholdBPS = b
	}
	if val := os.Getenv("FLOWGUARD_DDOS_THRESHOLD_FPS"); val != "" {
		f, err := parseEnvInt("FLOWGUARD_DDOS_THRESHOLD_FPS", val)
		if err != nil {
			return nil, err
		}
		cfg.DDoSThresholdFPS = f
	}
	if val := os.Getenv("FLOWGUARD_SYN_FLOOD_THRESHOLD_PPS"); val != "" {
		p, err := parseEnvInt("FLOWGUARD_SYN_FLOOD_THRESHOLD_PPS", val)
		if err != nil {
			return nil, err
		}
		cfg.SYNFloodThresholdPPS = p
	}
	if val := os.Getenv("FLOWGUARD_UDP_FLOOD_THRESHOLD_PPS"); val != "" {
		p, err := parseEnvInt("FLOWGUARD_UDP_FLOOD_THRESHOLD_PPS", val)
		if err != nil {
			return nil, err
		}
		cfg.UDPFloodThresholdPPS = p
	}
	if val := os.Getenv("FLOWGUARD_ICMP_FLOOD_THRESHOLD_PPS"); val != "" {
		p, err := parseEnvInt("FLOWGUARD_ICMP_FLOOD_THRESHOLD_PPS", val)
		if err != nil {
			return nil, err
		}
		cfg.ICMPFloodThresholdPPS = p
	}

	if val := os.Getenv("FLOWGUARD_WEBHOOK_URL"); val != "" {
		cfg.WebhookURL = val
	}
	if val := os.Getenv("FLOWGUARD_WEBHOOK_FORMAT"); val != "" {
		cfg.WebhookFormat = val
	}
	if val := os.Getenv("FLOWGUARD_WEBHOOK_HEADERS"); val != "" {
		var headers map[string]string
		if err := json.Unmarshal([]byte(val), &headers); err != nil {
			return nil, fmt.Errorf("invalid FLOWGUARD_WEBHOOK_HEADERS JSON object: %w", err)
		}
		cfg.WebhookHeaders = headers
	}
	if val := os.Getenv("FLOWGUARD_TELEGRAM_ENABLED"); val != "" {
		enabled, err := parseEnvBool("FLOWGUARD_TELEGRAM_ENABLED", val)
		if err != nil {
			return nil, err
		}
		cfg.TelegramEnabled = enabled
	}
	if val := os.Getenv("FLOWGUARD_TELEGRAM_TOKEN"); val != "" {
		cfg.TelegramToken = val
	}
	if val := os.Getenv("FLOWGUARD_TELEGRAM_CHAT_ID"); val != "" {
		cfg.TelegramChatID = val
	}
	if val := os.Getenv("FLOWGUARD_STORAGE_BACKEND"); val != "" {
		cfg.StorageBackend = val
	}
	if val := os.Getenv("FLOWGUARD_FIRST_RUN_COMPLETED"); val != "" {
		completed, err := parseEnvBool("FLOWGUARD_FIRST_RUN_COMPLETED", val)
		if err != nil {
			return nil, err
		}
		cfg.FirstRunCompleted = completed
	}
	if val := os.Getenv("FLOWGUARD_ADMIN_PASSWORD_HASH"); val != "" {
		cfg.AdminPasswordHash = val
	}
	if val := os.Getenv("FLOWGUARD_SESSION_SECRET"); val != "" {
		cfg.SessionSecret = val
	}
	if val := os.Getenv("FLOWGUARD_RETENTION_DAYS"); val != "" {
		r, err := parseEnvInt("FLOWGUARD_RETENTION_DAYS", val)
		if err != nil {
			return nil, err
		}
		cfg.RetentionDays = r
	}

	// Normalize empty fields to their default values
	if cfg.Port == "" {
		cfg.Port = "8080"
	}
	if cfg.StorageBackend == "" {
		cfg.StorageBackend = StorageBackendSQLite
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.Environment == "" {
		cfg.Environment = "production"
	}
	if cfg.WebhookFormat == "" {
		cfg.WebhookFormat = WebhookFormatGeneric
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// SaveConfig writes the configuration back to a YAML file.
func SaveConfig(path string, cfg *Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0644)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, path)
}

// Validate rejects malformed configuration before the daemon starts.
func (c *Config) Validate() error {
	if err := validateTCPPort("port", c.Port); err != nil {
		return err
	}
	if err := validateUDPPort("netflow_port", c.NetflowPort); err != nil {
		return err
	}
	if err := validateUDPPort("sflow_port", c.SflowPort); err != nil {
		return err
	}
	if err := validateUDPPort("unifi_syslog_port", c.UniFiSyslogPort); err != nil {
		return err
	}
	if c.UniFiSyslogEnabled && c.UniFiSyslogPort == 0 {
		return fmt.Errorf("unifi_syslog_port must be greater than 0 when unifi_syslog_enabled is true")
	}
	if err := validateCollectorPortConflicts(c); err != nil {
		return err
	}
	if strings.TrimSpace(c.StorageDir) == "" {
		return fmt.Errorf("storage_dir cannot be empty")
	}
	if !oneOf(c.LogLevel, "debug", "info", "warn", "error") {
		return fmt.Errorf("invalid log_level %q; allowed values are debug, info, warn, error", c.LogLevel)
	}
	if !oneOf(c.Environment, "development", "staging", "production", "test") {
		return fmt.Errorf("invalid environment %q; allowed values are development, staging, production, test", c.Environment)
	}
	if !oneOf(c.StorageBackend, StorageBackendSQLite, StorageBackendDuckDB) {
		return fmt.Errorf("invalid storage_backend %q; allowed values are sqlite, duckdb", c.StorageBackend)
	}
	if !oneOf(c.WebhookFormat, WebhookFormatGeneric, WebhookFormatSlack, WebhookFormatTelegram) {
		return fmt.Errorf("invalid webhook_format %q; allowed values are generic, slack, telegram", c.WebhookFormat)
	}
	if c.RetentionDays < MinRetentionDays || c.RetentionDays > MaxRetentionDays {
		return fmt.Errorf("retention_days must be between %d and %d", MinRetentionDays, MaxRetentionDays)
	}
	if c.DDoSThresholdPPS <= 0 || c.DDoSThresholdBPS <= 0 || c.DDoSThresholdFPS <= 0 ||
		c.SYNFloodThresholdPPS <= 0 || c.UDPFloodThresholdPPS <= 0 || c.ICMPFloodThresholdPPS <= 0 {
		return fmt.Errorf("DDoS thresholds must be positive integers")
	}
	for _, subnet := range c.LocalSubnets {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(subnet)); err != nil {
			return fmt.Errorf("invalid local_subnets entry %q: %w", subnet, err)
		}
	}
	if len(c.UniFiSyslogAllowedIPs) > 32 {
		return fmt.Errorf("unifi_syslog_allowed_ips supports at most 32 entries")
	}
	for _, item := range c.UniFiSyslogAllowedIPs {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if strings.ContainsAny(trimmed, "\x00\r\n") {
			return fmt.Errorf("invalid unifi_syslog_allowed_ips entry %q: control line breaks are not allowed", item)
		}
		if ip := net.ParseIP(trimmed); ip != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(trimmed); err != nil {
			return fmt.Errorf("invalid unifi_syslog_allowed_ips entry %q: must be an IP address or CIDR", item)
		}
	}
	if c.TelegramEnabled && (strings.TrimSpace(c.TelegramToken) == "" || strings.TrimSpace(c.TelegramChatID) == "") {
		return fmt.Errorf("telegram_token and telegram_chat_id are required when telegram_enabled is true")
	}
	return nil
}

func parseEnvInt(name, raw string) (int, error) {
	val, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s integer value %q: %w", name, raw, err)
	}
	return val, nil
}

func parseEnvBool(name, raw string) (bool, error) {
	val, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid %s boolean value %q: %w", name, raw, err)
	}
	return val, nil
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func validateCollectorPortConflicts(c *Config) error {
	used := make(map[int]string)
	for _, item := range []struct {
		name    string
		port    int
		enabled bool
	}{
		{name: "netflow_port", port: c.NetflowPort, enabled: c.NetflowPort > 0},
		{name: "sflow_port", port: c.SflowPort, enabled: c.SflowPort > 0},
		{name: "unifi_syslog_port", port: c.UniFiSyslogPort, enabled: c.UniFiSyslogEnabled && c.UniFiSyslogPort > 0},
	} {
		if !item.enabled {
			continue
		}
		if previous, ok := used[item.port]; ok {
			return fmt.Errorf("%s conflicts with %s on UDP port %d", item.name, previous, item.port)
		}
		used[item.port] = item.name
	}
	return nil
}

func validateTCPPort(name, raw string) error {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%s must be a TCP port between 1 and 65535", name)
	}
	return nil
}

func validateUDPPort(name string, port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("%s must be a UDP port between 0 and 65535", name)
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
