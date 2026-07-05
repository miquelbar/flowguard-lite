//go:generate go run ../../cmd/docgen/main.go
package config

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration.
type Config struct {
	Port                  string            `yaml:"port"`
	NetflowPort           int               `yaml:"netflow_port"`
	SflowPort             int               `yaml:"sflow_port"`
	StorageDir            string            `yaml:"storage_dir"`
	LogLevel              string            `yaml:"log_level"`
	Environment           string            `yaml:"environment"`
	LocalSubnets          []string          `yaml:"local_subnets"`
	DDoSThresholdPPS      int               `yaml:"ddos_threshold_pps"`
	DDoSThresholdBPS      int               `yaml:"ddos_threshold_bps"`
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
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() *Config {
	return &Config{
		Port:                  "8080",
		NetflowPort:           2055,
		SflowPort:             6343,
		StorageDir:            "/data",
		LogLevel:              "info",
		Environment:           "production",
		LocalSubnets:          []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"},
		DDoSThresholdPPS:      5000,
		DDoSThresholdBPS:      10 * 1024 * 1024, // 10 MB/s
		SYNFloodThresholdPPS:  1000,
		UDPFloodThresholdPPS:  3000,
		ICMPFloodThresholdPPS: 500,
		SuricataEvePath:       "",
		WebhookURL:            "",
		WebhookFormat:         "generic",
		WebhookHeaders:        make(map[string]string),
		TelegramEnabled:       false,
		TelegramToken:         "",
		TelegramChatID:        "",
		StorageBackend:        "sqlite",
		FirstRunCompleted:     false,
		AdminPasswordHash:     "",
		SessionSecret:         "",
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
		if p, err := strconv.Atoi(val); err == nil {
			cfg.NetflowPort = p
		}
	}
	if val := os.Getenv("FLOWGUARD_SFLOW_PORT"); val != "" {
		if p, err := strconv.Atoi(val); err == nil {
			cfg.SflowPort = p
		}
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

	if val := os.Getenv("FLOWGUARD_WEBHOOK_URL"); val != "" {
		cfg.WebhookURL = val
	}
	if val := os.Getenv("FLOWGUARD_WEBHOOK_FORMAT"); val != "" {
		cfg.WebhookFormat = val
	}
	if val := os.Getenv("FLOWGUARD_WEBHOOK_HEADERS"); val != "" {
		var headers map[string]string
		if err := json.Unmarshal([]byte(val), &headers); err == nil {
			cfg.WebhookHeaders = headers
		}
	}
	if val := os.Getenv("FLOWGUARD_TELEGRAM_ENABLED"); val != "" {
		cfg.TelegramEnabled = (val == "true")
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
		cfg.FirstRunCompleted = (val == "true")
	}
	if val := os.Getenv("FLOWGUARD_ADMIN_PASSWORD_HASH"); val != "" {
		cfg.AdminPasswordHash = val
	}
	if val := os.Getenv("FLOWGUARD_SESSION_SECRET"); val != "" {
		cfg.SessionSecret = val
	}

	return cfg, nil
}

// SaveConfig writes the configuration back to a YAML file.
func SaveConfig(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
