package config

import (
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration.
type Config struct {
	Port         string   `yaml:"port"`
	NetflowPort  int      `yaml:"netflow_port"`
	SflowPort    int      `yaml:"sflow_port"`
	StorageDir   string   `yaml:"storage_dir"`
	LogLevel     string   `yaml:"log_level"`
	Environment  string   `yaml:"environment"`
	LocalSubnets []string `yaml:"local_subnets"`
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() *Config {
	return &Config{
		Port:         "8080",
		NetflowPort:  2055,
		SflowPort:    6343,
		StorageDir:   "/data",
		LogLevel:     "info",
		Environment:  "production",
		LocalSubnets: []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"},
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

	return cfg, nil
}
