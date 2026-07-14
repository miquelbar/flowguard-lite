package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Port != "8080" {
		t.Errorf("expected default Port '8080', got %s", cfg.Port)
	}
	if cfg.NetflowPort != 2055 {
		t.Errorf("expected default NetflowPort 2055, got %d", cfg.NetflowPort)
	}
	if cfg.SflowPort != 6343 {
		t.Errorf("expected default SflowPort 6343, got %d", cfg.SflowPort)
	}
	if cfg.UniFiSyslogEnabled {
		t.Error("expected UniFi syslog collector disabled by default")
	}
	if cfg.UniFiSyslogPort != 5514 {
		t.Errorf("expected default UniFiSyslogPort 5514, got %d", cfg.UniFiSyslogPort)
	}
	if cfg.StorageDir != "/data" {
		t.Errorf("expected default StorageDir '/data', got %s", cfg.StorageDir)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default LogLevel 'info', got %s", cfg.LogLevel)
	}
	if cfg.Environment != "production" {
		t.Errorf("expected default Environment 'production', got %s", cfg.Environment)
	}
}

func TestLoadConfig_Yaml(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	yamlContent := `
port: "9090"
netflow_port: 3000
sflow_port: 4000
storage_dir: "/tmp/data"
log_level: "debug"
environment: "development"
capture_interface: "en0"
capture_bpf_filter: "tcp or udp"
capture_promiscuous: true
unifi_syslog_enabled: true
unifi_syslog_port: 5514
unifi_syslog_allowed_ips:
  - "192.168.1.1"
  - "192.168.1.0/24"
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Port != "9090" {
		t.Errorf("expected Port '9090', got %s", cfg.Port)
	}
	if cfg.NetflowPort != 3000 {
		t.Errorf("expected NetflowPort 3000, got %d", cfg.NetflowPort)
	}
	if cfg.SflowPort != 4000 {
		t.Errorf("expected SflowPort 4000, got %d", cfg.SflowPort)
	}
	if cfg.StorageDir != "/tmp/data" {
		t.Errorf("expected StorageDir '/tmp/data', got %s", cfg.StorageDir)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected LogLevel 'debug', got %s", cfg.LogLevel)
	}
	if cfg.Environment != "development" {
		t.Errorf("expected Environment 'development', got %s", cfg.Environment)
	}
	if cfg.CaptureInterface != "en0" || cfg.CaptureBPFFilter != "tcp or udp" || !cfg.CapturePromiscuous {
		t.Errorf("unexpected capture config: interface=%q filter=%q promiscuous=%t", cfg.CaptureInterface, cfg.CaptureBPFFilter, cfg.CapturePromiscuous)
	}
	if !cfg.UniFiSyslogEnabled || cfg.UniFiSyslogPort != 5514 || len(cfg.UniFiSyslogAllowedIPs) != 2 {
		t.Errorf("unexpected UniFi syslog config: %+v", cfg)
	}
}

func TestLoadConfig_EnvOverride(t *testing.T) {
	os.Setenv("FLOWGUARD_PORT", "9999")
	os.Setenv("FLOWGUARD_NETFLOW_PORT", "5055")
	os.Setenv("FLOWGUARD_SFLOW_PORT", "7343")
	os.Setenv("FLOWGUARD_STORAGE_DIR", "/env/data")
	os.Setenv("FLOWGUARD_LOG_LEVEL", "warn")
	os.Setenv("FLOWGUARD_ENV", "staging")
	os.Setenv("FLOWGUARD_ADMIN_PASSWORD_HASH", "pbkdf2-sha256$1$salt$hash")
	os.Setenv("FLOWGUARD_SESSION_SECRET", "session-secret")
	os.Setenv("FLOWGUARD_CAPTURE_INTERFACE", "eth0")
	os.Setenv("FLOWGUARD_CAPTURE_BPF_FILTER", "udp")
	os.Setenv("FLOWGUARD_CAPTURE_PROMISCUOUS", "true")
	os.Setenv("FLOWGUARD_UNIFI_SYSLOG_ENABLED", "true")
	os.Setenv("FLOWGUARD_UNIFI_SYSLOG_PORT", "5514")
	os.Setenv("FLOWGUARD_UNIFI_SYSLOG_ALLOWED_IPS", "192.168.1.1,192.168.1.0/24")
	os.Setenv("FLOWGUARD_DDOS_THRESHOLD_PPS", "6000")
	os.Setenv("FLOWGUARD_DDOS_THRESHOLD_BPS", "12582912")
	os.Setenv("FLOWGUARD_DDOS_THRESHOLD_FPS", "1200")
	os.Setenv("FLOWGUARD_SYN_FLOOD_THRESHOLD_PPS", "1100")
	os.Setenv("FLOWGUARD_UDP_FLOOD_THRESHOLD_PPS", "3100")
	os.Setenv("FLOWGUARD_ICMP_FLOOD_THRESHOLD_PPS", "600")

	defer func() {
		os.Unsetenv("FLOWGUARD_PORT")
		os.Unsetenv("FLOWGUARD_NETFLOW_PORT")
		os.Unsetenv("FLOWGUARD_SFLOW_PORT")
		os.Unsetenv("FLOWGUARD_STORAGE_DIR")
		os.Unsetenv("FLOWGUARD_LOG_LEVEL")
		os.Unsetenv("FLOWGUARD_ENV")
		os.Unsetenv("FLOWGUARD_ADMIN_PASSWORD_HASH")
		os.Unsetenv("FLOWGUARD_SESSION_SECRET")
		os.Unsetenv("FLOWGUARD_CAPTURE_INTERFACE")
		os.Unsetenv("FLOWGUARD_CAPTURE_BPF_FILTER")
		os.Unsetenv("FLOWGUARD_CAPTURE_PROMISCUOUS")
		os.Unsetenv("FLOWGUARD_UNIFI_SYSLOG_ENABLED")
		os.Unsetenv("FLOWGUARD_UNIFI_SYSLOG_PORT")
		os.Unsetenv("FLOWGUARD_UNIFI_SYSLOG_ALLOWED_IPS")
		os.Unsetenv("FLOWGUARD_DDOS_THRESHOLD_PPS")
		os.Unsetenv("FLOWGUARD_DDOS_THRESHOLD_BPS")
		os.Unsetenv("FLOWGUARD_DDOS_THRESHOLD_FPS")
		os.Unsetenv("FLOWGUARD_SYN_FLOOD_THRESHOLD_PPS")
		os.Unsetenv("FLOWGUARD_UDP_FLOOD_THRESHOLD_PPS")
		os.Unsetenv("FLOWGUARD_ICMP_FLOOD_THRESHOLD_PPS")
	}()

	cfg, err := LoadConfig("non-existent-config.yaml")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Port != "9999" {
		t.Errorf("expected Port '9999', got %s", cfg.Port)
	}
	if cfg.NetflowPort != 5055 {
		t.Errorf("expected NetflowPort 5055, got %d", cfg.NetflowPort)
	}
	if cfg.SflowPort != 7343 {
		t.Errorf("expected SflowPort 7343, got %d", cfg.SflowPort)
	}
	if cfg.StorageDir != "/env/data" {
		t.Errorf("expected StorageDir '/env/data', got %s", cfg.StorageDir)
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("expected LogLevel 'warn', got %s", cfg.LogLevel)
	}
	if cfg.Environment != "staging" {
		t.Errorf("expected Environment 'staging', got %s", cfg.Environment)
	}
	if cfg.AdminPasswordHash != "pbkdf2-sha256$1$salt$hash" {
		t.Errorf("expected admin password hash override, got %q", cfg.AdminPasswordHash)
	}
	if cfg.SessionSecret != "session-secret" {
		t.Errorf("expected session secret override, got %q", cfg.SessionSecret)
	}
	if cfg.CaptureInterface != "eth0" || cfg.CaptureBPFFilter != "udp" || !cfg.CapturePromiscuous {
		t.Errorf("unexpected capture env overrides: interface=%q filter=%q promiscuous=%t", cfg.CaptureInterface, cfg.CaptureBPFFilter, cfg.CapturePromiscuous)
	}
	if !cfg.UniFiSyslogEnabled || cfg.UniFiSyslogPort != 5514 || len(cfg.UniFiSyslogAllowedIPs) != 2 {
		t.Errorf("unexpected UniFi syslog env overrides: %+v", cfg)
	}
	if cfg.DDoSThresholdPPS != 6000 || cfg.DDoSThresholdBPS != 12582912 || cfg.DDoSThresholdFPS != 1200 ||
		cfg.SYNFloodThresholdPPS != 1100 || cfg.UDPFloodThresholdPPS != 3100 || cfg.ICMPFloodThresholdPPS != 600 {
		t.Errorf("unexpected DDoS threshold env overrides: %+v", cfg)
	}
}

func TestLoadConfig_WebhookHeadersEnvOverride(t *testing.T) {
	t.Setenv("FLOWGUARD_WEBHOOK_HEADERS", `{"Authorization":"Bearer test","X-FlowGuard":"dev"}`)

	cfg, err := LoadConfig("non-existent-config.yaml")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.WebhookHeaders["Authorization"] != "Bearer test" {
		t.Errorf("expected Authorization header override, got %q", cfg.WebhookHeaders["Authorization"])
	}
	if cfg.WebhookHeaders["X-FlowGuard"] != "dev" {
		t.Errorf("expected X-FlowGuard header override, got %q", cfg.WebhookHeaders["X-FlowGuard"])
	}
}

func TestLoadConfigRejectsInvalidEnvironmentOverrides(t *testing.T) {
	t.Setenv("FLOWGUARD_NETFLOW_PORT", "not-a-port")

	if _, err := LoadConfig("non-existent-config.yaml"); err == nil {
		t.Fatal("expected invalid integer environment override to fail")
	}
}

func TestLoadConfigRejectsInvalidWebhookHeaders(t *testing.T) {
	t.Setenv("FLOWGUARD_WEBHOOK_HEADERS", `{not-json}`)

	if _, err := LoadConfig("non-existent-config.yaml"); err == nil {
		t.Fatal("expected invalid webhook headers JSON to fail")
	}
}

func TestConfigValidateRejectsUnsafeValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name:   "invalid local subnet",
			mutate: func(cfg *Config) { cfg.LocalSubnets = []string{"192.168.1.0/24", "bad-cidr"} },
		},
		{
			name:   "retention too high",
			mutate: func(cfg *Config) { cfg.RetentionDays = MaxRetentionDays + 1 },
		},
		{
			name:   "invalid backend",
			mutate: func(cfg *Config) { cfg.StorageBackend = "postgres" },
		},
		{
			name:   "telegram enabled without target",
			mutate: func(cfg *Config) { cfg.TelegramEnabled = true },
		},
		{
			name:   "enabled unifi syslog with zero port",
			mutate: func(cfg *Config) { cfg.UniFiSyslogEnabled = true; cfg.UniFiSyslogPort = 0 },
		},
		{
			name:   "collector UDP port conflict",
			mutate: func(cfg *Config) { cfg.UniFiSyslogEnabled = true; cfg.UniFiSyslogPort = cfg.NetflowPort },
		},
		{
			name:   "invalid unifi syslog allowlist",
			mutate: func(cfg *Config) { cfg.UniFiSyslogAllowedIPs = []string{"not-an-ip"} },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoadConfigRejectsInvalidYamlValues(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_invalid_yaml")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(`
port: "8080"
storage_backend: "postgres"
local_subnets:
  - "192.168.1.0/24"
retention_days: 7
`), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	if _, err := LoadConfig(configPath); err == nil {
		t.Fatal("expected invalid YAML config value to fail")
	}
}

func TestDefaultConfigIsValid(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("default config should validate: %v", err)
	}
}

func TestSaveConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_save_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := DefaultConfig()
	cfg.Port = "1234"
	cfg.FirstRunCompleted = true

	configPath := filepath.Join(tmpDir, "saved_config.yaml")
	if err := SaveConfig(configPath, cfg); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load saved config: %v", err)
	}

	if loaded.Port != "1234" {
		t.Errorf("expected saved Port '1234', got %s", loaded.Port)
	}
	if !loaded.FirstRunCompleted {
		t.Errorf("expected saved FirstRunCompleted to be true")
	}
}

func TestSaveConfigRejectsInvalidWithoutReplacingExistingFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_save_atomic_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	initial := DefaultConfig()
	initial.Port = "1234"
	if err := SaveConfig(configPath, initial); err != nil {
		t.Fatalf("failed to save initial config: %v", err)
	}

	invalid := DefaultConfig()
	invalid.Port = "not-a-port"
	if err := SaveConfig(configPath, invalid); err == nil {
		t.Fatal("expected invalid config save to fail")
	}

	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load retained config: %v", err)
	}
	if loaded.Port != "1234" {
		t.Fatalf("expected retained config port 1234, got %s", loaded.Port)
	}
}

func TestLoadConfigNormalization(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_normalize_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	// Save a config with empty strings for fields that have default values
	rawYaml := `
port: ""
storage_backend: ""
log_level: ""
environment: ""
webhook_format: ""
storage_dir: "/tmp/data"
`
	if err := os.WriteFile(configPath, []byte(rawYaml), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed to normalize empty strings: %v", err)
	}

	if cfg.Port != "8080" {
		t.Errorf("expected normalized Port '8080', got %q", cfg.Port)
	}
	if cfg.StorageBackend != StorageBackendSQLite {
		t.Errorf("expected normalized StorageBackend 'sqlite', got %q", cfg.StorageBackend)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected normalized LogLevel 'info', got %q", cfg.LogLevel)
	}
	if cfg.Environment != "production" {
		t.Errorf("expected normalized Environment 'production', got %q", cfg.Environment)
	}
	if cfg.WebhookFormat != WebhookFormatGeneric {
		t.Errorf("expected normalized WebhookFormat 'generic', got %q", cfg.WebhookFormat)
	}
}
