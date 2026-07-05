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

	defer func() {
		os.Unsetenv("FLOWGUARD_PORT")
		os.Unsetenv("FLOWGUARD_NETFLOW_PORT")
		os.Unsetenv("FLOWGUARD_SFLOW_PORT")
		os.Unsetenv("FLOWGUARD_STORAGE_DIR")
		os.Unsetenv("FLOWGUARD_LOG_LEVEL")
		os.Unsetenv("FLOWGUARD_ENV")
		os.Unsetenv("FLOWGUARD_ADMIN_PASSWORD_HASH")
		os.Unsetenv("FLOWGUARD_SESSION_SECRET")
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
