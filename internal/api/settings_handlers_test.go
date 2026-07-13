package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miquelbar/flowguard-lite/internal/config"
)

func TestHandleSettings(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "api_settings_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}
	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, nil, configPath)

	// 1. GET settings
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w.Code)
	}

	var current SettingsPayload
	if err := json.Unmarshal(w.Body.Bytes(), &current); err != nil {
		t.Fatalf("failed to decode current settings: %v", err)
	}
	if current.Port != "8080" || current.FirstRunCompleted {
		t.Errorf("unexpected current settings: %+v", current)
	}
	if current.CaptureInterface != "" || current.CaptureBPFFilter != "ip or ip6" || current.CapturePromiscuous {
		t.Errorf("unexpected default capture settings: %+v", current)
	}

	// 2. POST settings
	newSettings := SettingsPayload{
		Port:                  "9090",
		NetflowPort:           3000,
		SflowPort:             4000,
		UniFiSyslogEnabled:    true,
		UniFiSyslogPort:       5514,
		UniFiSyslogAllowedIPs: []string{"192.168.1.1", "192.168.1.0/24"},
		CaptureInterface:      "eth0",
		CaptureBPFFilter:      "tcp or udp",
		CapturePromiscuous:    true,
		StorageDir:            "/tmp/foo",
		LogLevel:              "debug",
		Environment:           "development",
		LocalSubnets:          []string{"192.168.10.0/24"},
		WebhookURL:            "https://example.invalid/hook",
		WebhookFormat:         "generic",
		WebhookHeaders:        map[string]string{"Authorization": "Bearer test"},
		StorageBackend:        "duckdb",
		FirstRunCompleted:     true,
		RetentionDays:         7,
		DDoSThresholdPPS:      5000,
		DDoSThresholdBPS:      10485760,
		DDoSThresholdFPS:      1000,
		SYNFloodThresholdPPS:  1000,
		UDPFloodThresholdPPS:  3000,
		ICMPFloodThresholdPPS: 500,
	}

	bodyBytes, _ := json.Marshal(newSettings)
	req = httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(string(bodyBytes)))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d with body: %s", w.Code, w.Body.String())
	}

	// Verify settings were updated in memory
	if server.cfg.Port != "9090" || server.cfg.StorageBackend != "duckdb" || !server.cfg.FirstRunCompleted {
		t.Errorf("expected updated server configuration, got %+v", server.cfg)
	}
	if server.cfg.CaptureInterface != "eth0" || server.cfg.CaptureBPFFilter != "tcp or udp" || !server.cfg.CapturePromiscuous {
		t.Errorf("expected capture settings to update in memory, got %+v", server.cfg)
	}
	if !server.cfg.UniFiSyslogEnabled || server.cfg.UniFiSyslogPort != 5514 || len(server.cfg.UniFiSyslogAllowedIPs) != 2 {
		t.Errorf("expected UniFi syslog settings to update in memory, got %+v", server.cfg)
	}
	if server.cfg.WebhookHeaders["Authorization"] != "Bearer test" {
		t.Errorf("expected webhook headers to update in memory, got %+v", server.cfg.WebhookHeaders)
	}

	// Verify settings were persisted on disk
	loadedConfig, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed loading saved config: %v", err)
	}
	if loadedConfig.Port != "9090" || !loadedConfig.FirstRunCompleted {
		t.Errorf("expected loaded config to have updated values, got %+v", loadedConfig)
	}
	if loadedConfig.CaptureInterface != "eth0" || loadedConfig.CaptureBPFFilter != "tcp or udp" || !loadedConfig.CapturePromiscuous {
		t.Errorf("expected capture settings to persist, got %+v", loadedConfig)
	}
	if !loadedConfig.UniFiSyslogEnabled || loadedConfig.UniFiSyslogPort != 5514 || len(loadedConfig.UniFiSyslogAllowedIPs) != 2 {
		t.Errorf("expected UniFi syslog settings to persist, got %+v", loadedConfig)
	}
	if loadedConfig.WebhookHeaders["Authorization"] != "Bearer test" {
		t.Errorf("expected loaded config to persist webhook headers, got %+v", loadedConfig.WebhookHeaders)
	}
}

func TestSettingsAPI_ValidationAndMasking(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TelegramToken = "secret-token-123"
	cfg.RetentionDays = 7
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}

	tmpFile, err := os.CreateTemp("", "config_test_settings")
	if err != nil {
		t.Fatalf("failed creating tmp config: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, nil, tmpFile.Name())

	// 1. GET settings - verify masking
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 GET, got %d", w.Code)
	}
	var getResp SettingsPayload
	if err := json.Unmarshal(w.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("failed decoding GET settings response: %v", err)
	}
	if getResp.TelegramToken != "******" {
		t.Errorf("expected TelegramToken to be masked, got: %s", getResp.TelegramToken)
	}
	if getResp.RetentionDays != 7 {
		t.Errorf("expected default retention days 7, got: %d", getResp.RetentionDays)
	}

	// 2. POST settings - verify validation failures
	// A. Too short password
	badBody := `{"port":"8080","netflow_port":2055,"sflow_port":6343,"storage_backend":"sqlite","local_subnets":["192.168.0.0/16"],"retention_days":7,"ddos_threshold_pps":5000,"ddos_threshold_bps":10000000,"ddos_threshold_fps":1000,"syn_flood_threshold_pps":1000,"udp_flood_threshold_pps":3000,"icmp_flood_threshold_pps":500,"log_level":"info","environment":"production","admin_password":"short"}`
	req = httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(badBody))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for short password, got %d", w.Code)
	}

	// B. Invalid CIDR subnet
	badCIDR := `{"port":"8080","netflow_port":2055,"sflow_port":6343,"storage_backend":"sqlite","local_subnets":["192.168.0.256/24"],"retention_days":7,"ddos_threshold_pps":5000,"ddos_threshold_bps":10000000,"ddos_threshold_fps":1000,"syn_flood_threshold_pps":1000,"udp_flood_threshold_pps":3000,"icmp_flood_threshold_pps":500,"log_level":"info","environment":"production"}`
	req = httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(badCIDR))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for invalid CIDR, got %d", w.Code)
	}

	// C. Out-of-bounds port
	badPort := `{"port":"8080","netflow_port":99999,"sflow_port":6343,"storage_backend":"sqlite","local_subnets":["192.168.0.0/24"],"retention_days":7,"ddos_threshold_pps":5000,"ddos_threshold_bps":10000000,"ddos_threshold_fps":1000,"syn_flood_threshold_pps":1000,"udp_flood_threshold_pps":3000,"icmp_flood_threshold_pps":500,"log_level":"info","environment":"production"}`
	req = httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(badPort))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for out-of-bounds port, got %d", w.Code)
	}

	// D. Passive capture requires a bounded, non-empty BPF filter.
	badCapture := `{"port":"8080","netflow_port":2055,"sflow_port":6343,"capture_interface":"eth0","capture_bpf_filter":"","storage_backend":"sqlite","local_subnets":["192.168.0.0/24"],"retention_days":7,"ddos_threshold_pps":5000,"ddos_threshold_bps":10000000,"ddos_threshold_fps":1000,"syn_flood_threshold_pps":1000,"udp_flood_threshold_pps":3000,"icmp_flood_threshold_pps":500,"log_level":"info","environment":"production"}`
	req = httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(badCapture))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for enabled capture without BPF filter, got %d", w.Code)
	}

	// E. Collector ports must not conflict when enabled.
	badCollectorConflict := `{"port":"8080","netflow_port":2055,"sflow_port":6343,"unifi_syslog_enabled":true,"unifi_syslog_port":2055,"storage_backend":"sqlite","local_subnets":["192.168.0.0/24"],"retention_days":7,"ddos_threshold_pps":5000,"ddos_threshold_bps":10000000,"ddos_threshold_fps":1000,"syn_flood_threshold_pps":1000,"udp_flood_threshold_pps":3000,"icmp_flood_threshold_pps":500,"log_level":"info","environment":"production"}`
	req = httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(badCollectorConflict))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for collector port conflict, got %d", w.Code)
	}

	// 3. POST settings - verify successful update with masked token preservation
	validBody := `{"port":"8082","netflow_port":2056,"sflow_port":6344,"storage_backend":"sqlite","local_subnets":["192.168.1.0/24"],"retention_days":15,"ddos_threshold_pps":6000,"ddos_threshold_bps":12000000,"ddos_threshold_fps":1200,"syn_flood_threshold_pps":1100,"udp_flood_threshold_pps":3100,"icmp_flood_threshold_pps":600,"log_level":"debug","environment":"development","telegram_token":"******"}`
	req = httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(validBody))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	// Assert config was updated in memory
	if cfg.Port != "8082" || cfg.NetflowPort != 2056 || cfg.RetentionDays != 15 || cfg.LogLevel != "debug" || cfg.Environment != "development" {
		t.Errorf("config in memory was not updated correctly: %+v", cfg)
	}
	// Assert the actual secret token was preserved (not overwritten by ******)
	if cfg.TelegramToken != "secret-token-123" {
		t.Errorf("Telegram token was overwritten by mask: %s", cfg.TelegramToken)
	}
}
