package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/collector"
	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/risk"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

func TestHandleHealth(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockColl := &MockCollector{
		Stats: collector.Stats{
			PacketsReceived: 42,
			DecodeErrors:    1,
		},
	}
	server := NewAPIServer(cfg, logger, mockColl, nil, nil, nil, nil, nil, nil, nil, "")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	var res HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if res.Status != "OK" {
		t.Errorf("expected status 'OK', got %s", res.Status)
	}
	if !res.Healthy {
		t.Error("expected healthy flag to be true")
	}
	if res.Collector == nil {
		t.Fatal("expected collector stats in response, got nil")
	}
	if res.Collector.PacketsReceived != 42 {
		t.Errorf("expected PacketsReceived 42, got %d", res.Collector.PacketsReceived)
	}
	if res.Collector.DecodeErrors != 1 {
		t.Errorf("expected DecodeErrors 1, got %d", res.Collector.DecodeErrors)
	}
}

func TestAccessLogMiddleware(t *testing.T) {
	cfg := config.DefaultConfig()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	server := NewAPIServer(cfg, logger, nil, nil, nil, nil, nil, nil, nil, nil, "")

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status OK, got %d", w.Code)
	}
	logLine := buf.String()
	for _, want := range []string{
		"msg=\"HTTP request\"",
		"method=GET",
		"path=/api/health",
		"status=200",
	} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("expected access log to contain %q, got %s", want, logLine)
		}
	}
}

func TestHandleHealth_InvalidMethod(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewAPIServer(cfg, logger, nil, nil, nil, nil, nil, nil, nil, nil, "")

	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected status MethodNotAllowed (405), got %v", resp.Status)
	}
}

func TestHandleExporters(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now()
	mockColl := &MockCollector{
		Exporters: []collector.ExporterMetadata{
			{IP: "192.168.1.1", LastSeen: now, PacketCount: 100},
		},
	}
	server := NewAPIServer(cfg, logger, mockColl, nil, nil, nil, nil, nil, nil, nil, "")

	req := httptest.NewRequest(http.MethodGet, "/api/exporters", nil)
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}

	var res []collector.ExporterMetadata
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(res) != 1 {
		t.Fatalf("expected 1 exporter, got %d", len(res))
	}
	if res[0].IP != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %s", res[0].IP)
	}
	if res[0].PacketCount != 100 {
		t.Errorf("expected PacketCount 100, got %d", res[0].PacketCount)
	}
}

func TestParseQueryParams_Valid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/top/sources?limit=25&start=2026-07-03T12:00:00Z&end=2026-07-03T13:00:00Z", nil)
	start, end, limit, err := parseQueryParams(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if limit != 25 {
		t.Errorf("expected limit 25, got %d", limit)
	}
	if start.Format(time.RFC3339) != "2026-07-03T12:00:00Z" {
		t.Errorf("expected start RFC3339, got %s", start.Format(time.RFC3339))
	}
	if end.Format(time.RFC3339) != "2026-07-03T13:00:00Z" {
		t.Errorf("expected end RFC3339, got %s", end.Format(time.RFC3339))
	}
}

func TestParseQueryParams_Invalid(t *testing.T) {
	// Invalid limit
	req := httptest.NewRequest(http.MethodGet, "/api/top/sources?limit=-5", nil)
	_, _, _, err := parseQueryParams(req)
	if err == nil {
		t.Error("expected error for negative limit, got nil")
	}

	// Range exceeds 7 days
	req = httptest.NewRequest(http.MethodGet, "/api/top/sources?start=2026-07-01T00:00:00Z&end=2026-07-10T00:00:00Z", nil)
	_, _, _, err = parseQueryParams(req)
	if err == nil {
		t.Error("expected error for range > 7 days, got nil")
	}

	// Start after end
	req = httptest.NewRequest(http.MethodGet, "/api/top/sources?start=2026-07-03T14:00:00Z&end=2026-07-03T13:00:00Z", nil)
	_, _, _, err = parseQueryParams(req)
	if err == nil {
		t.Error("expected error for start after end, got nil")
	}
}

func TestHandleUI(t *testing.T) {
	// Skip if UI assets are not compiled (e.g. in CI native test job)
	uiDir := filepath.Join("..", "ui", "assets", "dist")
	if _, err := os.Stat(filepath.Join(uiDir, "index.html")); os.IsNotExist(err) {
		t.Skip("compiled UI assets not found, skipping UI handler test")
		return
	}

	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewAPIServer(cfg, logger, nil, nil, nil, nil, nil, nil, nil, nil, "")

	// Fetch root "/"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected OK (200), got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "FlowGuard Lite Dashboard") {
		t.Errorf("expected HTML body to contain 'FlowGuard Lite Dashboard', got: %s", body)
	}

	// Fetch styles.css
	req = httptest.NewRequest(http.MethodGet, "/styles.css", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected OK (200) for styles.css, got %d", w.Code)
	}

	// Fetch app.js
	req = httptest.NewRequest(http.MethodGet, "/app.js", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected OK (200) for app.js, got %d", w.Code)
	}
}

func TestHandleAnomalies(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}

	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, nil, "")

	// 1. GET /api/anomalies
	req := httptest.NewRequest(http.MethodGet, "/api/anomalies?limit=10", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	var anomalies []struct {
		storage.Anomaly
		DeviceLabel       string `json:"device_label"`
		DeviceHostname    string `json:"device_hostname"`
		DeviceDisplayName string `json:"device_display_name"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &anomalies); err != nil {
		t.Fatalf("failed decoding anomalies: %v", err)
	}
	if len(anomalies) != 1 || anomalies[0].ID != 123 || anomalies[0].Type != "TRAFFIC_SPIKE" {
		t.Errorf("unexpected anomalies result: %v", anomalies)
	}
	if anomalies[0].DeviceDisplayName != "Discovered Device" || anomalies[0].DeviceHostname != "test.local" {
		t.Errorf("expected anomaly device identity enrichment, got: %+v", anomalies[0])
	}

	// 2. PUT /api/anomalies/123/status (valid)
	bodyStr := `{"status": "acknowledged"}`
	req = httptest.NewRequest(http.MethodPut, "/api/anomalies/123/status", strings.NewReader(bodyStr))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	// 3. PUT /api/anomalies/999/status (not found)
	req = httptest.NewRequest(http.MethodPut, "/api/anomalies/999/status", strings.NewReader(bodyStr))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status NotFound (404), got %d", w.Code)
	}
}

func TestHandleListRiskDevices(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}

	// Add some mock devices and active anomalies to MockFlowRepository so we can score
	mockRepo.Devices = []storage.Device{
		{IP: "192.168.1.10", Hostname: "test.local", Label: "Discovered Device"},
	}
	mockRepo.Anomalies = []storage.Anomaly{
		{IP: "192.168.1.10", Type: "TRAFFIC_SPIKE", Severity: "high", Status: "active", CreatedAt: time.Now()},
	}

	riskEng := risk.NewRiskEngine(mockRepo)
	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, riskEng, nil, nil, nil, "")

	req := httptest.NewRequest(http.MethodGet, "/api/risk/devices", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	var results []risk.DeviceRisk
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatalf("failed decoding risk list: %v", err)
	}
	if len(results) != 1 || results[0].RiskScore != 40 || results[0].RiskLevel != "medium" {
		t.Errorf("unexpected risk list: %+v", results)
	}
}

func TestHandleListAuditLogs(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}

	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, nil, "")

	req := httptest.NewRequest(http.MethodGet, "/api/audit-logs?limit=10", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	var results []storage.AuditLog
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatalf("failed decoding audit logs: %v", err)
	}
	if len(results) != 1 || results[0].Action != "update_label" {
		t.Errorf("unexpected audit logs list: %+v", results)
	}
}

func TestHandleGetFirewallRules(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}

	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, nil, "")

	// Test missing/invalid IP
	req := httptest.NewRequest(http.MethodGet, "/api/firewall/rules", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", w.Code)
	}

	// Test valid IP
	req = httptest.NewRequest(http.MethodGet, "/api/firewall/rules?ip=192.168.1.100", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w.Code)
	}

	var results map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatalf("failed decoding firewall rules templates: %v", err)
	}
	if results["ip"] != "192.168.1.100" || results["mikrotik"] == "" || results["unifi"] == "" || results["opnsense"] == "" {
		t.Errorf("unexpected firewall templates result: %+v", results)
	}
}

func TestHandleMetrics(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}

	// Seed mock device and anomaly
	mockRepo.Devices = []storage.Device{
		{IP: "192.168.1.100", Hostname: "tv.local", Label: "IoT"},
	}
	mockRepo.Anomalies = []storage.Anomaly{
		{IP: "192.168.1.100", Type: "ddos", Severity: "high", Status: "active", CreatedAt: time.Now()},
	}

	// Create a mock collector
	coll := collector.NewFlowCollector(cfg, logger, nil, nil)

	server := NewAPIServer(cfg, logger, coll, mockRepo, mockRepo, nil, nil, nil, nil, nil, "")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("expected text/plain Content-Type, got %q", contentType)
	}

	body := w.Body.String()
	if !strings.Contains(body, "flowguard_collector_packets_total") {
		t.Error("expected flowguard_collector_packets_total metric in output")
	}
	if !strings.Contains(body, `flowguard_collector_source_enabled{kind="netflow",id="netflow"} 1`) {
		t.Error("expected bounded netflow collector source metric in output")
	}
	if !strings.Contains(body, `flowguard_collector_source_enabled{kind="unifi_syslog",id="unifi_syslog"} 0`) {
		t.Error("expected bounded UniFi syslog collector source metric in output")
	}
	if !strings.Contains(body, `flowguard_collector_source_drops_total{kind="unifi_syslog",id="unifi_syslog"} 0`) {
		t.Error("expected bounded UniFi syslog source drop metric in output")
	}
	if !strings.Contains(body, `flowguard_collector_source_errors_total{kind="unifi_syslog",id="unifi_syslog"} 0`) {
		t.Error("expected bounded UniFi syslog source error metric in output")
	}
	if !strings.Contains(body, "flowguard_discovered_devices_total 1") {
		t.Error("expected flowguard_discovered_devices_total 1 metric in output")
	}
	if !strings.Contains(body, `flowguard_active_anomalies{severity="high",type="ddos"} 1`) {
		t.Error("expected active anomalies metrics matching mock setup")
	}
}
