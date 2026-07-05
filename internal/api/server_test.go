package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flowguard/flowguard/internal/baseline"
	"github.com/flowguard/flowguard/internal/collector"
	"github.com/flowguard/flowguard/internal/config"
	"github.com/flowguard/flowguard/internal/flow"
	"github.com/flowguard/flowguard/internal/risk"
	"github.com/flowguard/flowguard/internal/storage"
	"github.com/flowguard/flowguard/internal/webhook"
)

type MockCollector struct {
	Stats     collector.Stats
	Exporters []collector.ExporterMetadata
}

func (m *MockCollector) GetStats() collector.Stats {
	return m.Stats
}

func (m *MockCollector) GetExporters() []collector.ExporterMetadata {
	return m.Exporters
}

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

type MockFlowRepository struct {
	Sources      []flow.TopResult
	Destinations []flow.TopResult
	Ports        []flow.TopResult
	Protocols    []flow.TopResult
	Baseline     *storage.DeviceBaseline
	Devices      []storage.Device
	Anomalies    []storage.Anomaly
	Err          error
}

func (m *MockFlowRepository) SaveAggregates(ctx context.Context, ts time.Time, aggregates []flow.FlowEvent) error {
	return nil
}

func (m *MockFlowRepository) GetTopSources(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return m.Sources, m.Err
}

func (m *MockFlowRepository) GetTopDestinations(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return m.Destinations, m.Err
}

func (m *MockFlowRepository) GetTopPorts(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return m.Ports, m.Err
}

func (m *MockFlowRepository) GetTopProtocols(ctx context.Context, start, end time.Time, limit int) ([]flow.TopResult, error) {
	return m.Protocols, m.Err
}

func (m *MockFlowRepository) GetTrafficTimeSeries(ctx context.Context, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error) {
	return []flow.TrafficTimeBucket{
		{Timestamp: start.UTC(), Bytes: 1000, Packets: 10, Flows: 2},
	}, m.Err
}

func (m *MockFlowRepository) UpsertDevice(ctx context.Context, ip string, hostname string, lastSeen time.Time) error {
	return nil
}

func (m *MockFlowRepository) UpdateDeviceLabel(ctx context.Context, ip string, label string) error {
	if ip == "192.168.1.10" {
		return m.Err
	}
	return errors.New("device not found")
}

func (m *MockFlowRepository) GetDevice(ctx context.Context, ip string) (*storage.Device, error) {
	for _, d := range m.Devices {
		if d.IP == ip {
			return &d, m.Err
		}
	}
	return nil, m.Err
}

func (m *MockFlowRepository) ListDevices(ctx context.Context) ([]storage.Device, error) {
	if len(m.Devices) > 0 {
		return m.Devices, m.Err
	}
	return []storage.Device{
		{IP: "192.168.1.10", Label: "Discovered Device", Hostname: "test.local"},
	}, m.Err
}

func (m *MockFlowRepository) SaveBaseline(ctx context.Context, b *storage.DeviceBaseline) error {
	m.Baseline = b
	return m.Err
}

func (m *MockFlowRepository) GetBaseline(ctx context.Context, ip string) (*storage.DeviceBaseline, error) {
	if m.Baseline != nil && m.Baseline.IP == ip {
		return m.Baseline, m.Err
	}
	return nil, m.Err
}

func (m *MockFlowRepository) SaveAnomaly(ctx context.Context, a *storage.Anomaly) error {
	return m.Err
}

func (m *MockFlowRepository) UpdateAnomalyStatus(ctx context.Context, id int64, status string) error {
	if id == 123 {
		return m.Err
	}
	return errors.New("anomaly not found")
}

func (m *MockFlowRepository) ListAnomalies(ctx context.Context, limit int) ([]storage.Anomaly, error) {
	return []storage.Anomaly{
		{ID: 123, IP: "192.168.1.10", Type: "TRAFFIC_SPIKE", Status: "active"},
	}, m.Err
}

func (m *MockFlowRepository) GetActiveAnomalies(ctx context.Context, since time.Time) ([]storage.Anomaly, error) {
	if len(m.Anomalies) > 0 {
		return m.Anomalies, m.Err
	}
	return []storage.Anomaly{
		{ID: 123, IP: "192.168.1.10", Type: "TRAFFIC_SPIKE", Status: "active", CreatedAt: time.Now()},
	}, m.Err
}

func (m *MockFlowRepository) SaveAuditLog(ctx context.Context, action string, details string) error {
	return m.Err
}

func (m *MockFlowRepository) ListAuditLogs(ctx context.Context, limit int) ([]storage.AuditLog, error) {
	return []storage.AuditLog{
		{ID: 1, Timestamp: time.Now(), Action: "update_label", Details: "Updated label"},
	}, m.Err
}

func (m *MockFlowRepository) GetAnomaliesForIP(ctx context.Context, ip string, limit int) ([]storage.Anomaly, error) {
	var filtered []storage.Anomaly
	for _, a := range m.Anomalies {
		if a.IP == ip {
			filtered = append(filtered, a)
			if len(filtered) >= limit {
				break
			}
		}
	}
	if len(filtered) == 0 && len(m.Anomalies) > 0 {
		for _, a := range m.Anomalies {
			filtered = append(filtered, a)
			if len(filtered) >= limit {
				break
			}
		}
	}
	return filtered, m.Err
}

func (m *MockFlowRepository) GetDeviceTrafficTimeSeries(ctx context.Context, ip string, start, end time.Time, bucketSeconds int) ([]flow.TrafficTimeBucket, error) {
	return []flow.TrafficTimeBucket{
		{Timestamp: start.UTC(), Bytes: 500, Packets: 5, Flows: 1},
	}, m.Err
}

func (m *MockFlowRepository) GetDeviceTopPeers(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error) {
	if m.Destinations == nil {
		return []flow.TopResult{}, m.Err
	}
	return m.Destinations, m.Err
}

func (m *MockFlowRepository) GetDeviceTopPorts(ctx context.Context, ip string, start, end time.Time, limit int) ([]flow.TopResult, error) {
	if m.Ports == nil {
		return []flow.TopResult{}, m.Err
	}
	return m.Ports, m.Err
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

func TestHandleTopTalkers(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{
		Sources: []flow.TopResult{
			{Key: "192.168.1.10", Bytes: 1000, Packets: 10, Flows: 1},
		},
		Destinations: []flow.TopResult{
			{Key: "8.8.8.8", Bytes: 500, Packets: 5, Flows: 1},
		},
		Ports: []flow.TopResult{
			{Key: "53", Bytes: 500, Packets: 5, Flows: 1},
		},
		Protocols: []flow.TopResult{
			{Key: "17", Bytes: 500, Packets: 5, Flows: 1},
		},
	}

	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, nil, "")

	// 1. Sources check
	req := httptest.NewRequest(http.MethodGet, "/api/top/sources", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected OK, got %d", w.Code)
	}
	var srcRes []flow.TopResult
	if err := json.Unmarshal(w.Body.Bytes(), &srcRes); err != nil {
		t.Fatalf("failed decoding: %v", err)
	}
	if len(srcRes) != 1 || srcRes[0].Key != "192.168.1.10" {
		t.Errorf("unexpected sources output: %v", srcRes)
	}

	// 2. Destinations check
	req = httptest.NewRequest(http.MethodGet, "/api/top/destinations", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected OK, got %d", w.Code)
	}
	var dstRes []flow.TopResult
	if err := json.Unmarshal(w.Body.Bytes(), &dstRes); err != nil {
		t.Fatalf("failed decoding: %v", err)
	}
	if len(dstRes) != 1 || dstRes[0].Key != "8.8.8.8" {
		t.Errorf("unexpected destinations output: %v", dstRes)
	}

	// 3. Ports check
	req = httptest.NewRequest(http.MethodGet, "/api/top/ports", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected OK, got %d", w.Code)
	}
	var portRes []flow.TopResult
	if err := json.Unmarshal(w.Body.Bytes(), &portRes); err != nil {
		t.Fatalf("failed decoding: %v", err)
	}
	if len(portRes) != 1 || portRes[0].Key != "53" {
		t.Errorf("unexpected ports output: %v", portRes)
	}

	// 4. Protocols check
	req = httptest.NewRequest(http.MethodGet, "/api/top/protocols", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected OK, got %d", w.Code)
	}
	var protocolRes []flow.TopResult
	if err := json.Unmarshal(w.Body.Bytes(), &protocolRes); err != nil {
		t.Fatalf("failed decoding: %v", err)
	}
	if len(protocolRes) != 1 || protocolRes[0].Key != "17" {
		t.Errorf("unexpected protocols output: %v", protocolRes)
	}
}

func TestHandleTrafficTimeSeries(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}
	server := NewAPIServer(cfg, logger, nil, mockRepo, nil, nil, nil, nil, nil, nil, "")

	start := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	end := time.Now().UTC().Format(time.RFC3339)
	req := httptest.NewRequest(http.MethodGet, "/api/traffic/timeseries?start="+start+"&end="+end+"&bucket_seconds=300", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var result []flow.TrafficTimeBucket
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed decoding traffic time series: %v", err)
	}
	if len(result) != 1 || result[0].Bytes != 1000 || result[0].Packets != 10 || result[0].Flows != 2 {
		t.Fatalf("unexpected traffic time series result: %+v", result)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/traffic/timeseries?bucket_seconds=17", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid bucket to return 400, got %d", w.Code)
	}
}

func TestHandleUI(t *testing.T) {
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

func TestHandleDevices(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}

	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, nil, "")

	// 1. GET /api/devices
	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	var devices []storage.Device
	if err := json.Unmarshal(w.Body.Bytes(), &devices); err != nil {
		t.Fatalf("failed decoding devices: %v", err)
	}
	if len(devices) != 1 || devices[0].IP != "192.168.1.10" {
		t.Errorf("unexpected devices result: %v", devices)
	}

	// 2. PUT /api/devices/192.168.1.10/label (valid)
	bodyStr := `{"label": "My Router"}`
	req = httptest.NewRequest(http.MethodPut, "/api/devices/192.168.1.10/label", strings.NewReader(bodyStr))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	// 3. PUT /api/devices/1.1.1.1/label (not found)
	req = httptest.NewRequest(http.MethodPut, "/api/devices/1.1.1.1/label", strings.NewReader(bodyStr))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status NotFound (404), got %d", w.Code)
	}
}

func TestHandleDeviceBaseline(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}
	engine := baseline.NewBaselineEngine(mockRepo, logger)

	ip := "192.168.1.10"
	mockRepo.Baseline = &storage.DeviceBaseline{
		IP:        ip,
		MeanBytes: 25000.0,
		UpdatedAt: time.Now().Truncate(time.Second),
	}
	_ = engine.LoadBaselines(context.Background())

	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, engine, nil, nil, nil, nil, "")

	// 1. GET /api/devices/192.168.1.10/baseline (valid)
	req := httptest.NewRequest(http.MethodGet, "/api/devices/192.168.1.10/baseline", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	var baseVal storage.DeviceBaseline
	if err := json.Unmarshal(w.Body.Bytes(), &baseVal); err != nil {
		t.Fatalf("failed decoding baseline: %v", err)
	}
	if baseVal.MeanBytes != 25000.0 {
		t.Errorf("expected mean bytes 25000.0, got %f", baseVal.MeanBytes)
	}

	// 2. GET /api/devices/1.1.1.1/baseline (not found)
	req = httptest.NewRequest(http.MethodGet, "/api/devices/1.1.1.1/baseline", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status NotFound (404), got %d", w.Code)
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

	var anomalies []storage.Anomaly
	if err := json.Unmarshal(w.Body.Bytes(), &anomalies); err != nil {
		t.Fatalf("failed decoding anomalies: %v", err)
	}
	if len(anomalies) != 1 || anomalies[0].ID != 123 || anomalies[0].Type != "TRAFFIC_SPIKE" {
		t.Errorf("unexpected anomalies result: %v", anomalies)
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

	// 2. POST settings
	newSettings := SettingsPayload{
		Port:              "9090",
		NetflowPort:       3000,
		SflowPort:         4000,
		StorageDir:        "/tmp/foo",
		LogLevel:          "debug",
		Environment:       "development",
		LocalSubnets:      []string{"192.168.10.0/24"},
		WebhookURL:        "https://example.invalid/hook",
		WebhookFormat:     "generic",
		WebhookHeaders:    map[string]string{"Authorization": "Bearer test"},
		StorageBackend:    "duckdb",
		FirstRunCompleted: true,
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
	if loadedConfig.WebhookHeaders["Authorization"] != "Bearer test" {
		t.Errorf("expected loaded config to persist webhook headers, got %+v", loadedConfig.WebhookHeaders)
	}
}

func TestAuthSetupLoginAndProtectedAPI(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "api_auth_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	cfg := config.DefaultConfig()
	cfg.FirstRunCompleted = true
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockColl := &MockCollector{}
	server := NewAPIServer(cfg, logger, mockColl, nil, nil, nil, nil, nil, nil, nil, configPath)

	req := httptest.NewRequest(http.MethodGet, "/api/exporters", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected protected API to require auth, got %d", w.Code)
	}

	setupBody := `{"password":"correct horse battery"}`
	req = httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(setupBody))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected setup 200, got %d: %s", w.Code, w.Body.String())
	}
	if server.cfg.AdminPasswordHash == "" || strings.Contains(server.cfg.AdminPasswordHash, "correct horse battery") {
		t.Fatalf("expected stored password hash, got %q", server.cfg.AdminPasswordHash)
	}
	setupCookie := w.Result().Cookies()[0]

	req = httptest.NewRequest(http.MethodGet, "/api/exporters", nil)
	req.AddCookie(setupCookie)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected authenticated API request to succeed, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(setupCookie)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected logout 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/exporters", nil)
	req.AddCookie(setupCookie)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected logged-out cookie to be rejected, got %d", w.Code)
	}

	loginBody := `{"password":"correct horse battery"}`
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(loginBody))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuthRejectsShortPasswordAndInvalidLogin(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.FirstRunCompleted = true
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewAPIServer(cfg, logger, nil, nil, nil, nil, nil, nil, nil, nil, "")

	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(`{"password":"short"}`))
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected short password 400, got %d", w.Code)
	}

	hash, err := hashPassword("correct horse battery")
	if err != nil {
		t.Fatalf("failed hashing password: %v", err)
	}
	server.cfg.AdminPasswordHash = hash

	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"password":"wrong password"}`))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected invalid login 401, got %d", w.Code)
	}
}

func TestHandleTestAlert(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}

	receivedChan := make(chan []byte, 1)
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		receivedChan <- bodyBytes
	}))
	defer mockServer.Close()

	engine := webhook.NewWebhookEngine(mockServer.URL, "generic", nil, false, "", "", logger)
	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, engine, "")

	req := httptest.NewRequest(http.MethodPost, "/api/settings/test-alert", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed decoding test alert response: %v", err)
	}
	if resp["status"] != "test alert dispatched successfully" {
		t.Errorf("unexpected status message: %s", resp["status"])
	}

	select {
	case body := <-receivedChan:
		var anomaly storage.Anomaly
		if err := json.Unmarshal(body, &anomaly); err != nil {
			t.Fatalf("failed to unmarshal test anomaly: %v", err)
		}
		if anomaly.Type != "test_alert" || anomaly.IP != "192.168.1.99" {
			t.Errorf("unexpected anomaly in test alert: %+v", anomaly)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for test alert webhook dispatch")
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
	coll := collector.NewFlowCollector(cfg, logger, nil)

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
	if !strings.Contains(body, "flowguard_discovered_devices_total 1") {
		t.Error("expected flowguard_discovered_devices_total 1 metric in output")
	}
	if !strings.Contains(body, `flowguard_active_anomalies{severity="high",type="ddos"} 1`) {
		t.Error("expected active anomalies metrics matching mock setup")
	}
}

func TestHandleGetDeviceProfileAndFlows(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}

	// Setup mock data
	ip := "192.168.1.10"
	mockRepo.Devices = []storage.Device{
		{IP: ip, Hostname: "test.local", Label: "Discovered Device", Vendor: "Apple", FirstSeen: time.Now(), LastSeen: time.Now()},
	}
	mockRepo.Baseline = &storage.DeviceBaseline{
		IP:        ip,
		MeanBytes: 12345.0,
		UpdatedAt: time.Now().Truncate(time.Second),
	}
	mockRepo.Anomalies = []storage.Anomaly{
		{ID: 10, IP: ip, Type: "TRAFFIC_SPIKE", Severity: "high", Status: "active", CreatedAt: time.Now()},
	}

	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, nil, "")

	// 1. Test GET /api/devices/{ip} (profile)
	req := httptest.NewRequest(http.MethodGet, "/api/devices/"+ip, nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	var profile map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil {
		t.Fatalf("failed decoding profile: %v", err)
	}

	if profile["ip"] != ip {
		t.Errorf("expected IP %s, got %v", ip, profile["ip"])
	}
	if profile["subnet_vlan"] == nil {
		t.Error("expected subnet_vlan to be present")
	}
	if profile["risk"] == nil {
		t.Error("expected risk to be present")
	}

	// 2. Test GET /api/devices/{ip}/flows
	req = httptest.NewRequest(http.MethodGet, "/api/devices/"+ip+"/flows?bucket_seconds=60", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	var flows map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &flows); err != nil {
		t.Fatalf("failed decoding flows: %v", err)
	}

	if flows["time_series"] == nil {
		t.Error("expected time_series to be present")
	}
	if flows["top_peers"] == nil {
		t.Error("expected top_peers to be present")
	}
	if flows["top_ports"] == nil {
		t.Error("expected top_ports to be present")
	}

	// 3. Test invalid IP format
	req = httptest.NewRequest(http.MethodGet, "/api/devices/invalid-ip", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected StatusBadRequest (400), got %d", w.Code)
	}

	// 4. Test device not found
	req = httptest.NewRequest(http.MethodGet, "/api/devices/1.2.3.4", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected StatusNotFound (404), got %d", w.Code)
	}
}
