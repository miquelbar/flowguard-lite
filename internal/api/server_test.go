package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/flowguard/flowguard/internal/collector"
	"github.com/flowguard/flowguard/internal/config"
	"github.com/flowguard/flowguard/internal/flow"
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
	server := NewAPIServer(cfg, logger, mockColl, nil)

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
	server := NewAPIServer(cfg, logger, nil, nil)

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
	server := NewAPIServer(cfg, logger, mockColl, nil)

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
	}

	server := NewAPIServer(cfg, logger, nil, mockRepo)

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
}

func TestHandleUI(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewAPIServer(cfg, logger, nil, nil)

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
