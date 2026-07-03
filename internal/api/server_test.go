package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/flowguard/flowguard/internal/collector"
	"github.com/flowguard/flowguard/internal/config"
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
