package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

func TestHandleListUniFiEvents(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}

	// Seed mock events
	now := time.Now().UTC()
	mockRepo.UniFiEvents = []storage.UniFiEvent{
		{
			ID:            1,
			Timestamp:     now,
			SourceGateway: "192.168.1.1",
			Category:      "Security Detections",
			Severity:      "high",
			ClientIP:      "192.168.1.50",
			Summary:       "Threat detected",
			Attributes:    map[string]string{"signature_id": "2018402"},
		},
	}

	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, nil, "")

	req := httptest.NewRequest(http.MethodGet, "/api/security/unifi-events", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	var events []storage.UniFiEvent
	if err := json.Unmarshal(w.Body.Bytes(), &events); err != nil {
		t.Fatalf("failed decoding events: %v", err)
	}
	if len(events) != 1 || events[0].ClientIP != "192.168.1.50" {
		t.Errorf("unexpected events list: %+v", events)
	}
}

func TestHandleGetDeviceUniFiEvents(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}

	now := time.Now().UTC()
	mockRepo.UniFiEvents = []storage.UniFiEvent{
		{
			ID:            1,
			Timestamp:     now,
			SourceGateway: "192.168.1.1",
			Category:      "Security Detections",
			Severity:      "high",
			ClientIP:      "192.168.1.50",
			Summary:       "Threat detected",
			Attributes:    map[string]string{},
		},
		{
			ID:            2,
			Timestamp:     now,
			SourceGateway: "192.168.1.1",
			Category:      "Admin Activity",
			Severity:      "low",
			ClientIP:      "192.168.1.100",
			Summary:       "Admin login",
			Attributes:    map[string]string{},
		},
	}

	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, nil, "")

	req := httptest.NewRequest(http.MethodGet, "/api/devices/192.168.1.50/unifi-events", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	var events []storage.UniFiEvent
	if err := json.Unmarshal(w.Body.Bytes(), &events); err != nil {
		t.Fatalf("failed decoding events: %v", err)
	}
	if len(events) != 1 || events[0].ClientIP != "192.168.1.50" {
		t.Errorf("unexpected events list for device: %+v", events)
	}
}
