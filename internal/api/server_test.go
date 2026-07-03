package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/flowguard/flowguard/internal/config"
)

func TestHandleHealth(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewAPIServer(cfg, logger)

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
	if res.Environment != cfg.Environment {
		t.Errorf("expected environment %s, got %s", cfg.Environment, res.Environment)
	}
	if res.Version != "0.1.0" {
		t.Errorf("expected version 0.1.0, got %s", res.Version)
	}
}

func TestHandleHealth_InvalidMethod(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewAPIServer(cfg, logger)

	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected status MethodNotAllowed (405), got %v", resp.Status)
	}
}
