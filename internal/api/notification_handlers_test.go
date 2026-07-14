package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/storage"
	"github.com/miquelbar/flowguard-lite/internal/webhook"
)

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

	engine := webhook.NewWebhookEngine(nil, "", mockServer.URL, "generic", nil, false, "", "", logger)
	defer shutdownNotificationTestWebhookEngine(t, engine)
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

func TestHandleTestNotificationRule(t *testing.T) {
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

	engine := webhook.NewWebhookEngine(nil, mockServer.URL, "", "generic", nil, false, "", "", logger)
	defer shutdownNotificationTestWebhookEngine(t, engine)
	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, engine, "")

	req := httptest.NewRequest(http.MethodPost, "/api/notification-rules/555/test", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed decoding test rule response: %v", err)
	}
	if resp["status"] != "test alert dispatched successfully" {
		t.Errorf("unexpected status message: %s", resp["status"])
	}

	select {
	case body := <-receivedChan:
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("failed to unmarshal test anomaly: %v", err)
		}
		if payload["text"] == nil {
			t.Error("expected text property to be present in Slack format payload")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for test rule webhook dispatch")
	}
}

func shutdownNotificationTestWebhookEngine(t *testing.T, engine *webhook.WebhookEngine) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := engine.Shutdown(ctx); err != nil {
		t.Fatalf("failed to shut down webhook engine: %v", err)
	}
}
