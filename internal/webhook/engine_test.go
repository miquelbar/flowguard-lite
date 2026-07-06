package webhook

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/flowguard/flowguard/internal/storage"
)

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestWebhookEngine_Dispatch(t *testing.T) {
	tests := []struct {
		format       string
		validateFunc func(t *testing.T, body []byte)
	}{
		{
			format: "slack",
			validateFunc: func(t *testing.T, body []byte) {
				var payload map[string]interface{}
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("failed to unmarshal Slack payload: %v", err)
				}
				text, ok := payload["text"].(string)
				if !ok || text == "" {
					t.Errorf("expected 'text' field in Slack payload, got: %v", payload)
				}
			},
		},
		{
			format: "telegram",
			validateFunc: func(t *testing.T, body []byte) {
				var payload map[string]interface{}
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("failed to unmarshal Telegram payload: %v", err)
				}
				text, ok := payload["text"].(string)
				if !ok || text == "" {
					t.Errorf("expected 'text' field in Telegram payload, got: %v", payload)
				}
				mode, ok := payload["parse_mode"].(string)
				if !ok || mode != "Markdown" {
					t.Errorf("expected 'parse_mode' equal to 'Markdown', got: %v", payload)
				}
			},
		},
		{
			format: "generic",
			validateFunc: func(t *testing.T, body []byte) {
				var anomaly storage.Anomaly
				if err := json.Unmarshal(body, &anomaly); err != nil {
					t.Fatalf("failed to unmarshal Generic anomaly payload: %v", err)
				}
				if anomaly.IP != "192.168.1.10" || anomaly.Type != "TRAFFIC_SPIKE" {
					t.Errorf("unexpected generic anomaly fields: %+v", anomaly)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			receivedChan := make(chan []byte, 1)

			// Start mock receiver
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				bodyBytes, err := io.ReadAll(r.Body)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusOK)
				receivedChan <- bodyBytes
			}))
			defer server.Close()

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			engine := NewWebhookEngine(nil, server.URL, tt.format, nil, false, "", "", logger)

			anomaly := &storage.Anomaly{
				IP:          "192.168.1.10",
				Type:        "TRAFFIC_SPIKE",
				Severity:    "high",
				Status:      "active",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
				Description: "Abnormal volume spike",
			}

			engine.SendAnomalyAlert(context.Background(), anomaly)

			// Wait for async background dispatch
			select {
			case body := <-receivedChan:
				tt.validateFunc(t, body)
			case <-time.After(1 * time.Second):
				t.Fatal("timeout waiting for webhook dispatch")
			}
		})
	}
}

func TestWebhookEngine_TelegramDirect(t *testing.T) {
	receivedChan := make(chan []byte, 1)

	// Mock receiver for direct Telegram sendMessage API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		receivedChan <- bodyBytes
	}))
	defer server.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := NewWebhookEngine(nil, "", "generic", nil, true, "token123", "chat456", logger)
	engine.client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		expectedURL := "https://api.telegram.org/bottoken123/sendMessage"
		if req.URL.String() != expectedURL {
			t.Errorf("expected URL %q, got %q", expectedURL, req.URL.String())
		}
		localReq, err := http.NewRequest(req.Method, server.URL, req.Body)
		if err != nil {
			return nil, err
		}
		return http.DefaultClient.Do(localReq)
	})

	anomaly := &storage.Anomaly{
		IP:          "192.168.1.50",
		Type:        "ddos",
		Severity:    "high",
		Status:      "active",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Description: "DDoS flood detected",
	}

	engine.SendAnomalyAlert(context.Background(), anomaly)

	select {
	case body := <-receivedChan:
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("failed to unmarshal Telegram payload: %v", err)
		}
		if payload["chat_id"] != "chat456" {
			t.Errorf("expected chat_id 'chat456', got: %v", payload["chat_id"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for Telegram dispatch")
	}
}

func TestWebhookEngine_UpdateConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := NewWebhookEngine(nil, "http://old-url", "generic", map[string]string{"X-Auth": "old"}, false, "old-token", "old-chat", logger)

	engine.UpdateConfig("http://new-url", "slack", map[string]string{"X-Auth": "new"}, true, "new-token", "new-chat")

	engine.mu.RLock()
	defer engine.mu.RUnlock()

	if engine.url != "http://new-url" || engine.format != "slack" || engine.webhookHeaders["X-Auth"] != "new" || !engine.tgEnabled || engine.tgToken != "new-token" || engine.tgChatID != "new-chat" {
		t.Errorf("UpdateConfig failed, got: url=%s format=%s enabled=%v token=%s chat=%s headers=%v",
			engine.url, engine.format, engine.tgEnabled, engine.tgToken, engine.tgChatID, engine.webhookHeaders)
	}
}

func TestWebhookEngine_Headers(t *testing.T) {
	headersChan := make(chan http.Header, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headersChan <- r.Header
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	customHeaders := map[string]string{
		"Authorization":   "Bearer token123",
		"X-Custom-Header": "custom-val",
	}
	engine := NewWebhookEngine(nil, server.URL, "generic", customHeaders, false, "", "", logger)

	anomaly := &storage.Anomaly{
		IP:        "192.168.1.1",
		Type:      "port_scan",
		Severity:  "low",
		Status:    "active",
		CreatedAt: time.Now(),
	}

	engine.SendAnomalyAlert(context.Background(), anomaly)

	select {
	case h := <-headersChan:
		if h.Get("Authorization") != "Bearer token123" {
			t.Errorf("expected Authorization header to be Bearer token123, got: %s", h.Get("Authorization"))
		}
		if h.Get("X-Custom-Header") != "custom-val" {
			t.Errorf("expected X-Custom-Header to be custom-val, got: %s", h.Get("X-Custom-Header"))
		}
		if h.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got: %s", h.Get("Content-Type"))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for webhook dispatch")
	}
}
