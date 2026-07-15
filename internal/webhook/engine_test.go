package webhook

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

	"github.com/miquelbar/flowguard-lite/internal/storage"
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
			// "telegram" format is deprecated — it now falls back to generic JSON.
			// Telegram alerts are dispatched via the native Bot API path (token+chatID), not via webhook format.
			format: "telegram",
			validateFunc: func(t *testing.T, body []byte) {
				var anomaly storage.Anomaly
				if err := json.Unmarshal(body, &anomaly); err != nil {
					t.Fatalf("expected deprecated telegram format to fall back to generic anomaly JSON, unmarshal failed: %v", err)
				}
				if anomaly.IP != "192.168.1.10" || anomaly.Type != "TRAFFIC_SPIKE" {
					t.Errorf("unexpected generic fallback anomaly fields: %+v", anomaly)
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
			slackURL := ""
			webhookURL := server.URL
			if tt.format == "slack" {
				slackURL = server.URL
				webhookURL = ""
			}
			engine := NewWebhookEngine(nil, slackURL, webhookURL, tt.format, nil, false, "", "", logger)
			defer shutdownWebhookEngine(t, engine)

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
	repo := &MockRepository{
		devices: map[string]storage.Device{
			"192.168.1.50": {IP: "192.168.1.50", Label: "Living Room Apple TV", Hostname: "apple-tv.local"},
		},
	}
	engine := NewWebhookEngine(repo, "", "", "generic", nil, true, "token123", "chat456", logger)
	defer shutdownWebhookEngine(t, engine)
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
		if _, ok := payload["parse_mode"]; ok {
			t.Fatalf("expected Telegram payload to be plain text without parse_mode, got: %v", payload)
		}
		text, ok := payload["text"].(string)
		if !ok || !strings.Contains(text, "Living Room Apple TV (192.168.1.50)") {
			t.Fatalf("expected Telegram text to include device identity, got: %v", payload["text"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for Telegram dispatch")
	}
}

func TestWebhookEngine_UpdateConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := NewWebhookEngine(nil, "http://old-slack", "http://old-url", "generic", map[string]string{"X-Auth": "old"}, false, "old-token", "old-chat", logger)
	defer shutdownWebhookEngine(t, engine)

	engine.UpdateConfig("http://new-slack", "http://new-url", "slack", map[string]string{"X-Auth": "new"}, true, "new-token", "new-chat")

	engine.mu.RLock()
	defer engine.mu.RUnlock()

	if engine.slackURL != "http://new-slack" || engine.webhookURL != "http://new-url" || engine.format != "slack" || engine.webhookHeaders["X-Auth"] != "new" || !engine.tgEnabled || engine.tgToken != "new-token" || engine.tgChatID != "new-chat" {
		t.Errorf("UpdateConfig failed, got: slackURL=%s webhookURL=%s format=%s enabled=%v token=%s chat=%s headers=%v",
			engine.slackURL, engine.webhookURL, engine.format, engine.tgEnabled, engine.tgToken, engine.tgChatID, engine.webhookHeaders)
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
	engine := NewWebhookEngine(nil, "", server.URL, "generic", customHeaders, false, "", "", logger)
	defer shutdownWebhookEngine(t, engine)

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

func TestWebhookEngine_DispatchQueueDropsWhenSaturated(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo := &MockRepository{}
	engine := NewWebhookEngine(repo, "", "http://example.test", "generic", nil, false, "", "", logger)

	block := make(chan struct{})
	started := make(chan struct{}, webhookDispatchWorkers+webhookDispatchQueueSize)
	engine.client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		started <- struct{}{}
		<-block
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       http.NoBody,
		}, nil
	})

	for i := 0; i < webhookDispatchWorkers; i++ {
		if !engine.enqueueDispatch(context.Background(), int64(i+1), nil, "webhook", "http://example.test", []byte(`{}`), nil) {
			t.Fatalf("expected worker dispatch %d to be accepted", i+1)
		}
	}
	for i := 0; i < webhookDispatchWorkers; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for dispatch workers to block")
		}
	}
	for i := 0; i < webhookDispatchQueueSize; i++ {
		if !engine.enqueueDispatch(context.Background(), int64(webhookDispatchWorkers+i+1), nil, "webhook", "http://example.test", []byte(`{}`), nil) {
			t.Fatalf("expected queued dispatch %d to be accepted", i+1)
		}
	}
	if engine.enqueueDispatch(context.Background(), 999, nil, "webhook", "http://example.test", []byte(`{}`), nil) {
		t.Fatal("expected saturated dispatch queue to reject the next dispatch")
	}

	repo.mu.Lock()
	logs := append([]storage.NotificationLog(nil), repo.logs...)
	repo.mu.Unlock()
	if len(logs) != 1 {
		t.Fatalf("expected 1 failed notification log for dropped dispatch, got %d", len(logs))
	}
	if logs[0].Status != "failed" || logs[0].ErrorMessage != "webhook dispatch queue is full" {
		t.Fatalf("unexpected dropped dispatch log: %+v", logs[0])
	}

	close(block)
	shutdownWebhookEngine(t, engine)
}

func TestWebhookEngine_ShutdownWaitsForQueuedDispatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := NewWebhookEngine(nil, "", "http://example.test", "generic", nil, false, "", "", logger)

	finished := make(chan struct{})
	engine.client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		time.Sleep(25 * time.Millisecond)
		close(finished)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       http.NoBody,
		}, nil
	})

	if !engine.enqueueDispatch(context.Background(), 1, nil, "webhook", "http://example.test", []byte(`{}`), nil) {
		t.Fatal("expected dispatch to be queued")
	}

	shutdownWebhookEngine(t, engine)

	select {
	case <-finished:
	default:
		t.Fatal("shutdown returned before queued dispatch finished")
	}
}

func shutdownWebhookEngine(t *testing.T, engine *WebhookEngine) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := engine.Shutdown(ctx); err != nil {
		t.Fatalf("failed to shut down webhook engine: %v", err)
	}
}
