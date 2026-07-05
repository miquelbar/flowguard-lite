package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/flowguard/flowguard/internal/storage"
)

// WebhookEngine handles asynchronous dispatching of security anomaly alerts to external channels.
type WebhookEngine struct {
	mu             sync.RWMutex
	url            string
	format         string // "generic", "slack", "telegram"
	webhookHeaders map[string]string
	tgEnabled      bool
	tgToken        string
	tgChatID       string
	client         *http.Client
	logger         *slog.Logger
}

// NewWebhookEngine creates and configures a WebhookEngine instance.
func NewWebhookEngine(url string, format string, headers map[string]string, tgEnabled bool, tgToken string, tgChatID string, logger *slog.Logger) *WebhookEngine {
	if format == "" {
		format = "generic"
	}
	return &WebhookEngine{
		url:            url,
		format:         format,
		webhookHeaders: cloneHeaders(headers),
		tgEnabled:      tgEnabled,
		tgToken:        tgToken,
		tgChatID:       tgChatID,
		client:         &http.Client{Timeout: 5 * time.Second},
		logger:         logger,
	}
}

// UpdateConfig dynamically updates the notification endpoints at runtime thread-safely.
func (w *WebhookEngine) UpdateConfig(url string, format string, headers map[string]string, tgEnabled bool, tgToken string, tgChatID string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.url = url
	if format == "" {
		format = "generic"
	}
	w.format = format
	if headers == nil {
		headers = make(map[string]string)
	}
	w.webhookHeaders = cloneHeaders(headers)
	w.tgEnabled = tgEnabled
	w.tgToken = tgToken
	w.tgChatID = tgChatID

	w.logger.Info("Notification configurations dynamically updated",
		slog.Bool("webhook_configured", url != ""),
		slog.String("webhook_format", format),
		slog.Int("webhook_headers_count", len(headers)),
		slog.Bool("telegram_enabled", tgEnabled))
}

// SendAnomalyAlert formats and dispatches a JSON payload asynchronously to all active alert channels.
func (w *WebhookEngine) SendAnomalyAlert(ctx context.Context, anomaly *storage.Anomaly) {
	if anomaly.Status == "silenced" {
		w.logger.Debug("Anomaly is silenced by policy, skipping webhook alert dispatch", slog.Int64("id", anomaly.ID))
		return
	}

	w.mu.RLock()
	url := w.url
	format := w.format
	headers := make(map[string]string)
	for k, v := range w.webhookHeaders {
		headers[k] = v
	}
	tgEnabled := w.tgEnabled
	tgToken := w.tgToken
	tgChatID := w.tgChatID
	w.mu.RUnlock()

	messageText := fmt.Sprintf("🚨 *FlowGuard Lite Anomaly Alert*\n\n*IP Address:* %s\n*Type:* %s\n*Severity:* %s\n*Description:* %s\n*Time:* %s",
		anomaly.IP,
		anomaly.Type,
		anomaly.Severity,
		anomaly.Description,
		anomaly.CreatedAt.Format(time.RFC3339))

	// 1. Dispatch Webhook Alert if configured
	if url != "" {
		var payload interface{}
		switch format {
		case "slack":
			payload = map[string]interface{}{
				"text": messageText,
			}
		case "telegram":
			payload = map[string]interface{}{
				"text":       messageText,
				"parse_mode": "Markdown",
			}
		default: // "generic"
			payload = anomaly
		}

		bodyBytes, err := json.Marshal(payload)
		if err != nil {
			w.logger.Error("Failed to marshal webhook payload", slog.String("error", err.Error()))
		} else {
			go w.dispatchHTTP(url, bodyBytes, "webhook", headers)
		}
	}

	// 2. Dispatch Direct Telegram Alert if enabled
	if tgEnabled && tgToken != "" && tgChatID != "" {
		tgURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tgToken)
		payload := map[string]interface{}{
			"chat_id":    tgChatID,
			"text":       messageText,
			"parse_mode": "Markdown",
		}

		bodyBytes, err := json.Marshal(payload)
		if err != nil {
			w.logger.Error("Failed to marshal Telegram payload", slog.String("error", err.Error()))
		} else {
			go w.dispatchHTTP(tgURL, bodyBytes, "telegram", nil)
		}
	}
}

func (w *WebhookEngine) dispatchHTTP(url string, body []byte, label string, headers map[string]string) {
	reqCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		w.logger.Error("Failed to build HTTP request for "+label, slog.String("error", err.Error()))
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// Apply custom headers if present
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	w.logger.Debug("Dispatching alert...", slog.String("target", label))
	resp, err := w.client.Do(req)
	if err != nil {
		w.logger.Error(label+" HTTP dispatch failed", slog.String("error", err.Error()))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		w.logger.Error(label+" endpoint returned failure status code", slog.Int("status_code", resp.StatusCode))
		return
	}

	w.logger.Info(label + " alert dispatched successfully")
}

func cloneHeaders(headers map[string]string) map[string]string {
	cloned := make(map[string]string, len(headers))
	for k, v := range headers {
		cloned[k] = v
	}
	return cloned
}
