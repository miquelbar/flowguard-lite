package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/netclient"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

const notificationDiagnosticTimeout = 10 * time.Second

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// TestChannelPayload represents parameters for testing a single notification channel.
type TestChannelPayload struct {
	Channel         string            `json:"channel"`
	SlackWebhookURL string            `json:"slack_webhook_url"`
	WebhookURL      string            `json:"webhook_url"`
	WebhookFormat   string            `json:"webhook_format"`
	WebhookHeaders  map[string]string `json:"webhook_headers"`
	TelegramToken   string            `json:"telegram_token"`
	TelegramChatID  string            `json:"telegram_chat_id"`
}

// TestChannelResponse represents the output of a diagnostic connection check.
type TestChannelResponse struct {
	Success    bool   `json:"success"`
	StatusCode int    `json:"status_code,omitempty"`
	Response   string `json:"response,omitempty"`
	Error      string `json:"error,omitempty"`
}

// NotificationChannelTester builds and sends bounded diagnostic notification requests.
type NotificationChannelTester struct {
	client httpDoer
}

func NewNotificationChannelTester(client httpDoer) *NotificationChannelTester {
	if client == nil {
		client = netclient.NewHTTPClient(notificationDiagnosticTimeout)
	}
	return &NotificationChannelTester{client: client}
}

func (t *NotificationChannelTester) Test(ctx context.Context, cfg *config.Config, payload TestChannelPayload) TestChannelResponse {
	ctx, cancel := context.WithTimeout(ctx, notificationDiagnosticTimeout)
	defer cancel()

	req, validation := t.buildRequest(ctx, cfg, payload)
	if validation != "" {
		return TestChannelResponse{Success: false, Error: validation}
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return TestChannelResponse{Success: false, Error: "Connection check failed: " + err.Error()}
	}
	defer resp.Body.Close()

	bodyTextBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return TestChannelResponse{
		Success:    resp.StatusCode >= 200 && resp.StatusCode < 300,
		StatusCode: resp.StatusCode,
		Response:   string(bodyTextBytes),
	}
}

func (t *NotificationChannelTester) buildRequest(ctx context.Context, cfg *config.Config, payload TestChannelPayload) (*http.Request, string) {
	targetURL, bodyBytes, headers, validation := diagnosticRequestParts(cfg, payload)
	if validation != "" {
		return nil, validation
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, "Failed to construct request: " + err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, ""
}

func diagnosticRequestParts(cfg *config.Config, payload TestChannelPayload) (string, []byte, map[string]string, string) {
	messageText, testAnomaly := diagnosticMessage()
	headers := make(map[string]string)

	switch payload.Channel {
	case "telegram":
		token := payload.TelegramToken
		if token == "******" || token == "" {
			token = cfg.TelegramToken
		}
		chatID := payload.TelegramChatID
		if chatID == "" {
			chatID = cfg.TelegramChatID
		}
		if token == "" || chatID == "" {
			return "", nil, nil, "Telegram Token and Chat ID must not be empty"
		}
		bodyBytes, err := json.Marshal(map[string]interface{}{
			"chat_id":    chatID,
			"text":       messageText,
			"parse_mode": "Markdown",
		})
		if err != nil {
			return "", nil, nil, "Failed to encode Telegram payload: " + err.Error()
		}
		return fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token), bodyBytes, headers, ""

	case "slack":
		url := strings.TrimSpace(payload.SlackWebhookURL)
		if url == "" {
			url = strings.TrimSpace(cfg.SlackWebhookURL)
		}
		if url == "" {
			return "", nil, nil, "Slack Webhook URL must not be empty"
		}
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return "", nil, nil, "Slack Webhook URL must be a valid HTTP or HTTPS address"
		}
		bodyBytes, err := json.Marshal(map[string]interface{}{"text": messageText})
		if err != nil {
			return "", nil, nil, "Failed to encode Slack payload: " + err.Error()
		}
		return url, bodyBytes, headers, ""

	case "webhook":
		url := strings.TrimSpace(payload.WebhookURL)
		if url == "" {
			return "", nil, nil, "Webhook URL must not be empty"
		}
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return "", nil, nil, "Webhook URL must be a valid HTTP or HTTPS address"
		}
		bodyBytes, err := json.Marshal(testAnomaly)
		if err != nil {
			return "", nil, nil, "Failed to encode Webhook payload: " + err.Error()
		}
		for k, v := range payload.WebhookHeaders {
			if v == "******" {
				headers[k] = cfg.WebhookHeaders[k]
			} else {
				headers[k] = v
			}
		}
		return url, bodyBytes, headers, ""
	}

	return "", nil, nil, "invalid channel value (must be 'telegram', 'slack', or 'webhook')"
}

func diagnosticMessage() (string, *storage.Anomaly) {
	now := time.Now()
	testAnomaly := &storage.Anomaly{
		IP:          "192.168.1.99",
		Type:        "test_alert",
		Description: "This is a FlowGuard Lite synchronous notification test alert. Your channel configuration is verified!",
		Severity:    "info",
		Status:      storage.AnomalyStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	messageText := fmt.Sprintf("FlowGuard Lite Test Alert\n\nIP Address: %s\nType: %s\nSeverity: %s\nDescription: %s\nTime: %s",
		testAnomaly.IP,
		testAnomaly.Type,
		testAnomaly.Severity,
		testAnomaly.Description,
		testAnomaly.CreatedAt.Format(time.RFC3339))
	return messageText, testAnomaly
}
