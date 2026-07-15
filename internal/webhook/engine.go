package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/netclient"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

// WebhookEngine handles asynchronous dispatching of security anomaly alerts to external channels.
type WebhookEngine struct {
	mu             sync.RWMutex
	repo           storage.StorageRepository
	slackURL       string
	webhookURL     string
	format         string // "generic", "slack", "telegram"
	webhookHeaders map[string]string
	tgEnabled      bool
	tgToken        string
	tgChatID       string
	client         *http.Client
	logger         *slog.Logger

	dispatchQueue chan webhookDispatchRequest
	dispatchWG    sync.WaitGroup
	queueMu       sync.Mutex
	queueClosed   bool
}

// NewWebhookEngine creates and configures a WebhookEngine instance.
func NewWebhookEngine(repo storage.StorageRepository, slackURL string, webhookURL string, format string, headers map[string]string, tgEnabled bool, tgToken string, tgChatID string, logger *slog.Logger) *WebhookEngine {
	if format == "" {
		format = "generic"
	}
	engine := &WebhookEngine{
		repo:           repo,
		slackURL:       slackURL,
		webhookURL:     webhookURL,
		format:         format,
		webhookHeaders: cloneHeaders(headers),
		tgEnabled:      tgEnabled,
		tgToken:        tgToken,
		tgChatID:       tgChatID,
		client:         netclient.NewHTTPClient(10 * time.Second),
		logger:         logger,
		dispatchQueue:  make(chan webhookDispatchRequest, webhookDispatchQueueSize),
	}
	for i := 0; i < webhookDispatchWorkers; i++ {
		engine.dispatchWG.Add(1)
		go engine.dispatchWorker()
	}
	return engine
}

// UpdateConfig dynamically updates the notification endpoints at runtime thread-safely.
func (w *WebhookEngine) UpdateConfig(slackURL string, webhookURL string, format string, headers map[string]string, tgEnabled bool, tgToken string, tgChatID string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.slackURL = slackURL
	w.webhookURL = webhookURL
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
		slog.Bool("slack_configured", slackURL != ""),
		slog.Bool("webhook_configured", webhookURL != ""),
		slog.String("webhook_format", format),
		slog.Int("webhook_headers_count", len(headers)),
		slog.Bool("telegram_enabled", tgEnabled))
}

// SendAnomalyAlert formats and dispatches a JSON payload asynchronously to all active alert channels.
func (w *WebhookEngine) SendAnomalyAlert(ctx context.Context, anomaly *storage.Anomaly) {
	if anomaly.Status == "silenced" {
		w.logger.Debug("Anomaly is silenced by policy, skipping webhook alert dispatch", slog.Int64("id", anomaly.ID))
		if w.repo != nil {
			_ = w.repo.SaveNotificationLog(ctx, &storage.NotificationLog{
				AnomalyID:    anomaly.ID,
				Channel:      "all",
				Status:       "suppressed",
				ErrorMessage: "Silenced by policy override",
				DispatchedAt: time.Now(),
			})
		}
		return
	}

	w.mu.RLock()
	slackURL := w.slackURL
	webhookURL := w.webhookURL
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

	severityScore := func(sev string) int {
		switch strings.ToLower(sev) {
		case "high":
			return 3
		case "medium":
			return 2
		case "low":
			return 1
		default:
			return 0
		}
	}

	// Fetch rules if repo is available
	var rules []storage.NotificationRule
	var err error
	if w.repo != nil {
		rules, err = w.repo.ListNotificationRules(ctx)
		if err != nil {
			w.logger.Error("Failed to list notification rules, falling back to default channels", slog.String("error", err.Error()))
		}
	}

	var activeRules []storage.NotificationRule
	for _, r := range rules {
		if r.Enabled {
			activeRules = append(activeRules, r)
		}
	}

	// 1. Fallback mode: if no custom notification rules exist, use all configured global channels.
	if len(activeRules) == 0 {
		if slackURL != "" {
			bodyBytes, err := json.Marshal(map[string]interface{}{"text": messageText})
			if err != nil {
				w.logger.Error("Failed to marshal Slack payload", slog.String("error", err.Error()))
			} else {
				w.enqueueDispatch(context.Background(), anomaly.ID, nil, "slack", slackURL, bodyBytes, nil)
			}
		}

		if webhookURL != "" {
			bodyBytes, err := json.Marshal(anomaly)
			if err != nil {
				w.logger.Error("Failed to marshal webhook payload", slog.String("error", err.Error()))
			} else {
				w.enqueueDispatch(context.Background(), anomaly.ID, nil, "webhook", webhookURL, bodyBytes, headers)
			}
		}

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
				w.enqueueDispatch(context.Background(), anomaly.ID, nil, "telegram", tgURL, bodyBytes, nil)
			}
		}
		return
	}

	// 2. Rules evaluation mode: check each active notification rule
	for _, rule := range activeRules {
		// A. Check Severity Min Filter
		if severityScore(anomaly.Severity) < severityScore(rule.SeverityMin) {
			continue
		}

		// B. Check Alert Type Filter
		if len(rule.AlertTypes) > 0 {
			matchedType := false
			for _, t := range rule.AlertTypes {
				if strings.EqualFold(t, anomaly.Type) {
					matchedType = true
					break
				}
			}
			if !matchedType {
				continue
			}
		}

		// C. Check Scope / Target Filter
		if rule.Scope != "global" && rule.Target != "" {
			if rule.Scope == "ip" {
				if anomaly.IP != rule.Target {
					continue
				}
			} else if rule.Scope == "subnet" {
				_, ipNet, err := net.ParseCIDR(rule.Target)
				if err != nil {
					w.logger.Error("Invalid subnet target in notification rule", slog.Int64("rule_id", rule.ID), slog.String("target", rule.Target))
					continue
				}
				ipObj := net.ParseIP(anomaly.IP)
				if ipObj == nil || !ipNet.Contains(ipObj) {
					continue
				}
			}
		}

		// D. Cooldown Deduplication Check
		if rule.CooldownSeconds > 0 && w.repo != nil {
			since := time.Now().Add(-time.Duration(rule.CooldownSeconds) * time.Second)
			hasRecent, err := w.repo.HasRecentNotification(ctx, rule.ID, anomaly.IP, anomaly.Type, since)
			if err == nil && hasRecent {
				w.logger.Info("Notification alert deduplicated, skipping dispatch", slog.Int64("rule_id", rule.ID), slog.String("ip", anomaly.IP), slog.String("type", anomaly.Type))
				_ = w.repo.SaveNotificationLog(ctx, &storage.NotificationLog{
					AnomalyID:    anomaly.ID,
					RuleID:       &rule.ID,
					Channel:      "all",
					Status:       "deduplicated",
					ErrorMessage: "Suppressed by cooldown deduplication rule",
					DispatchedAt: time.Now(),
				})
				continue
			}
		}

		// E. Dispatch to specified channel targets
		ruleIDCopy := rule.ID
		for _, ch := range rule.ChannelTargets {
			switch ch {
			case "slack":
				if slackURL == "" {
					w.logger.Error("Slack routing matched but Slack webhook URL is not configured")
					if w.repo != nil {
						_ = w.repo.SaveNotificationLog(ctx, &storage.NotificationLog{
							AnomalyID:    anomaly.ID,
							RuleID:       &ruleIDCopy,
							Channel:      ch,
							Status:       "failed",
							ErrorMessage: "Slack webhook URL is not configured",
							DispatchedAt: time.Now(),
						})
					}
					continue
				}
				bodyBytes, err := json.Marshal(map[string]interface{}{"text": messageText})
				if err != nil {
					w.logger.Error("Failed to marshal Slack payload", slog.String("error", err.Error()))
				} else {
					w.enqueueDispatch(context.Background(), anomaly.ID, &ruleIDCopy, ch, slackURL, bodyBytes, nil)
				}

			case "webhook":
				if webhookURL == "" {
					w.logger.Error("Webhook routing matched but webhook URL is not configured")
					if w.repo != nil {
						_ = w.repo.SaveNotificationLog(ctx, &storage.NotificationLog{
							AnomalyID:    anomaly.ID,
							RuleID:       &ruleIDCopy,
							Channel:      ch,
							Status:       "failed",
							ErrorMessage: "Webhook destination URL is not configured",
							DispatchedAt: time.Now(),
						})
					}
					continue
				}
				bodyBytes, err := json.Marshal(anomaly)
				if err != nil {
					w.logger.Error("Failed to marshal webhook payload", slog.String("error", err.Error()))
				} else {
					w.enqueueDispatch(context.Background(), anomaly.ID, &ruleIDCopy, ch, webhookURL, bodyBytes, headers)
				}

			case "telegram":
				if !tgEnabled || tgToken == "" || tgChatID == "" {
					w.logger.Error("Telegram routing matched but Telegram is not enabled or credentials are missing")
					if w.repo != nil {
						_ = w.repo.SaveNotificationLog(ctx, &storage.NotificationLog{
							AnomalyID:    anomaly.ID,
							RuleID:       &ruleIDCopy,
							Channel:      ch,
							Status:       "failed",
							ErrorMessage: "Telegram credentials are not configured",
							DispatchedAt: time.Now(),
						})
					}
					continue
				}
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
					w.enqueueDispatch(context.Background(), anomaly.ID, &ruleIDCopy, ch, tgURL, bodyBytes, nil)
				}
			}
		}
	}
}

// SendTestAlert formats and dispatches a test alert directly to the specified rule's channel targets, bypassing cooldowns.
func (w *WebhookEngine) SendTestAlert(ctx context.Context, rule *storage.NotificationRule, anomaly *storage.Anomaly) {
	messageText := fmt.Sprintf("🚨 *FlowGuard Lite Test Alert*\n\n*Rule Name:* %s\n*IP Address:* %s\n*Type:* %s\n*Severity:* %s\n*Description:* %s\n*Time:* %s",
		rule.Name,
		anomaly.IP,
		anomaly.Type,
		anomaly.Severity,
		anomaly.Description,
		anomaly.CreatedAt.Format(time.RFC3339))

	w.mu.RLock()
	slackURL := w.slackURL
	webhookURL := w.webhookURL
	format := w.format
	headers := make(map[string]string)
	for k, v := range w.webhookHeaders {
		headers[k] = v
	}
	tgEnabled := w.tgEnabled
	tgToken := w.tgToken
	tgChatID := w.tgChatID
	w.mu.RUnlock()

	ruleIDCopy := rule.ID

	for _, ch := range rule.ChannelTargets {
		switch ch {
		case "slack":
			if slackURL == "" {
				w.logger.Error("Test alert routing matched but Slack webhook URL is not configured")
				if w.repo != nil {
					_ = w.repo.SaveNotificationLog(ctx, &storage.NotificationLog{
						AnomalyID:    anomaly.ID,
						RuleID:       &ruleIDCopy,
						Channel:      ch,
						Status:       "failed",
						ErrorMessage: "Slack webhook URL is not configured",
						DispatchedAt: time.Now(),
					})
				}
				continue
			}
			bodyBytes, err := json.Marshal(map[string]interface{}{"text": messageText})
			if err != nil {
				w.logger.Error("Failed to marshal Slack payload", slog.String("error", err.Error()))
			} else {
				w.enqueueDispatch(context.Background(), anomaly.ID, &ruleIDCopy, ch, slackURL, bodyBytes, nil)
			}

		case "webhook":
			if webhookURL == "" {
				w.logger.Error("Test alert routing matched but webhook URL is not configured")
				if w.repo != nil {
					_ = w.repo.SaveNotificationLog(ctx, &storage.NotificationLog{
						AnomalyID:    anomaly.ID,
						RuleID:       &ruleIDCopy,
						Channel:      ch,
						Status:       "failed",
						ErrorMessage: "Webhook destination URL is not configured",
						DispatchedAt: time.Now(),
					})
				}
				continue
			}
			var payload interface{} = anomaly
			if format == "telegram" {
				payload = map[string]interface{}{
					"text":       messageText,
					"parse_mode": "Markdown",
				}
			}
			bodyBytes, err := json.Marshal(payload)
			if err != nil {
				w.logger.Error("Failed to marshal webhook payload", slog.String("error", err.Error()))
			} else {
				w.enqueueDispatch(context.Background(), anomaly.ID, &ruleIDCopy, ch, webhookURL, bodyBytes, headers)
			}

		case "telegram":
			if !tgEnabled || tgToken == "" || tgChatID == "" {
				w.logger.Error("Test alert routing matched but Telegram credentials are not configured")
				if w.repo != nil {
					_ = w.repo.SaveNotificationLog(ctx, &storage.NotificationLog{
						AnomalyID:    anomaly.ID,
						RuleID:       &ruleIDCopy,
						Channel:      ch,
						Status:       "failed",
						ErrorMessage: "Telegram credentials are not configured",
						DispatchedAt: time.Now(),
					})
				}
				continue
			}
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
				w.enqueueDispatch(context.Background(), anomaly.ID, &ruleIDCopy, ch, tgURL, bodyBytes, nil)
			}
		}
	}
}

func cloneHeaders(headers map[string]string) map[string]string {
	cloned := make(map[string]string, len(headers))
	for k, v := range headers {
		cloned[k] = v
	}
	return cloned
}
