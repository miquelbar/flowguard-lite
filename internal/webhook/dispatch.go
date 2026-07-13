package webhook

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/storage"
)

const (
	webhookDispatchQueueSize = 16
	webhookDispatchWorkers   = 4
)

type webhookDispatchRequest struct {
	logCtx    context.Context
	anomalyID int64
	ruleID    *int64
	channel   string
	url       string
	body      []byte
	headers   map[string]string
}

// Shutdown stops accepting new async notification dispatches and waits for queued dispatches.
func (w *WebhookEngine) Shutdown(ctx context.Context) error {
	w.queueMu.Lock()
	if !w.queueClosed {
		close(w.dispatchQueue)
		w.queueClosed = true
	}
	w.queueMu.Unlock()

	done := make(chan struct{})
	go func() {
		w.dispatchWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *WebhookEngine) enqueueDispatch(ctx context.Context, anomalyID int64, ruleID *int64, channel string, url string, body []byte, headers map[string]string) bool {
	req := webhookDispatchRequest{
		logCtx:    ctx,
		anomalyID: anomalyID,
		ruleID:    ruleID,
		channel:   channel,
		url:       url,
		body:      append([]byte(nil), body...),
		headers:   cloneHeaders(headers),
	}

	w.queueMu.Lock()
	defer w.queueMu.Unlock()
	if w.queueClosed {
		w.recordDroppedDispatch(ctx, anomalyID, ruleID, channel, "webhook dispatch queue is closed")
		return false
	}

	select {
	case w.dispatchQueue <- req:
		return true
	default:
		w.recordDroppedDispatch(ctx, anomalyID, ruleID, channel, "webhook dispatch queue is full")
		return false
	}
}

func (w *WebhookEngine) recordDroppedDispatch(ctx context.Context, anomalyID int64, ruleID *int64, channel string, reason string) {
	w.logger.Warn("Dropped webhook dispatch", slog.Int64("anomaly_id", anomalyID), slog.String("channel", channel), slog.String("reason", reason))
	if w.repo != nil {
		_ = w.repo.SaveNotificationLog(ctx, &storage.NotificationLog{
			AnomalyID:    anomalyID,
			RuleID:       ruleID,
			Channel:      channel,
			Status:       "failed",
			ErrorMessage: reason,
			DispatchedAt: time.Now(),
		})
	}
}

func (w *WebhookEngine) dispatchWorker() {
	defer w.dispatchWG.Done()
	for req := range w.dispatchQueue {
		w.dispatchHTTP(req.logCtx, req.anomalyID, req.ruleID, req.channel, req.url, req.body, req.headers)
	}
}

func (w *WebhookEngine) dispatchHTTP(ctx context.Context, anomalyID int64, ruleID *int64, channel string, url string, body []byte, headers map[string]string) {
	reqCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		w.logger.Error("Failed to build HTTP request for "+channel, slog.String("error", err.Error()))
		if w.repo != nil {
			_ = w.repo.SaveNotificationLog(ctx, &storage.NotificationLog{
				AnomalyID:    anomalyID,
				RuleID:       ruleID,
				Channel:      channel,
				Status:       "failed",
				ErrorMessage: "Failed to build HTTP request: " + err.Error(),
				DispatchedAt: time.Now(),
			})
		}
		return
	}
	req.Header.Set("Content-Type", "application/json")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	w.logger.Debug("Dispatching alert...", slog.String("target", channel))
	resp, err := w.client.Do(req)
	if err != nil {
		w.logger.Error(channel+" HTTP dispatch failed", slog.String("error", err.Error()))
		if w.repo != nil {
			_ = w.repo.SaveNotificationLog(ctx, &storage.NotificationLog{
				AnomalyID:    anomalyID,
				RuleID:       ruleID,
				Channel:      channel,
				Status:       "failed",
				ErrorMessage: err.Error(),
				DispatchedAt: time.Now(),
			})
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errMsg := fmt.Sprintf("endpoint returned failure status code: %d", resp.StatusCode)
		w.logger.Error(channel + " " + errMsg)
		if w.repo != nil {
			_ = w.repo.SaveNotificationLog(ctx, &storage.NotificationLog{
				AnomalyID:    anomalyID,
				RuleID:       ruleID,
				Channel:      channel,
				Status:       "failed",
				ErrorMessage: errMsg,
				DispatchedAt: time.Now(),
			})
		}
		return
	}

	w.logger.Info(channel + " alert dispatched successfully")
	if w.repo != nil {
		_ = w.repo.SaveNotificationLog(ctx, &storage.NotificationLog{
			AnomalyID:    anomalyID,
			RuleID:       ruleID,
			Channel:      channel,
			Status:       "sent",
			DispatchedAt: time.Now(),
		})
	}
}
