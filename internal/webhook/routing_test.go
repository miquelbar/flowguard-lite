package webhook

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/storage"
)

// MockRepository implements StorageRepository for testing routing rules.
type MockRepository struct {
	storage.StorageRepository
	mu      sync.Mutex
	rules   []storage.NotificationRule
	logs    []storage.NotificationLog
	devices map[string]storage.Device
	ruleErr error
	logErr  error
}

func (m *MockRepository) GetDevice(ctx context.Context, ip string) (*storage.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	device, ok := m.devices[ip]
	if !ok {
		return nil, nil
	}
	return &device, nil
}

func (m *MockRepository) ListNotificationRules(ctx context.Context) ([]storage.NotificationRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ruleErr != nil {
		return nil, m.ruleErr
	}
	return m.rules, nil
}

func (m *MockRepository) SaveNotificationLog(ctx context.Context, l *storage.NotificationLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.logErr != nil {
		return m.logErr
	}
	l.ID = int64(len(m.logs) + 1)
	m.logs = append(m.logs, *l)
	return nil
}

func (m *MockRepository) ListNotificationLogs(ctx context.Context, limit int) ([]storage.NotificationLog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.logs, nil
}

func (m *MockRepository) HasRecentNotification(ctx context.Context, ruleID int64, ip string, anomalyType string, since time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range m.logs {
		if l.RuleID != nil && *l.RuleID == ruleID && l.Status == "sent" && l.DispatchedAt.After(since) {
			return true, nil
		}
	}
	return false, nil
}

func TestWebhookEngine_RoutingRules(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Mock receiver
	receivedChan := make(chan []byte, 10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		receivedChan <- bodyBytes
	}))
	defer server.Close()

	// 1. Test suppressed by policy
	t.Run("Suppressed by policy override", func(t *testing.T) {
		repo := &MockRepository{}
		engine := NewWebhookEngine(repo, "", server.URL, "generic", nil, false, "", "", logger)
		defer shutdownWebhookEngine(t, engine)

		anomaly := &storage.Anomaly{
			ID:       42,
			IP:       "192.168.1.10",
			Type:     "port_scan",
			Severity: "medium",
			Status:   "silenced", // Silenced by policy override
		}

		engine.SendAnomalyAlert(context.Background(), anomaly)

		// Wait slightly to ensure async runs
		time.Sleep(100 * time.Millisecond)

		repo.mu.Lock()
		defer repo.mu.Unlock()
		if len(repo.logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(repo.logs))
		}
		if repo.logs[0].Status != "suppressed" {
			t.Errorf("expected status 'suppressed', got %q", repo.logs[0].Status)
		}
	})

	// 2. Test fallback mode when no rules configured
	t.Run("Fallback mode (no rules)", func(t *testing.T) {
		repo := &MockRepository{}
		engine := NewWebhookEngine(repo, "", server.URL, "generic", nil, false, "", "", logger)
		defer shutdownWebhookEngine(t, engine)

		anomaly := &storage.Anomaly{
			ID:       43,
			IP:       "192.168.1.10",
			Type:     "port_scan",
			Severity: "medium",
			Status:   "active",
		}

		engine.SendAnomalyAlert(context.Background(), anomaly)

		// Verify HTTP received dispatch
		select {
		case body := <-receivedChan:
			var payload storage.Anomaly
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("failed to parse payload: %v", err)
			}
			if payload.ID != 43 {
				t.Errorf("expected ID 43, got %d", payload.ID)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("timeout waiting for fallback dispatch")
		}

		// Wait slightly for async logging
		time.Sleep(100 * time.Millisecond)

		repo.mu.Lock()
		defer repo.mu.Unlock()
		if len(repo.logs) != 1 {
			t.Fatalf("expected 1 log, got %d", len(repo.logs))
		}
		if repo.logs[0].Status != "sent" || repo.logs[0].Channel != "webhook" {
			t.Errorf("expected status 'sent' on 'webhook', got %q on %q", repo.logs[0].Status, repo.logs[0].Channel)
		}
	})

	// 3. Test rule matching
	t.Run("Rule severity and scope matching", func(t *testing.T) {
		ruleID1 := int64(101)
		ruleID2 := int64(102)

		repo := &MockRepository{
			rules: []storage.NotificationRule{
				{
					ID:             ruleID1,
					Name:           "Critical Slack Webhook",
					Enabled:        true,
					SeverityMin:    "high", // High severity minimum
					Scope:          "global",
					ChannelTargets: []string{"slack"},
				},
				{
					ID:             ruleID2,
					Name:           "Medium IP Specific",
					Enabled:        true,
					SeverityMin:    "medium",
					Scope:          "ip",
					Target:         "192.168.1.15", // Only matches 192.168.1.15
					ChannelTargets: []string{"webhook"},
				},
			},
		}

		engine := NewWebhookEngine(repo, server.URL, server.URL, "generic", nil, false, "", "", logger)
		defer shutdownWebhookEngine(t, engine)

		// This anomaly is high severity and 192.168.1.15, so it should match BOTH rules!
		anomaly := &storage.Anomaly{
			ID:       50,
			IP:       "192.168.1.15",
			Type:     "ddos",
			Severity: "high",
			Status:   "active",
		}

		engine.SendAnomalyAlert(context.Background(), anomaly)

		// Wait for both HTTP dispatches
		var count int
		for i := 0; i < 2; i++ {
			select {
			case <-receivedChan:
				count++
			case <-time.After(1 * time.Second):
			}
		}
		if count != 2 {
			t.Errorf("expected 2 HTTP dispatches, got %d", count)
		}

		time.Sleep(100 * time.Millisecond)

		repo.mu.Lock()
		defer repo.mu.Unlock()
		if len(repo.logs) != 2 {
			t.Fatalf("expected 2 logs, got %d", len(repo.logs))
		}
	})

	// 4. Test Cooldown Deduplication
	t.Run("Cooldown Deduplication", func(t *testing.T) {
		ruleID := int64(201)
		repo := &MockRepository{
			rules: []storage.NotificationRule{
				{
					ID:              ruleID,
					Name:            "Deduplicated Rule",
					Enabled:         true,
					SeverityMin:     "low",
					Scope:           "global",
					CooldownSeconds: 60,
					ChannelTargets:  []string{"webhook"},
				},
			},
			// Simulate a recent "sent" log inside cooldown window
			logs: []storage.NotificationLog{
				{
					AnomalyID:    99,
					RuleID:       &ruleID,
					Channel:      "webhook",
					Status:       "sent",
					DispatchedAt: time.Now().Add(-10 * time.Second),
				},
			},
		}

		engine := NewWebhookEngine(repo, "", server.URL, "generic", nil, false, "", "", logger)
		defer shutdownWebhookEngine(t, engine)

		anomaly := &storage.Anomaly{
			ID:       51,
			IP:       "192.168.1.15",
			Type:     "port_scan",
			Severity: "low",
			Status:   "active",
		}

		engine.SendAnomalyAlert(context.Background(), anomaly)

		// Verify NO HTTP request was received because it was deduplicated
		select {
		case <-receivedChan:
			t.Fatal("received dispatch unexpectedly during cooldown")
		case <-time.After(200 * time.Millisecond):
			// Success, no request dispatched
		}

		repo.mu.Lock()
		defer repo.mu.Unlock()
		// First log was the pre-existing one; second log should be the new "deduplicated" entry
		if len(repo.logs) != 2 {
			t.Fatalf("expected 2 logs, got %d", len(repo.logs))
		}
		if repo.logs[1].Status != "deduplicated" {
			t.Errorf("expected status 'deduplicated', got %q", repo.logs[1].Status)
		}
	})
}

func TestWebhookEngine_GlobalNoiseControlsSuppressNotification(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo := &MockRepository{}
	engine := NewWebhookEngine(repo, "", "http://example.test/hook", "generic", nil, false, "", "", logger)
	defer shutdownWebhookEngine(t, engine)
	engine.UpdateNoiseControls(NoiseControls{
		SuppressedTypes: []string{"BEACONING"},
	})

	engine.SendAnomalyAlert(context.Background(), &storage.Anomaly{
		ID:        77,
		IP:        "192.168.1.77",
		Type:      "BEACONING",
		Severity:  "medium",
		Status:    "active",
		CreatedAt: time.Now(),
	})

	time.Sleep(25 * time.Millisecond)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.logs) != 1 {
		t.Fatalf("expected one suppressed notification log, got %d", len(repo.logs))
	}
	if repo.logs[0].Status != "suppressed" || repo.logs[0].Channel != "all" {
		t.Fatalf("unexpected notification log: %+v", repo.logs[0])
	}
}

func TestWebhookEngine_GlobalAllowedSubnetsSuppressOutsideSource(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo := &MockRepository{}
	engine := NewWebhookEngine(repo, "", "http://example.test/hook", "generic", nil, false, "", "", logger)
	defer shutdownWebhookEngine(t, engine)
	engine.UpdateNoiseControls(NoiseControls{
		AllowedSubnets: []string{"192.168.10.0/24"},
	})

	engine.SendAnomalyAlert(context.Background(), &storage.Anomaly{
		ID:        78,
		IP:        "192.168.50.77",
		Type:      "TRAFFIC_SPIKE",
		Severity:  "high",
		Status:    "active",
		CreatedAt: time.Now(),
	})

	time.Sleep(25 * time.Millisecond)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.logs) != 1 {
		t.Fatalf("expected one suppressed notification log, got %d", len(repo.logs))
	}
	if repo.logs[0].Status != "suppressed" || !strings.Contains(repo.logs[0].ErrorMessage, "outside configured notification subnets") {
		t.Fatalf("unexpected notification log: %+v", repo.logs[0])
	}
}
