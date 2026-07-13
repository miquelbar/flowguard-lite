package duckdb

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestRepository_NotificationRulesAndLogs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flowguard-duckdb-test-notification-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to initialize repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()

	r1 := &NotificationRule{
		Name:            "Slack High Alerts",
		Enabled:         true,
		SeverityMin:     "high",
		AlertTypes:      []string{"port_scan", "ddos"},
		Scope:           "subnet",
		Target:          "192.168.1.0/24",
		CooldownSeconds: 120,
		ChannelTargets:  []string{"slack", "telegram"},
	}

	err = repo.SaveNotificationRule(ctx, r1)
	if err != nil {
		t.Fatalf("failed to save notification rule: %v", err)
	}
	if r1.ID == 0 {
		t.Error("expected generated rule ID, got 0")
	}

	retrieved, err := repo.GetNotificationRule(ctx, r1.ID)
	if err != nil {
		t.Fatalf("failed to get notification rule: %v", err)
	}
	if retrieved.Name != "Slack High Alerts" || len(retrieved.AlertTypes) != 2 || retrieved.CooldownSeconds != 120 {
		t.Errorf("retrieved rule mismatch: %+v", retrieved)
	}

	list, err := repo.ListNotificationRules(ctx)
	if err != nil {
		t.Fatalf("failed to list notification rules: %v", err)
	}
	if len(list) != 1 || list[0].ID != r1.ID {
		t.Errorf("list notification rules mismatch: %+v", list)
	}

	l1 := &NotificationLog{
		AnomalyID:    999,
		RuleID:       &r1.ID,
		Channel:      "slack",
		Status:       "sent",
		DispatchedAt: time.Now(),
	}

	err = repo.SaveNotificationLog(ctx, l1)
	if err != nil {
		t.Fatalf("failed to save notification log: %v", err)
	}

	logs, err := repo.ListNotificationLogs(ctx, 10)
	if err != nil {
		t.Fatalf("failed to list notification logs: %v", err)
	}
	if len(logs) != 1 || logs[0].AnomalyID != 999 || logs[0].Channel != "slack" || logs[0].Status != "sent" {
		t.Errorf("retrieved logs mismatch: %+v", logs)
	}

	a1 := &Anomaly{
		IP:          "192.168.1.5",
		Type:        "port_scan",
		Severity:    "high",
		Status:      "active",
		Description: "Port scanning activity",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	err = repo.SaveAnomaly(ctx, a1)
	if err != nil {
		t.Fatalf("failed to save anomaly: %v", err)
	}

	l2 := &NotificationLog{
		AnomalyID:    a1.ID,
		RuleID:       &r1.ID,
		Channel:      "slack",
		Status:       "sent",
		DispatchedAt: time.Now(),
	}
	err = repo.SaveNotificationLog(ctx, l2)
	if err != nil {
		t.Fatalf("failed to save log: %v", err)
	}

	hasRecent, err := repo.HasRecentNotification(ctx, r1.ID, "192.168.1.5", "port_scan", time.Now().Add(-10*time.Second))
	if err != nil {
		t.Fatalf("HasRecentNotification failed: %v", err)
	}
	if !hasRecent {
		t.Error("expected hasRecent to be true")
	}

	hasRecent, err = repo.HasRecentNotification(ctx, r1.ID, "192.168.1.5", "port_scan", time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatalf("HasRecentNotification failed: %v", err)
	}
	if hasRecent {
		t.Error("expected hasRecent to be false outside window")
	}

	err = repo.DeleteNotificationRule(ctx, r1.ID)
	if err != nil {
		t.Fatalf("failed to delete notification rule: %v", err)
	}

	_, err = repo.GetNotificationRule(ctx, r1.ID)
	if err == nil {
		t.Error("expected error getting deleted notification rule, got nil")
	}
}

func TestDuckDBSaveNotificationRuleRollsBackWhenAuditFails(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flowguard-duckdb-notification-rollback-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create DuckDB repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	if _, err := repo.db.ExecContext(ctx, "DROP TABLE audit_logs"); err != nil {
		t.Fatalf("failed removing audit_logs table: %v", err)
	}

	rule := &NotificationRule{
		Name:            "Rollback notification",
		Enabled:         true,
		SeverityMin:     SeverityHigh,
		Scope:           NotificationScopeGlobal,
		CooldownSeconds: 60,
		ChannelTargets:  []string{NotificationChannelSlack},
	}
	if err := repo.SaveNotificationRule(ctx, rule); err == nil {
		t.Fatal("expected SaveNotificationRule to fail when audit insert is blocked")
	}

	rules, err := repo.ListNotificationRules(ctx)
	if err != nil {
		t.Fatalf("failed listing notification rules after rollback: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected notification rule insert to roll back, got %+v", rules)
	}
}

func TestDuckDBDeleteNotificationRuleRollsBackWhenAuditFails(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flowguard-duckdb-notification-delete-rollback-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create DuckDB repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	rule := &NotificationRule{
		Name:            "Retained notification",
		Enabled:         true,
		SeverityMin:     SeverityHigh,
		Scope:           NotificationScopeGlobal,
		CooldownSeconds: 60,
		ChannelTargets:  []string{NotificationChannelSlack},
	}
	if err := repo.SaveNotificationRule(ctx, rule); err != nil {
		t.Fatalf("failed saving setup notification rule: %v", err)
	}
	if _, err := repo.db.ExecContext(ctx, "DROP TABLE audit_logs"); err != nil {
		t.Fatalf("failed removing audit_logs table: %v", err)
	}

	if err := repo.DeleteNotificationRule(ctx, rule.ID); err == nil {
		t.Fatal("expected DeleteNotificationRule to fail when audit insert is blocked")
	}

	got, err := repo.GetNotificationRule(ctx, rule.ID)
	if err != nil {
		t.Fatalf("expected notification rule delete to roll back with audit failure: %v", err)
	}
	if got.Name != rule.Name {
		t.Fatalf("unexpected retained notification rule after rollback: %+v", got)
	}
}
