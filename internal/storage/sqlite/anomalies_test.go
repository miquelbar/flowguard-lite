package sqlite

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestRepository_Anomalies(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_anomalies_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repo: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	// Save parent device first to satisfy foreign key constraint
	err = repo.UpsertDevice(ctx, "192.168.1.100", "", now)
	if err != nil {
		t.Fatalf("failed setup: %v", err)
	}

	anom := &Anomaly{
		IP:          "192.168.1.100",
		Type:        "TRAFFIC_SPIKE",
		Description: "Abnormal volume spike",
		Severity:    "high",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// 1. Save Anomaly
	err = repo.SaveAnomaly(ctx, anom)
	if err != nil {
		t.Fatalf("failed to save anomaly: %v", err)
	}
	if anom.ID == 0 {
		t.Error("expected populated auto-increment anomaly ID, got 0")
	}

	// 2. List anomalies
	list, err := repo.ListAnomalies(ctx, 10)
	if err != nil {
		t.Fatalf("failed listing anomalies: %v", err)
	}
	if len(list) != 1 || list[0].IP != "192.168.1.100" || list[0].Status != "active" {
		t.Errorf("unexpected anomalies list output: %v", list)
	}

	// 3. Update status
	err = repo.UpdateAnomalyStatus(ctx, anom.ID, "acknowledged")
	if err != nil {
		t.Fatalf("failed to update anomaly status: %v", err)
	}

	// 4. Verify update
	list, _ = repo.ListAnomalies(ctx, 10)
	if len(list) != 1 || list[0].Status != "acknowledged" {
		t.Errorf("expected status 'acknowledged', got '%s'", list[0].Status)
	}

	// 5. Save another active anomaly and verify GetActiveAnomalies
	anom2 := &Anomaly{
		IP:          "192.168.1.100",
		Type:        "NEW_PORT",
		Description: "New port query",
		Severity:    "low",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	_ = repo.SaveAnomaly(ctx, anom2)

	activeList, err := repo.GetActiveAnomalies(ctx, now.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("failed query active anomalies: %v", err)
	}
	if len(activeList) != 1 || activeList[0].Type != "NEW_PORT" {
		t.Errorf("expected 1 active anomaly (NEW_PORT), got: %v", activeList)
	}
	// 6. Test anomaly callbacks and audit logging
	var callbackTriggered int32
	repo.RegisterAnomalyCallback(func(a *Anomaly) {
		atomic.AddInt32(&callbackTriggered, 1)
	})

	anom3 := &Anomaly{
		IP:          "192.168.1.50",
		Type:        "NEW_DESTINATION",
		Description: "New peer query",
		Severity:    "low",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	_ = repo.SaveAnomaly(ctx, anom3)

	time.Sleep(50 * time.Millisecond) // Allow background goroutine to execute
	if atomic.LoadInt32(&callbackTriggered) != 1 {
		t.Error("expected anomaly save callback to trigger")
	}

	err = repo.SaveAuditLog(ctx, "update_label", "set ip 192.168.1.50 to Laptop")
	if err != nil {
		t.Fatalf("failed saving audit log: %v", err)
	}

	logs, err := repo.ListAuditLogs(ctx, 10)
	if err != nil {
		t.Fatalf("failed querying audit logs: %v", err)
	}
	if len(logs) != 1 || logs[0].Action != "update_label" {
		t.Errorf("unexpected audit logs list: %v", logs)
	}
}

func TestSQLiteSaveAnomalyFailsClosedWhenPolicyEvaluationFails(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flowguard-sqlite-anomaly-policy-fail-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to initialize SQLite repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	policy := &Policy{
		Name:       "Corrupt policy candidate",
		Scope:      PolicyScopeAlertType,
		Target:     "BEACONING",
		Suppressed: true,
	}
	if err := repo.SavePolicy(ctx, policy); err != nil {
		t.Fatalf("failed saving policy: %v", err)
	}
	if _, err := repo.metaDB.ExecContext(ctx, "UPDATE policies SET notification_channels = ? WHERE id = ?", "not-json", policy.ID); err != nil {
		t.Fatalf("failed corrupting policy channels: %v", err)
	}

	var callbackCount int32
	repo.RegisterAnomalyCallback(func(a *Anomaly) {
		atomic.AddInt32(&callbackCount, 1)
	})

	anomaly := &Anomaly{
		IP:          "192.168.1.50",
		Type:        "BEACONING",
		Description: "policy evaluation should fail before insert",
		Severity:    SeverityHigh,
		Status:      AnomalyStatusActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if err := repo.SaveAnomaly(ctx, anomaly); err == nil {
		t.Fatal("expected SaveAnomaly to fail when policy evaluation fails")
	}

	anomalies, err := repo.ListAnomalies(ctx, 10)
	if err != nil {
		t.Fatalf("failed listing anomalies: %v", err)
	}
	if len(anomalies) != 0 {
		t.Fatalf("expected no anomaly to be persisted after policy evaluation failure, got %+v", anomalies)
	}
	if got := atomic.LoadInt32(&callbackCount); got != 0 {
		t.Fatalf("expected no anomaly callback after failed save, got %d", got)
	}
}
