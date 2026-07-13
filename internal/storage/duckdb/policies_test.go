package duckdb

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestDuckDBPolicies(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flowguard-duckdb-policies-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	repo, err := NewRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to initialize DuckDB repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	now := time.Now()
	_ = repo.UpsertDevice(ctx, "192.168.1.15", "test-host", now)

	p1 := &Policy{
		Name:                 "Silence Port Scans",
		Scope:                "alert_type",
		Target:               "port_scan",
		SeverityThreshold:    "medium",
		Suppressed:           true,
		CooldownSeconds:      60,
		QuietHoursStart:      "22:00",
		QuietHoursEnd:        "06:00",
		NotificationChannels: []string{"slack", "telegram"},
	}

	err = repo.SavePolicy(ctx, p1)
	if err != nil {
		t.Fatalf("failed to save policy: %v", err)
	}
	if p1.ID == 0 {
		t.Error("expected generated policy ID, got 0")
	}

	list, err := repo.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to list policies: %v", err)
	}
	if len(list) != 1 || list[0].Name != "Silence Port Scans" {
		t.Errorf("unexpected list result: %v", list)
	}

	retrieved, err := repo.GetPolicy(ctx, p1.ID)
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if retrieved.CooldownSeconds != 60 || !retrieved.Suppressed || len(retrieved.NotificationChannels) != 2 {
		t.Errorf("retrieved policy properties mismatch: %v", retrieved)
	}

	invalidP := &Policy{
		Name:   "Invalid IP Target",
		Scope:  "ip",
		Target: "not-an-ip",
	}
	err = repo.SavePolicy(ctx, invalidP)
	if err == nil {
		t.Error("expected error validating policy with invalid target IP, got nil")
	}

	anomMatch1 := &Anomaly{
		IP:          "192.168.1.15",
		Type:        "port_scan",
		Description: "Port scan activity",
		Severity:    "high",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	err = repo.SaveAnomaly(ctx, anomMatch1)
	if err != nil {
		t.Fatalf("failed to save anomaly: %v", err)
	}
	if anomMatch1.Status != "silenced" {
		t.Errorf("expected anomaly status to be 'silenced' by policy, got '%s'", anomMatch1.Status)
	}

	p2 := &Policy{
		Name:              "Ignore Low/Medium Volumetric",
		Scope:             "alert_type",
		Target:            "volume_anomaly",
		SeverityThreshold: "high",
	}
	_ = repo.SavePolicy(ctx, p2)

	anomMatch2 := &Anomaly{
		IP:          "192.168.1.15",
		Type:        "volume_anomaly",
		Description: "Moderate traffic jump",
		Severity:    "medium",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	_ = repo.SaveAnomaly(ctx, anomMatch2)
	if anomMatch2.Status != "silenced" {
		t.Errorf("expected anomaly status to be 'silenced' by severity threshold, got '%s'", anomMatch2.Status)
	}

	p3 := &Policy{
		Name:            "DDoS Cooldown",
		Scope:           "alert_type",
		Target:          "ddos_source",
		CooldownSeconds: 300,
	}
	_ = repo.SavePolicy(ctx, p3)

	anomMatch3a := &Anomaly{
		IP:          "192.168.1.15",
		Type:        "ddos_source",
		Description: "DDoS source flood",
		Severity:    "high",
		Status:      "active",
		CreatedAt:   now.Add(-10 * time.Second),
		UpdatedAt:   now.Add(-10 * time.Second),
	}
	_ = repo.SaveAnomaly(ctx, anomMatch3a)
	if anomMatch3a.Status != "active" {
		t.Errorf("expected first ddos anomaly to be 'active', got '%s'", anomMatch3a.Status)
	}

	anomMatch3b := &Anomaly{
		IP:          "192.168.1.15",
		Type:        "ddos_source",
		Description: "DDoS source flood repeat",
		Severity:    "high",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	_ = repo.SaveAnomaly(ctx, anomMatch3b)
	if anomMatch3b.Status != "silenced" {
		t.Errorf("expected repeated ddos anomaly within cooldown to be 'silenced', got '%s'", anomMatch3b.Status)
	}

	pGlobalSilence := &Policy{
		Name:       "Silence Everything Globally",
		Scope:      "global",
		Suppressed: true,
	}
	_ = repo.SavePolicy(ctx, pGlobalSilence)

	pIPActive := &Policy{
		Name:       "Keep This IP Active",
		Scope:      "ip",
		Target:     "192.168.1.15",
		Suppressed: false,
	}
	_ = repo.SavePolicy(ctx, pIPActive)

	anomPrecedence := &Anomaly{
		IP:          "192.168.1.15",
		Type:        "unknown_alert_type",
		Description: "Some alert",
		Severity:    "high",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	_ = repo.SaveAnomaly(ctx, anomPrecedence)
	if anomPrecedence.Status != "active" {
		t.Errorf("expected IP precedence rule (active) to win over global rule (silenced), got status: '%s'", anomPrecedence.Status)
	}

	err = repo.DeletePolicy(ctx, p1.ID)
	if err != nil {
		t.Fatalf("failed to delete policy: %v", err)
	}
	_, err = repo.GetPolicy(ctx, p1.ID)
	if err == nil {
		t.Error("expected error fetching deleted policy, got nil")
	}
}

func TestDuckDBSavePolicyRollsBackWhenAuditFails(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flowguard-duckdb-policy-rollback-test")
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

	policy := &Policy{
		Name:       "Rollback candidate",
		Scope:      PolicyScopeAlertType,
		Target:     "BEACONING",
		Suppressed: true,
	}
	if err := repo.SavePolicy(ctx, policy); err == nil {
		t.Fatal("expected SavePolicy to fail when audit insert is blocked")
	}

	policies, err := repo.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("failed listing policies after rollback: %v", err)
	}
	if len(policies) != 0 {
		t.Fatalf("expected policy insert to roll back with audit failure, got %+v", policies)
	}
}

func TestDuckDBDeletePolicyRollsBackWhenAuditFails(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flowguard-duckdb-policy-delete-rollback-test")
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
	policy := &Policy{
		Name:       "Delete rollback candidate",
		Scope:      PolicyScopeAlertType,
		Target:     "BEACONING",
		Suppressed: true,
	}
	if err := repo.SavePolicy(ctx, policy); err != nil {
		t.Fatalf("failed saving setup policy: %v", err)
	}
	if _, err := repo.db.ExecContext(ctx, "DROP TABLE audit_logs"); err != nil {
		t.Fatalf("failed removing audit_logs table: %v", err)
	}

	if err := repo.DeletePolicy(ctx, policy.ID); err == nil {
		t.Fatal("expected DeletePolicy to fail when audit insert is blocked")
	}

	got, err := repo.GetPolicy(ctx, policy.ID)
	if err != nil {
		t.Fatalf("expected policy delete to roll back with audit failure: %v", err)
	}
	if got.Name != policy.Name {
		t.Fatalf("unexpected retained policy after rollback: %+v", got)
	}
}

func TestDuckDBSaveAnomalyFailsClosedWhenPolicyEvaluationFails(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flowguard-duckdb-anomaly-policy-fail-test")
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
	policy := &Policy{
		Name:       "Corrupt policy candidate",
		Scope:      PolicyScopeAlertType,
		Target:     "BEACONING",
		Suppressed: true,
	}
	if err := repo.SavePolicy(ctx, policy); err != nil {
		t.Fatalf("failed saving policy: %v", err)
	}
	if _, err := repo.db.ExecContext(ctx, "UPDATE policies SET notification_channels = ? WHERE id = ?", "not-json", policy.ID); err != nil {
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
