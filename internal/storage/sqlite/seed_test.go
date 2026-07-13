package sqlite

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/config"
	storagepkg "github.com/miquelbar/flowguard-lite/internal/storage"
)

func TestSeedMockData_IsIdempotentForSQLite(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_seed_idempotent")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}
	defer repo.Close()

	cfg := config.DefaultConfig()
	cfg.StorageDir = tmpDir
	cfg.Environment = "development"
	configPath := filepath.Join(tmpDir, "config.yaml")

	if err := storagepkg.SeedMockData(repo, logger, cfg, configPath); err != nil {
		t.Fatalf("failed first seed: %v", err)
	}
	first := collectSeedSnapshot(t, repo)

	if err := storagepkg.SeedMockData(repo, logger, cfg, configPath); err != nil {
		t.Fatalf("failed second seed: %v", err)
	}
	second := collectSeedSnapshot(t, repo)

	if first != second {
		t.Fatalf("expected repeated seed to keep stable counts, first=%+v second=%+v", first, second)
	}
	if second.devices != 12 || second.policies != 3 || second.anomalies != 8 || second.activeAnomalies != 6 || second.auditLogs != 13 || second.notificationLogs != 6 {
		t.Fatalf("unexpected seed counts: %+v", second)
	}
	if !cfg.FirstRunCompleted {
		t.Fatal("expected seed to mark first-run setup completed")
	}
}

func TestSeedMockData_ConfigSaveFailureReportsBoundedPartialSeed(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_seed_config_failure")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}
	defer repo.Close()

	cfg := config.DefaultConfig()
	cfg.StorageDir = tmpDir
	cfg.Environment = "development"
	cfg.RetentionDays = 0
	configPath := filepath.Join(tmpDir, "config.yaml")

	err = storagepkg.SeedMockData(repo, logger, cfg, configPath)
	if err == nil {
		t.Fatal("expected seed to report config save failure")
	}
	if !strings.Contains(err.Error(), "populated repository but failed to persist setup bypass config") {
		t.Fatalf("expected bounded partial-seed error, got %v", err)
	}

	snapshot := collectSeedSnapshot(t, repo)
	if snapshot.devices != 12 || snapshot.policies != 3 || snapshot.anomalies != 8 || snapshot.notificationLogs != 6 {
		t.Fatalf("expected repository seed to remain populated after config failure, got %+v", snapshot)
	}
	if !cfg.FirstRunCompleted {
		t.Fatal("expected in-memory config to be marked completed before failed persistence")
	}
	if _, statErr := os.Stat(configPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected invalid config not to be written, statErr=%v", statErr)
	}
}

func TestSQLiteResetDevelopmentSeedRollsBackMetadataWhenDeleteFails(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flowguard-seed-reset-acid-test")
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
	rule := &NotificationRule{
		Name:            "Seed reset rollback notification",
		Enabled:         true,
		SeverityMin:     SeverityHigh,
		Scope:           NotificationScopeGlobal,
		CooldownSeconds: 60,
		ChannelTargets:  []string{NotificationChannelSlack},
	}
	if err := repo.SaveNotificationRule(ctx, rule); err != nil {
		t.Fatalf("failed saving notification rule: %v", err)
	}

	policy := &Policy{
		Name:       "Seed reset blocker",
		Scope:      PolicyScopeAlertType,
		Target:     "BEACONING",
		Suppressed: true,
	}
	if err := repo.SavePolicy(ctx, policy); err != nil {
		t.Fatalf("failed saving policy: %v", err)
	}

	if _, err := repo.metaDB.ExecContext(ctx, `
		CREATE TRIGGER block_seed_policy_delete
		BEFORE DELETE ON policies
		BEGIN
			SELECT RAISE(ABORT, 'seed policy delete blocked');
		END;
	`); err != nil {
		t.Fatalf("failed creating policy delete trigger: %v", err)
	}

	if err := repo.ResetDevelopmentSeed(ctx); err == nil {
		t.Fatal("expected ResetDevelopmentSeed to fail when metadata delete is blocked")
	}

	rules, err := repo.ListNotificationRules(ctx)
	if err != nil {
		t.Fatalf("failed listing notification rules after failed reset: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != rule.ID {
		t.Fatalf("expected notification rules delete to roll back, got %+v", rules)
	}
	if _, err := repo.GetPolicy(ctx, policy.ID); err != nil {
		t.Fatalf("expected policy to remain after failed reset: %v", err)
	}
}

type seedSnapshot struct {
	devices          int
	policies         int
	anomalies        int
	activeAnomalies  int
	auditLogs        int
	notificationLogs int
	topSources       int
}

func collectSeedSnapshot(t *testing.T, repo *Repository) seedSnapshot {
	t.Helper()

	ctx := context.Background()
	devices, err := repo.ListDevices(ctx)
	if err != nil {
		t.Fatalf("failed listing devices: %v", err)
	}
	policies, err := repo.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("failed listing policies: %v", err)
	}
	anomalies, err := repo.ListAnomalies(ctx, 100)
	if err != nil {
		t.Fatalf("failed listing anomalies: %v", err)
	}
	active, err := repo.GetActiveAnomalies(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("failed listing active anomalies: %v", err)
	}
	auditLogs, err := repo.ListAuditLogs(ctx, 100)
	if err != nil {
		t.Fatalf("failed listing audit logs: %v", err)
	}
	notificationLogs, err := repo.ListNotificationLogs(ctx, 100)
	if err != nil {
		t.Fatalf("failed listing notification logs: %v", err)
	}
	topSources, err := repo.GetTopSources(ctx, time.Now().Add(-24*time.Hour), time.Now().Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("failed listing seeded top sources: %v", err)
	}

	return seedSnapshot{
		devices:          len(devices),
		policies:         len(policies),
		anomalies:        len(anomalies),
		activeAnomalies:  len(active),
		auditLogs:        len(auditLogs),
		notificationLogs: len(notificationLogs),
		topSources:       len(topSources),
	}
}
