package sqlite

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestRepository_UniFiEvents(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sqlite_unifi_events_test")
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
	now := time.Now().UTC().Truncate(time.Second)

	e := &UniFiEvent{
		Timestamp:     now,
		SourceGateway: "192.168.1.1",
		Category:      "Security Detections",
		Severity:      "high",
		ClientIP:      "192.168.1.20",
		Summary:       "IDS Alert",
		Attributes:    map[string]string{"signature_id": "2018402"},
	}

	// 1. Save event
	if err := repo.SaveUniFiEvent(ctx, e); err != nil {
		t.Fatalf("failed to save UniFi event: %v", err)
	}
	if e.ID == 0 {
		t.Error("expected populated auto-increment ID, got 0")
	}

	// 2. List events
	list, err := repo.ListUniFiEvents(ctx, 10)
	if err != nil {
		t.Fatalf("failed to list UniFi events: %v", err)
	}
	if len(list) != 1 || list[0].ClientIP != "192.168.1.20" || list[0].Attributes["signature_id"] != "2018402" {
		t.Errorf("unexpected list output: %+v", list)
	}

	// 3. Get events by IP
	ipList, err := repo.GetUniFiEventsForIP(ctx, "192.168.1.20", 10)
	if err != nil {
		t.Fatalf("failed to get events for IP: %v", err)
	}
	if len(ipList) != 1 || ipList[0].ID != e.ID {
		t.Errorf("unexpected IP list output: %+v", ipList)
	}

	// 4. Test retention pruning
	// Save a very old event
	oldEvent := &UniFiEvent{
		Timestamp:     now.AddDate(0, 0, -10),
		SourceGateway: "192.168.1.1",
		Category:      "Clients",
		Severity:      "low",
		ClientIP:      "192.168.1.30",
		Summary:       "Client connected",
		Attributes:    map[string]string{},
	}
	if err := repo.SaveUniFiEvent(ctx, oldEvent); err != nil {
		t.Fatalf("failed to save old event: %v", err)
	}

	if err := repo.CleanupRetention(7); err != nil {
		t.Fatalf("failed retention cleanup: %v", err)
	}

	// Old event should be pruned, current event should remain
	allEvents, err := repo.ListUniFiEvents(ctx, 10)
	if err != nil {
		t.Fatalf("failed to list events after pruning: %v", err)
	}
	if len(allEvents) != 1 || allEvents[0].ID != e.ID {
		t.Errorf("expected only current event to remain after pruning, got %d events", len(allEvents))
	}

	// 5. Test seed reset
	if err := repo.ResetDevelopmentSeed(ctx); err != nil {
		t.Fatalf("failed to reset seed: %v", err)
	}
	allEvents, err = repo.ListUniFiEvents(ctx, 10)
	if err != nil {
		t.Fatalf("failed to list events after seed reset: %v", err)
	}
	if len(allEvents) != 0 {
		t.Errorf("expected 0 events after seed reset, got %d", len(allEvents))
	}
}
