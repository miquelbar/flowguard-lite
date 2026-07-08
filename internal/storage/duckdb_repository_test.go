package storage

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flowguard/flowguard/internal/flow"
)

func TestDuckDBRepository_SaveAndQuery(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "duckdb_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewDuckDBRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create DuckDB repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	now := time.Now()

	// 1. Insert aggregates
	aggregates := []flow.FlowEvent{
		{SrcIP: "192.168.1.10", DstIP: "8.8.8.8", DstPort: 53, Protocol: 17, Bytes: 1024, Packets: 10},
		{SrcIP: "192.168.1.10", DstIP: "8.8.8.8", DstPort: 53, Protocol: 17, Bytes: 512, Packets: 5},
	}
	err = repo.SaveAggregates(ctx, now, aggregates)
	if err != nil {
		t.Fatalf("failed saving aggregates: %v", err)
	}
	if err := repo.UpsertDevice(ctx, "192.168.1.10", "workstation.local", now); err != nil {
		t.Fatalf("failed upserting device: %v", err)
	}

	// 2. Query top sources
	sources, err := repo.GetTopSources(ctx, now.Add(-1*time.Minute), now.Add(1*time.Minute), 5)
	if err != nil {
		t.Fatalf("failed querying top sources: %v", err)
	}
	if len(sources) != 1 || sources[0].Key != "192.168.1.10" || sources[0].Bytes != 1536 || sources[0].Packets != 15 {
		t.Errorf("unexpected top sources result: %v", sources)
	}

	// 3. Query top destinations
	dests, err := repo.GetTopDestinations(ctx, now.Add(-1*time.Minute), now.Add(1*time.Minute), 5)
	if err != nil {
		t.Fatalf("failed querying top destinations: %v", err)
	}
	if len(dests) != 1 || dests[0].Key != "8.8.8.8" {
		t.Errorf("unexpected top destinations result: %v", dests)
	}

	// 4. Query top protocols
	protocols, err := repo.GetTopProtocols(ctx, now.Add(-1*time.Minute), now.Add(1*time.Minute), 5)
	if err != nil {
		t.Fatalf("failed querying top protocols: %v", err)
	}
	if len(protocols) != 1 || protocols[0].Key != "17" || protocols[0].Bytes != 1536 || protocols[0].Packets != 15 {
		t.Errorf("unexpected top protocols result: %v", protocols)
	}

	// 5. Query traffic time-series with 5-minute buckets
	series, err := repo.GetTrafficTimeSeries(ctx, now.Add(-1*time.Minute), now.Add(1*time.Minute), 300)
	if err != nil {
		t.Fatalf("failed querying traffic time series: %v", err)
	}
	if len(series) != 1 || series[0].Bytes != 1536 || series[0].Packets != 15 || series[0].Flows != 2 {
		t.Errorf("unexpected traffic time series result: %+v", series)
	}

	// 6. Query top devices and heatmap, filtering to known devices.
	topDevices, err := repo.GetTopDevicesByVolume(ctx, now.Add(-1*time.Minute), now.Add(1*time.Minute), 5)
	if err != nil {
		t.Fatalf("failed querying top devices: %v", err)
	}
	if len(topDevices) != 1 || topDevices[0].Key != "192.168.1.10" || topDevices[0].Bytes != 1536 {
		t.Errorf("unexpected top devices result: %+v", topDevices)
	}

	heatmap, err := repo.GetDeviceActivityHeatmap(ctx, now.Add(-1*time.Minute), now.Add(1*time.Minute), 5)
	if err != nil {
		t.Fatalf("failed querying device heatmap: %v", err)
	}
	if len(heatmap) != 1 || heatmap[0].IP != "192.168.1.10" || heatmap[0].Bytes != 1536 {
		t.Errorf("unexpected device heatmap result: %+v", heatmap)
	}
}

func TestDuckDBRepository_DevicesAndAnomalies(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "duckdb_test_devs")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewDuckDBRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create DuckDB repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	now := time.Now()

	// 1. Upsert device
	err = repo.UpsertDevice(ctx, "192.168.1.50", "laptop.local", now)
	if err != nil {
		t.Fatalf("failed to upsert device: %v", err)
	}

	// 2. Update label
	err = repo.UpdateDeviceLabel(ctx, "192.168.1.50", "Work Laptop")
	if err != nil {
		t.Fatalf("failed to update label: %v", err)
	}

	// 3. List devices
	devs, err := repo.ListDevices(ctx)
	if err != nil {
		t.Fatalf("failed listing devices: %v", err)
	}
	if len(devs) != 1 || devs[0].Label != "Work Laptop" || devs[0].Hostname != "laptop.local" {
		t.Errorf("unexpected listed devices: %v", devs)
	}

	// 3b. Get device details
	deviceDetails, err := repo.GetDevice(ctx, "192.168.1.50")
	if err != nil {
		t.Fatalf("failed getting device: %v", err)
	}
	if deviceDetails == nil || deviceDetails.Label != "Work Laptop" {
		t.Errorf("unexpected device details: %v", deviceDetails)
	}

	// 4. Save and query baseline
	baseline := &DeviceBaseline{
		IP:        "192.168.1.50",
		MeanBytes: 2000,
		UpdatedAt: now,
	}
	err = repo.SaveBaseline(ctx, baseline)
	if err != nil {
		t.Fatalf("failed saving baseline: %v", err)
	}
	bFetched, err := repo.GetBaseline(ctx, "192.168.1.50")
	if err != nil {
		t.Fatalf("failed fetching baseline: %v", err)
	}
	if bFetched.MeanBytes != 2000 {
		t.Errorf("unexpected mean bytes in baseline: %v", bFetched)
	}

	// 5. Save anomaly and callbacks
	var callbackTriggered int32
	repo.RegisterAnomalyCallback(func(a *Anomaly) {
		atomic.AddInt32(&callbackTriggered, 1)
	})

	anom := &Anomaly{
		IP:          "192.168.1.50",
		Type:        "TRAFFIC_SPIKE",
		Description: "High bytes",
		Severity:    "high",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	err = repo.SaveAnomaly(ctx, anom)
	if err != nil {
		t.Fatalf("failed saving anomaly: %v", err)
	}

	time.Sleep(50 * time.Millisecond) // Allow callback to run
	if atomic.LoadInt32(&callbackTriggered) != 1 {
		t.Error("expected anomaly save callback to be triggered")
	}

	// 6. List and update anomaly
	anoms, err := repo.ListAnomalies(ctx, 10)
	if err != nil {
		t.Fatalf("failed querying anomalies: %v", err)
	}
	if len(anoms) != 1 || anoms[0].Type != "TRAFFIC_SPIKE" {
		t.Errorf("unexpected listed anomalies: %v", anoms)
	}

	err = repo.UpdateAnomalyStatus(ctx, anom.ID, "acknowledged")
	if err != nil {
		t.Fatalf("failed to update status: %v", err)
	}

	// 7. Audit logging
	err = repo.SaveAuditLog(ctx, "block_ip", "blocked 10.0.0.5")
	if err != nil {
		t.Fatalf("failed saving audit log: %v", err)
	}
	logs, err := repo.ListAuditLogs(ctx, 10)
	if err != nil {
		t.Fatalf("failed listing audit logs: %v", err)
	}
	if len(logs) != 1 || logs[0].Action != "block_ip" {
		t.Errorf("unexpected audit logs result: %v", logs)
	}
}

func TestDuckDBRepository_DeviceProfileQueries(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "duckdb_profile_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewDuckDBRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	now := time.Now().Truncate(time.Minute)

	// 1. Setup metadata
	err = repo.UpsertDevice(ctx, "192.168.1.100", "test-host", now)
	if err != nil {
		t.Fatalf("failed to upsert device: %v", err)
	}

	anom := &Anomaly{
		IP:          "192.168.1.100",
		Type:        "TRAFFIC_SPIKE",
		Description: "Anomaly 1",
		Severity:    "high",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	err = repo.SaveAnomaly(ctx, anom)
	if err != nil {
		t.Fatalf("failed to save anomaly: %v", err)
	}

	// 2. Setup flows
	flows := []flow.FlowEvent{
		{
			Timestamp: now,
			SrcIP:     "192.168.1.100",
			DstIP:     "8.8.8.8",
			DstPort:   53,
			Protocol:  17,
			Bytes:     1000,
			Packets:   10,
		},
		{
			Timestamp: now,
			SrcIP:     "1.1.1.1",
			DstIP:     "192.168.1.100",
			DstPort:   443,
			Protocol:  6,
			Bytes:     2000,
			Packets:   20,
		},
	}
	err = repo.SaveAggregates(ctx, now, flows)
	if err != nil {
		t.Fatalf("failed to save aggregates: %v", err)
	}

	start := now.Add(-1 * time.Hour)
	end := now.Add(1 * time.Hour)

	// Test GetAnomaliesForIP
	anoms, err := repo.GetAnomaliesForIP(ctx, "192.168.1.100", 10)
	if err != nil {
		t.Fatalf("failed to get anomalies for IP: %v", err)
	}
	if len(anoms) != 1 || anoms[0].Type != "TRAFFIC_SPIKE" {
		t.Errorf("expected 1 anomaly of type TRAFFIC_SPIKE, got %v", anoms)
	}

	// Test GetDeviceTrafficTimeSeries
	ts, err := repo.GetDeviceTrafficTimeSeries(ctx, "192.168.1.100", start, end, 60)
	if err != nil {
		t.Fatalf("failed to get device traffic time series: %v", err)
	}
	if len(ts) != 1 || ts[0].Bytes != 3000 {
		t.Errorf("expected 3000 bytes in time series, got %v", ts)
	}

	// Test GetDeviceTopPeers
	peers, err := repo.GetDeviceTopPeers(ctx, "192.168.1.100", start, end, 10)
	if err != nil {
		t.Fatalf("failed to get device top peers: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}
	if peers[0].Key != "1.1.1.1" || peers[0].Bytes != 2000 {
		t.Errorf("expected top peer to be 1.1.1.1 with 2000 bytes, got %v", peers[0])
	}
	if peers[1].Key != "8.8.8.8" || peers[1].Bytes != 1000 {
		t.Errorf("expected second peer to be 8.8.8.8 with 1000 bytes, got %v", peers[1])
	}

	// Test GetDeviceTopPorts
	ports, err := repo.GetDeviceTopPorts(ctx, "192.168.1.100", start, end, 10)
	if err != nil {
		t.Fatalf("failed to get device top ports: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(ports))
	}
	if ports[0].Key != "443" || ports[0].Bytes != 2000 {
		t.Errorf("expected top port to be 443 with 2000 bytes, got %v", ports[0])
	}
	if ports[1].Key != "53" || ports[1].Bytes != 1000 {
		t.Errorf("expected second port to be 53 with 1000 bytes, got %v", ports[1])
	}
}

func TestDuckDBPolicies(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flowguard-duckdb-policies-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	repo, err := NewDuckDBRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to initialize DuckDB repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()

	// Register device
	now := time.Now()
	_ = repo.UpsertDevice(ctx, "192.168.1.15", "test-host", now)

	// 1. Test CRUD
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

	// List policies
	list, err := repo.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to list policies: %v", err)
	}
	if len(list) != 1 || list[0].Name != "Silence Port Scans" {
		t.Errorf("unexpected list result: %v", list)
	}

	// Get policy
	retrieved, err := repo.GetPolicy(ctx, p1.ID)
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if retrieved.CooldownSeconds != 60 || !retrieved.Suppressed || len(retrieved.NotificationChannels) != 2 {
		t.Errorf("retrieved policy properties mismatch: %v", retrieved)
	}

	// 2. Test Input Validation
	invalidP := &Policy{
		Name:   "Invalid IP Target",
		Scope:  "ip",
		Target: "not-an-ip",
	}
	err = repo.SavePolicy(ctx, invalidP)
	if err == nil {
		t.Error("expected error validating policy with invalid target IP, got nil")
	}

	// 3. Test Policy Suppression Rules on SaveAnomaly
	// A. Silence / Suppression toggle
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

	// B. Severity Threshold suppression
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

	// C. Cooldown deduplication suppression
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

	// D. Precedence Order Test (IP > Global)
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

	// 4. Test Delete
	err = repo.DeletePolicy(ctx, p1.ID)
	if err != nil {
		t.Fatalf("failed to delete policy: %v", err)
	}
	_, err = repo.GetPolicy(ctx, p1.ID)
	if err == nil {
		t.Error("expected error fetching deleted policy, got nil")
	}
}

func TestDuckDBRepository_NotificationRulesAndLogs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flowguard-duckdb-test-notification-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo, err := NewDuckDBRepository(tmpDir, logger)
	if err != nil {
		t.Fatalf("failed to initialize repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()

	// 1. Create a notification rule
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

	// 2. Get and List notification rules
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

	// 3. Save and List notification logs
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

	// 4. Test Deduplication
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

	// 5. Test Delete rule
	err = repo.DeleteNotificationRule(ctx, r1.ID)
	if err != nil {
		t.Fatalf("failed to delete notification rule: %v", err)
	}

	_, err = repo.GetNotificationRule(ctx, r1.ID)
	if err == nil {
		t.Error("expected error getting deleted notification rule, got nil")
	}
}
