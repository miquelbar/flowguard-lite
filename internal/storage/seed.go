package storage

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/flowguard/flowguard/internal/config"
	"github.com/flowguard/flowguard/internal/flow"
)

// SeedMockData populates 30 days of realistic mock telemetry, devices, baselines, and alerts.
func SeedMockData(repo StorageRepository, log *slog.Logger, cfg *config.Config, configPath string) error {
	ctx := context.Background()
	now := time.Now()

	log.Info("Seeding discovered device records...")
	devices := []struct {
		ip       string
		hostname string
		label    string
	}{
		{"192.168.1.1", "unifi-gateway", "Gateway"},
		{"192.168.1.50", "synology-nas", "Storage"},
		{"192.168.20.100", "smart-tv", "IoT"},
		{"192.168.30.150", "m1-macbook", "Workstation"},
		{"192.168.30.200", "ubiquiti-camera", "Security"},
	}

	for _, d := range devices {
		if err := repo.UpsertDevice(ctx, d.ip, d.hostname, now); err != nil {
			return fmt.Errorf("upsert device %s: %w", d.ip, err)
		}
		if err := repo.UpdateDeviceLabel(ctx, d.ip, d.label); err != nil {
			return fmt.Errorf("update label %s: %w", d.ip, err)
		}

		// Seed a statistical baseline profile for each device
		baseline := &DeviceBaseline{
			IP:            d.ip,
			MeanBytes:     150000.0,
			StdDevBytes:   20000.0,
			MeanPackets:   1500.0,
			StdDevPackets: 200.0,
			MeanPeers:     5.0,
			StdDevPeers:   1.0,
			UpdatedAt:     now,
		}
		if err := repo.SaveBaseline(ctx, baseline); err != nil {
			return fmt.Errorf("save baseline %s: %w", d.ip, err)
		}
	}

	log.Info("Seeding 30 days of flow aggregates...")
	// We generate flow aggregates representing normal local network profiles from the UniFi exporter
	for day := 30; day >= 0; day-- {
		t := now.Add(-24 * time.Hour * time.Duration(day))

		flows := []flow.FlowEvent{
			{
				Timestamp: t,
				SrcIP:     "192.168.30.150",
				DstIP:     "8.8.8.8",
				DstPort:   53,
				Protocol:  17, // UDP
				Bytes:     4500,
				Packets:   50,
			},
			{
				Timestamp: t,
				SrcIP:     "192.168.30.150",
				DstIP:     "142.250.74.46",
				DstPort:   443,
				Protocol:  6, // TCP
				Bytes:     1540000,
				Packets:   1200,
			},
			{
				Timestamp: t,
				SrcIP:     "192.168.1.50",
				DstIP:     "192.168.30.150",
				DstPort:   443,
				Protocol:  6,
				Bytes:     82004000,
				Packets:   80000,
			},
			{
				Timestamp: t,
				SrcIP:     "192.168.20.100",
				DstIP:     "52.84.150.12",
				DstPort:   443,
				Protocol:  6,
				Bytes:     5200000,
				Packets:   4000,
			},
			{
				Timestamp: t,
				SrcIP:     "192.168.30.200",
				DstIP:     "192.168.1.1",
				DstPort:   7447,
				Protocol:  6,
				Bytes:     256000000,
				Packets:   200000,
			},
		}

		if err := repo.SaveAggregates(ctx, t, flows); err != nil {
			return fmt.Errorf("failed saving aggregates for day %d: %w", day, err)
		}
	}

	log.Info("Seeding threat anomalies...")
	anomalies := []*Anomaly{
		{
			IP:          "192.168.20.100",
			Type:        "port_scan",
			Description: "Smart-TV scanned 42 local IP addresses on port 80 within 1 minute.",
			Severity:    "medium",
			Status:      "acknowledged",
			CreatedAt:   now.Add(-20 * 24 * time.Hour),
			UpdatedAt:   now.Add(-20 * 24 * time.Hour),
		},
		{
			IP:          "192.168.1.50",
			Type:        "outbound_volume",
			Description: "Synology-NAS outbound transfer of 8.2 GB/h exceeded baseline mean by 5.4 std deviations.",
			Severity:    "high",
			Status:      "acknowledged",
			CreatedAt:   now.Add(-15 * 24 * time.Hour),
			UpdatedAt:   now.Add(-15 * 24 * time.Hour),
		},
		{
			IP:          "192.168.20.100",
			Type:        "suricata",
			Description: "Suricata IDS Alert: ET MALWARE Trojan Activity - Command and Control communication detected",
			Severity:    "high",
			Status:      "active",
			CreatedAt:   now.Add(-1 * time.Hour),
			UpdatedAt:   now.Add(-1 * time.Hour),
		},
		{
			IP:          "192.168.30.150",
			Type:        "ddos",
			Description: "DDoS SYN flood detected from 192.168.30.150 toward external IP 185.220.101.4",
			Severity:    "high",
			Status:      "active",
			CreatedAt:   now.Add(-30 * time.Minute),
			UpdatedAt:   now.Add(-30 * time.Minute),
		},
	}

	for _, a := range anomalies {
		if err := repo.SaveAnomaly(ctx, a); err != nil {
			return fmt.Errorf("save anomaly %s: %w", a.IP, err)
		}
	}

	log.Info("Seeding audit logs...")
	auditLogs := []struct {
		t       time.Time
		action  string
		details string
	}{
		{now.Add(-30 * 24 * time.Hour), "setup_wizard", "FlowGuard Lite initial configuration completed."},
		{now.Add(-20 * 24 * time.Hour), "rules_exported", "Firewall rules for blocking malicious scanner exported to MikroTik CLI template."},
		{now.Add(-5 * 24 * time.Hour), "settings_updated", "Local subnets range modified to: 192.168.1.0/24"},
	}

	for _, al := range auditLogs {
		// Mock implementation using repository interface
		if err := repo.SaveAuditLog(ctx, al.action, al.details); err != nil {
			return fmt.Errorf("save audit log: %w", err)
		}
	}

	// Bypass the onboarding setup wizard
	cfg.FirstRunCompleted = true
	if err := config.SaveConfig(configPath, cfg); err != nil {
		log.Warn("Failed to save config during seeding bypass", slog.String("error", err.Error()))
	}

	log.Info("Development database successfully seeded with 30 days of mock data!")
	return nil
}
