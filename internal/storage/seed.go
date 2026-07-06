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
		{"192.168.1.10", "local-printer", "Printer"},
		{"192.168.20.100", "smart-tv", "IoT"},
		{"192.168.20.101", "philips-hue-hub", "IoT"},
		{"192.168.30.150", "m1-macbook", "Workstation"},
		{"192.168.30.160", "win11-desktop", "Workstation"},
		{"192.168.30.200", "ubiquiti-camera", "Security"},
		{"192.168.30.210", "iphone-15", "Mobile"},
		{"192.168.30.220", "nintendo-switch", "Gaming"},
		{"192.168.40.80", "proxmox-host", "Server"},
		{"192.168.30.99", "unknown-device", "Unknown"},
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
			MeanBytes:     250000.0,
			StdDevBytes:   50000.0,
			MeanPackets:   2500.0,
			StdDevPackets: 500.0,
			MeanPeers:     8.0,
			StdDevPeers:   2.0,
			UpdatedAt:     now,
		}
		if err := repo.SaveBaseline(ctx, baseline); err != nil {
			return fmt.Errorf("save baseline %s: %w", d.ip, err)
		}
	}

	log.Info("Seeding 30 days of hourly flow aggregates...")
	// We generate flow aggregates representing normal local network profiles with hourly granularity
	totalHours := 30 * 24
	for hourIdx := totalHours; hourIdx >= 0; hourIdx-- {
		t := now.Add(-time.Hour * time.Duration(hourIdx))

		var flows []flow.FlowEvent
		hour := t.Hour()
		weekday := t.Weekday()

		// 1. Workstation: Diurnal curve (active 8h - 19h, minimal activity at night)
		isWorkingHour := hour >= 8 && hour <= 19
		var workMultiplier uint64 = 1
		if isWorkingHour && weekday != time.Saturday && weekday != time.Sunday {
			workMultiplier = 15
		}

		flows = append(flows, flow.FlowEvent{
			Timestamp: t,
			SrcIP:     "192.168.30.150",
			DstIP:     "8.8.8.8",
			DstPort:   53,
			Protocol:  17, // UDP
			Bytes:     2500 * workMultiplier,
			Packets:   30 * workMultiplier,
		})

		flows = append(flows, flow.FlowEvent{
			Timestamp: t,
			SrcIP:     "192.168.30.150",
			DstIP:     "142.250.74.46",
			DstPort:   443,
			Protocol:  6, // TCP
			Bytes:     125000 * workMultiplier,
			Packets:   120 * workMultiplier,
		})

		// 2. Local TV streaming: Active mostly in evenings 18h - 23h
		var tvMultiplier uint64 = 1
		if hour >= 18 && hour <= 23 {
			tvMultiplier = 80 // massive streaming
		}
		flows = append(flows, flow.FlowEvent{
			Timestamp: t,
			SrcIP:     "192.168.20.100",
			DstIP:     "52.84.150.12",
			DstPort:   443,
			Protocol:  6,
			Bytes:     80000 * tvMultiplier,
			Packets:   90 * tvMultiplier,
		})

		// 3. Security Camera: Flat-line constant traffic to Gateway
		flows = append(flows, flow.FlowEvent{
			Timestamp: t,
			SrcIP:     "192.168.30.200",
			DstIP:     "192.168.1.1",
			DstPort:   7447,
			Protocol:  6,
			Bytes:     350000,
			Packets:   240,
		})

		// 4. NAS Backup: Spikes once a week (Sundays 2:00 AM - 4:00 AM)
		var nasBackup uint64 = 0
		if weekday == time.Sunday && hour >= 2 && hour <= 4 {
			nasBackup = 150000000 // 150MB per hour
		}
		if nasBackup > 0 {
			flows = append(flows, flow.FlowEvent{
				Timestamp: t,
				SrcIP:     "192.168.30.150",
				DstIP:     "192.168.1.50",
				DstPort:   443,
				Protocol:  6,
				Bytes:     nasBackup,
				Packets:   nasBackup / 1200,
			})
			flows = append(flows, flow.FlowEvent{
				Timestamp: t,
				SrcIP:     "192.168.30.160",
				DstIP:     "192.168.1.50",
				DstPort:   443,
				Protocol:  6,
				Bytes:     nasBackup * 8 / 10,
				Packets:   (nasBackup * 8 / 10) / 1200,
			})
		}

		// 5. General DNS/ICMP traffic mix to vary protocol donuts
		var icmpBytes uint64 = 64
		if hour%4 == 0 {
			icmpBytes = 512
		}
		flows = append(flows, flow.FlowEvent{
			Timestamp: t,
			SrcIP:     "192.168.30.210",
			DstIP:     "8.8.8.8",
			DstPort:   0,
			Protocol:  1, // ICMP
			Bytes:     icmpBytes,
			Packets:   uint64(hour%4 + 1),
		})

		// 6. Unknown device periodic polling
		flows = append(flows, flow.FlowEvent{
			Timestamp: t,
			SrcIP:     "192.168.30.99",
			DstIP:     "185.220.101.4",
			DstPort:   8080,
			Protocol:  6,
			Bytes:     1200,
			Packets:   4,
		})

		if err := repo.SaveAggregates(ctx, t, flows); err != nil {
			return fmt.Errorf("failed saving aggregates for hour index %d: %w", hourIdx, err)
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
		{
			IP:          "192.168.30.160",
			Type:        "beacon",
			Description: "Workstation win11-desktop shows periodic beaconing behavior (every 45s) to 91.228.166.12",
			Severity:    "medium",
			Status:      "active",
			CreatedAt:   now.Add(-6 * time.Hour),
			UpdatedAt:   now.Add(-6 * time.Hour),
		},
		{
			IP:          "192.168.20.101",
			Type:        "new_destination",
			Description: "Philips Hue Hub initiated connection to unrecognized external IP address 203.0.113.80",
			Severity:    "medium",
			Status:      "active",
			CreatedAt:   now.Add(-12 * time.Hour),
			UpdatedAt:   now.Add(-12 * time.Hour),
		},
		{
			IP:          "192.168.30.210",
			Type:        "nighttime_traffic",
			Description: "Mobile phone iphone-15 transferred 4.8 GB of data between 03:00 AM and 04:00 AM (abnormal behavior)",
			Severity:    "low",
			Status:      "active",
			CreatedAt:   now.Add(-18 * time.Hour),
			UpdatedAt:   now.Add(-18 * time.Hour),
		},
		{
			IP:          "192.168.40.80",
			Type:        "abnormal_flows",
			Description: "Proxmox Host initiated 4,200 concurrent flows, exceeding historical maximum by 250%",
			Severity:    "medium",
			Status:      "active",
			CreatedAt:   now.Add(-2 * time.Hour),
			UpdatedAt:   now.Add(-2 * time.Hour),
		},
	}

	for _, a := range anomalies {
		if err := repo.SaveAnomaly(ctx, a); err != nil {
			return fmt.Errorf("save anomaly %s: %w", a.IP, err)
		}
	}

	log.Info("Seeding custom policies...")
	policies := []*Policy{
		{
			Name:              "Silence Port Scans on IoT Subnet",
			Scope:             "subnet",
			Target:            "192.168.20.0/24",
			SeverityThreshold: "medium",
			Suppressed:        true,
			CooldownSeconds:   600,
		},
		{
			Name:              "DDoS Alerts Cooldown Filter",
			Scope:             "alert_type",
			Target:            "ddos",
			SeverityThreshold: "high",
			Suppressed:        false,
			CooldownSeconds:   300,
		},
		{
			Name:              "Global Low Severity Noise Gate",
			Scope:             "global",
			Target:            "",
			SeverityThreshold: "medium",
			Suppressed:        false,
			CooldownSeconds:   0,
		},
	}

	for _, p := range policies {
		if err := repo.SavePolicy(ctx, p); err != nil {
			return fmt.Errorf("save policy %s: %w", p.Name, err)
		}
	}

	log.Info("Seeding notification rule logs...")
	// Let's query anomaly IDs to link notification logs
	recentAnoms, err := repo.GetActiveAnomalies(ctx, now.Add(-24*time.Hour))
	if err == nil && len(recentAnoms) > 0 {
		channels := []string{"slack", "telegram", "webhook"}
		statuses := []string{"sent", "suppressed", "failed", "deduplicated"}
		errMsgs := []string{"", "", "Connection timed out", ""}

		for i, anom := range recentAnoms {
			ruleID := int64(1 + i%3)
			logEntry := &NotificationLog{
				AnomalyID:    anom.ID,
				RuleID:       &ruleID,
				Channel:      channels[i%len(channels)],
				Status:       statuses[i%len(statuses)],
				ErrorMessage: errMsgs[i%len(errMsgs)],
				DispatchedAt: anom.CreatedAt.Add(5 * time.Second),
			}
			if err := repo.SaveNotificationLog(ctx, logEntry); err != nil {
				log.Warn("Failed seeding notification log", slog.Int64("anomaly_id", anom.ID), slog.String("error", err.Error()))
			}
		}
	}

	log.Info("Seeding audit logs...")
	auditLogs := []struct {
		t       time.Time
		action  string
		details string
	}{
		{now.Add(-30 * 24 * time.Hour), "setup_wizard", "FlowGuard Lite initial configuration completed."},
		{now.Add(-25 * 24 * time.Hour), "settings_updated", "Access Control password changed by Administrator."},
		{now.Add(-20 * 24 * time.Hour), "policy_created", "Created policy 'Silence Port Scans on IoT Subnet'."},
		{now.Add(-15 * 24 * time.Hour), "settings_updated", "Local subnets range modified to: 192.168.1.0/24, 192.168.20.0/24, 192.168.30.0/24, 192.168.40.0/24"},
		{now.Add(-14 * 24 * time.Hour), "alert_acknowledged", "Acknowledged Synology-NAS outbound volume spike."},
		{now.Add(-10 * 24 * time.Hour), "rules_exported", "Firewall rules for blocking malicious scanner exported to MikroTik CLI template."},
		{now.Add(-5 * 24 * time.Hour), "settings_updated", "Collectors NetFlow port modified to: 2055"},
		{now.Add(-4 * 24 * time.Hour), "policy_created", "Created policy 'DDoS Alerts Cooldown Filter'."},
		{now.Add(-2 * 24 * time.Hour), "alert_acknowledged", "Acknowledged Smart-TV scanner anomaly."},
		{now.Add(-1 * 24 * time.Hour), "test_alert_sent", "Triggered test alert dispatch to Slack channel."},
	}

	for _, al := range auditLogs {
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
