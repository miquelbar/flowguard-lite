package collector

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

type mockSyslogStorage struct {
	storage.StorageRepository
	mu          sync.Mutex
	unifiEvents []storage.UniFiEvent
	anomalies   []storage.Anomaly
	devices     map[string]bool
}

func newMockSyslogStorage() *mockSyslogStorage {
	return &mockSyslogStorage{
		devices: make(map[string]bool),
	}
}

func (m *mockSyslogStorage) SaveUniFiEvent(ctx context.Context, e *storage.UniFiEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unifiEvents = append(m.unifiEvents, *e)
	return nil
}

func (m *mockSyslogStorage) SaveAnomaly(ctx context.Context, a *storage.Anomaly) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.anomalies = append(m.anomalies, *a)
	return nil
}

func (m *mockSyslogStorage) UpsertDevice(ctx context.Context, ip string, hostname string, lastSeen time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.devices[ip] = true
	return nil
}

func TestExtractUniFiCategory(t *testing.T) {
	cases := []struct {
		msg      string
		severity int
		expected string
	}{
		{"netconsole: server started", 5, "Netconsole"},
		{"ips: threat detected signature 2018402", 3, "Security Detections"},
		{"security detection: intrusion blocked", 2, "Security Detections"},
		{"admin login from 192.168.1.10", 6, "Admin Activity"},
		{"VPN connection established: user miquel", 6, "VPN"},
		{"checking for updates...", 6, "Updates"},
		{"firmware upgrade starting", 6, "Updates"},
		{"critical hardware error", 2, "Critical"},
		{"system rebooting", 1, "Critical"},
		{"device connected: ucg-fiber", 6, "Devices"},
		{"client connected to AP", 6, "Clients"},
		{"triggering backup job", 6, "Triggers"},
		{"something random", 6, "Other"},
	}

	for _, tc := range cases {
		t.Run(tc.msg, func(t *testing.T) {
			got := ExtractUniFiCategory(tc.msg, tc.severity)
			if got != tc.expected {
				t.Errorf("expected category %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestExtractIP(t *testing.T) {
	cases := []struct {
		msg      string
		expected string
	}{
		{"client 192.168.1.50 triggered alert", "192.168.1.50"},
		{"Admin login from 192.168.10.15", "192.168.10.15"},
		{"threat from 2001:db8::1 blocked", "2001:db8::1"},
		{"no IP address here", ""},
		{"invalid IP 999.999.999.999", ""},
	}

	for _, tc := range cases {
		t.Run(tc.msg, func(t *testing.T) {
			got := ExtractIP(tc.msg)
			if got != tc.expected {
				t.Errorf("expected IP %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestFlowCollector_UniFiSyslogEventIngestAndAnomaly(t *testing.T) {
	cfg := config.DefaultConfig()
	port := freeUDPPort(t)
	cfg.NetflowPort = 0
	cfg.SflowPort = 0
	cfg.UniFiSyslogEnabled = true
	cfg.UniFiSyslogPort = port
	cfg.UniFiSyslogAllowedIPs = []string{"127.0.0.1"}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo := newMockSyslogStorage()
	c := NewFlowCollector(cfg, logger, nil, repo)

	if err := c.Start(); err != nil {
		t.Fatalf("failed to start collector: %v", err)
	}
	defer c.Shutdown()

	// 1. Send Security Detection syslog (which triggers both an event and an anomaly)
	msg1 := []byte(`<134>1 2026-07-12T09:59:58Z ucg-fiber UniFi - security - Security Detection: client 192.168.1.20 triggered IDS`)
	sendUDP(t, port, msg1)

	// Wait for processing
	waitFor(t, func() bool {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		return len(repo.unifiEvents) == 1 && len(repo.anomalies) == 1
	})

	repo.mu.Lock()
	evt1 := repo.unifiEvents[0]
	anom1 := repo.anomalies[0]
	repo.mu.Unlock()

	if evt1.Category != "Security Detections" || evt1.Severity != "high" || evt1.ClientIP != "192.168.1.20" {
		t.Errorf("unexpected saved event: %+v", evt1)
	}
	if anom1.IP != "192.168.1.20" || anom1.Type != "UNIFI_SECURITY" || anom1.Severity != "high" {
		t.Errorf("unexpected saved anomaly: %+v", anom1)
	}

	// Verify device was registered
	repo.mu.Lock()
	hasDevice := repo.devices["192.168.1.20"]
	repo.mu.Unlock()
	if !hasDevice {
		t.Error("expected device 192.168.1.20 to be registered")
	}

	// 2. Send non-critical Admin Activity syslog (should save event but NOT trigger anomaly)
	msg2 := []byte(`<165>Jul 12 09:58:01 ucg-fiber UniFi[123]: Admin Activity login from 192.168.1.10`)
	sendUDP(t, port, msg2)

	waitFor(t, func() bool {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		return len(repo.unifiEvents) == 2
	})

	repo.mu.Lock()
	evt2 := repo.unifiEvents[1]
	anomCount := len(repo.anomalies)
	repo.mu.Unlock()

	if evt2.Category != "Admin Activity" || evt2.Severity != "low" || evt2.ClientIP != "192.168.1.10" {
		t.Errorf("unexpected saved event: %+v", evt2)
	}
	if anomCount != 1 {
		t.Errorf("expected no additional anomaly triggered, anomalies count: %d", anomCount)
	}
}
