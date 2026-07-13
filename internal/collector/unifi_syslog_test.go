package collector

import (
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/flow"
)

func TestParseUniFiSyslogRFC5424(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	msg := []byte(`<134>1 2026-07-12T09:59:58Z ucg-fiber UniFi - security - Security Detection: client 192.168.1.20 triggered IDS`)

	event, err := ParseUniFiSyslog(msg, now)
	if err != nil {
		t.Fatalf("expected RFC5424 parse to succeed: %v", err)
	}
	if event.Facility != 16 || event.Severity != 6 {
		t.Fatalf("unexpected priority decode: %+v", event)
	}
	if !event.Timestamp.Equal(time.Date(2026, 7, 12, 9, 59, 58, 0, time.UTC)) {
		t.Fatalf("unexpected timestamp: %s", event.Timestamp)
	}
	if event.Host != "ucg-fiber" || event.AppName != "UniFi" || event.MsgID != "security" {
		t.Fatalf("unexpected RFC5424 fields: %+v", event)
	}
	if !strings.Contains(event.Message, "Security Detection") {
		t.Fatalf("expected reduced message summary, got %q", event.Message)
	}
}

func TestParseUniFiSyslogRFC3164(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	msg := []byte(`<165>Jul 12 09:58:01 ucg-fiber UniFi[123]: Admin Activity login from 192.168.1.10`)

	event, err := ParseUniFiSyslog(msg, now)
	if err != nil {
		t.Fatalf("expected RFC3164 parse to succeed: %v", err)
	}
	if event.Facility != 20 || event.Severity != 5 {
		t.Fatalf("unexpected priority decode: %+v", event)
	}
	if event.Host != "ucg-fiber" || event.AppName != "UniFi" || event.ProcID != "123" {
		t.Fatalf("unexpected RFC3164 fields: %+v", event)
	}
	if event.Timestamp.Year() != 2026 || event.Timestamp.Month() != time.July || event.Timestamp.Day() != 12 {
		t.Fatalf("expected current-year RFC3164 timestamp, got %s", event.Timestamp)
	}
	if !strings.Contains(event.Message, "Admin Activity") {
		t.Fatalf("expected reduced message summary, got %q", event.Message)
	}
}

func TestParseUniFiSyslogRejectsMalformedAndOversized(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		msg  []byte
	}{
		{name: "missing priority", msg: []byte(`Jul 12 09:58:01 ucg UniFi: message`)},
		{name: "invalid priority", msg: []byte(`<999>Jul 12 09:58:01 ucg UniFi: message`)},
		{name: "truncated", msg: []byte(`<134>Jul 12`)},
		{name: "blank", msg: []byte(``)},
		{name: "oversized", msg: []byte(`<134>` + strings.Repeat("x", maxUniFiSyslogDatagramBytes+1))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseUniFiSyslog(tc.msg, now); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestFlowCollector_UniFiSyslogReceiveAndCounters(t *testing.T) {
	cfg := syslogTestConfig(t, []string{"127.0.0.1"})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewFlowCollector(cfg, logger, nil, nil)
	if err := c.Start(); err != nil {
		t.Fatalf("failed to start collector: %v", err)
	}
	defer c.Shutdown()
	if c.usConn == nil {
		t.Fatal("expected UniFi syslog socket to be listening")
	}

	sendUDP(t, cfg.UniFiSyslogPort, []byte(`<134>1 2026-07-12T09:59:58Z ucg UniFi - security - Security Detection`))
	waitFor(t, func() bool {
		stats := c.GetStats()
		return stats.PacketsUniFi == 1 && unifiSource(stats.Sources).Packets == 1
	})

	stats := c.GetStats()
	src := unifiSource(stats.Sources)
	if src.Kind != flow.CollectorKindUniFiSyslog || !src.Enabled || src.Status != "listening" {
		t.Fatalf("unexpected UniFi source stats: %+v", src)
	}
	if stats.DecodeErrors != 0 || src.DecodeErrors != 0 || src.Drops != 0 {
		t.Fatalf("unexpected counters after valid syslog message: %+v source=%+v", stats, src)
	}
}

func TestFlowCollector_UniFiSyslogMalformedOversizedAndAllowlistCounters(t *testing.T) {
	cfg := syslogTestConfig(t, []string{"192.0.2.0/24"})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewFlowCollector(cfg, logger, nil, nil)
	if err := c.Start(); err != nil {
		t.Fatalf("failed to start collector: %v", err)
	}

	sendUDP(t, cfg.UniFiSyslogPort, []byte(`<134>Jul 12`))
	sendUDP(t, cfg.UniFiSyslogPort, []byte(`<134>`+strings.Repeat("x", maxUniFiSyslogDatagramBytes+1)))
	waitFor(t, func() bool {
		src := unifiSource(c.GetStats().Sources)
		return src.Drops >= 2
	})

	stats := c.GetStats()
	src := unifiSource(stats.Sources)
	if stats.PacketsUniFi != 0 || src.Packets != 0 {
		t.Fatalf("allowlist rejects should not count as received packets: %+v source=%+v", stats, src)
	}
	if src.Drops < 2 || stats.PacketsDropped < 2 {
		t.Fatalf("expected allowlist drops, got stats=%+v source=%+v", stats, src)
	}

	c.Shutdown()

	cfg = syslogTestConfig(t, []string{"127.0.0.1"})
	c = NewFlowCollector(cfg, logger, nil, nil)
	if err := c.Start(); err != nil {
		t.Fatalf("failed to restart collector: %v", err)
	}
	defer c.Shutdown()

	sendUDP(t, cfg.UniFiSyslogPort, []byte(`<134>Jul 12`))
	sendUDP(t, cfg.UniFiSyslogPort, []byte(`<134>`+strings.Repeat("x", maxUniFiSyslogDatagramBytes+1)))
	waitFor(t, func() bool {
		src := unifiSource(c.GetStats().Sources)
		return src.DecodeErrors >= 2 && src.Drops >= 1
	})

	stats = c.GetStats()
	src = unifiSource(stats.Sources)
	if stats.PacketsUniFi != 1 || src.Packets != 1 {
		t.Fatalf("expected malformed non-oversized datagram to count as received, got stats=%+v source=%+v", stats, src)
	}
	if src.DecodeErrors < 2 || stats.DecodeErrors < 2 || src.Drops < 1 {
		t.Fatalf("expected malformed and oversized counters, got stats=%+v source=%+v", stats, src)
	}
}

func syslogTestConfig(t *testing.T, allowlist []string) *config.Config {
	t.Helper()
	port := freeUDPPort(t)
	cfg := config.DefaultConfig()
	cfg.NetflowPort = 0
	cfg.SflowPort = 0
	cfg.UniFiSyslogEnabled = true
	cfg.UniFiSyslogPort = port
	cfg.UniFiSyslogAllowedIPs = allowlist
	cfg.Environment = "test"
	return cfg
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve UDP addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func sendUDP(t *testing.T, port int, msg []byte) {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatalf("dial UDP: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write UDP: %v", err)
	}
}

func waitFor(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func unifiSource(sources []SourceStats) SourceStats {
	for _, src := range sources {
		if src.Kind == flow.CollectorKindUniFiSyslog {
			return src
		}
	}
	return SourceStats{}
}
