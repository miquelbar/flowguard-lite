package collector

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/miquelbar/flowguard-lite/internal/storage"
)

const (
	defaultUniFiSyslogQueueSize = 1000
	maxUniFiSyslogDatagramBytes = 4096
)

type syslogDatagram struct {
	data     []byte
	senderIP string
}

type uniFiSyslogAllowlist struct {
	ips      map[netip.Addr]struct{}
	prefixes []netip.Prefix
}

// UniFiSyslogEvent is a reduced in-memory representation of a parsed syslog
// message. M30.4 validates parsing and counters only; storage/evidence starts in M30.5.
type UniFiSyslogEvent struct {
	Timestamp time.Time
	Host      string
	AppName   string
	ProcID    string
	MsgID     string
	Facility  int
	Severity  int
	Message   string
}

func (c *FlowCollector) listenUniFiSyslogLoop(conn *net.UDPConn, allowlist uniFiSyslogAllowlist) {
	defer c.wg.Done()
	buf := make([]byte, maxUniFiSyslogDatagramBytes+1)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			n, rAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				c.logger.Warn("Error reading from UniFi syslog UDP socket", slog.String("error", err.Error()))
				continue
			}
			if !allowlist.allows(rAddr.IP) {
				c.incrementUniFiDrop()
				continue
			}
			if n > maxUniFiSyslogDatagramBytes {
				c.incrementUniFiDrop()
				c.incrementUniFiDecodeError()
				continue
			}

			data := make([]byte, n)
			copy(data, buf[:n])

			c.statsMu.Lock()
			c.receivedCount++
			c.receivedUniFiCount++
			c.statsMu.Unlock()

			select {
			case c.syslogChan <- &syslogDatagram{data: data, senderIP: rAddr.IP.String()}:
			default:
				c.incrementUniFiDrop()
			}
		}
	}
}

func (c *FlowCollector) unifiSyslogWorkerLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		case msg := <-c.syslogChan:
			if msg == nil {
				continue
			}
			parsed, err := ParseUniFiSyslog(msg.data, time.Now().UTC())
			if err != nil {
				c.incrementUniFiDecodeError()
				c.logger.Debug("Failed to parse UniFi syslog message",
					slog.String("sender", msg.senderIP),
					slog.String("error", err.Error()))
				continue
			}

			// Perform reduction, classification, storage, and anomaly generation
			if c.repo != nil {
				category := ExtractUniFiCategory(parsed.Message, parsed.Severity)
				clientIP := ExtractIP(parsed.Message)
				severity := mapSyslogSeverity(parsed.Severity, category)

				attributes := map[string]string{
					"app_name": parsed.AppName,
					"proc_id":  parsed.ProcID,
					"msg_id":   parsed.MsgID,
					"facility": strconv.Itoa(parsed.Facility),
					"severity": strconv.Itoa(parsed.Severity),
				}

				event := &storage.UniFiEvent{
					Timestamp:     parsed.Timestamp,
					SourceGateway: parsed.Host,
					Category:      category,
					Severity:      severity,
					ClientIP:      clientIP,
					Summary:       parsed.Message,
					Attributes:    attributes,
				}
				if event.SourceGateway == "" {
					event.SourceGateway = msg.senderIP
				}

				if err := c.repo.SaveUniFiEvent(c.ctx, event); err != nil {
					c.logger.Error("Failed to save UniFi SIEM event to database", slog.String("error", err.Error()))
				}

				// Convert only high-confidence security detections/critical events into anomalies/alarms
				isSecurityDetection := category == "Security Detections"
				isCriticalEvent := severity == "critical"
				if isSecurityDetection || isCriticalEvent {
					// We need an IP to associate the anomaly with. If no client IP is extracted, we fallback to the source gateway IP.
					targetIP := clientIP
					if targetIP == "" {
						targetIP = msg.senderIP
					}

					// Upsert the device first to fulfill the foreign key constraint in SQLite anomalies table
					if err := c.repo.UpsertDevice(c.ctx, targetIP, "", parsed.Timestamp); err != nil {
						c.logger.Error("Failed to upsert device for UniFi anomaly", slog.String("ip", targetIP), slog.String("error", err.Error()))
					}

					anomalyType := "UNIFI_SECURITY"
					if isCriticalEvent && !isSecurityDetection {
						anomalyType = "UNIFI_CRITICAL"
					}

					anomaly := &storage.Anomaly{
						IP:          targetIP,
						Type:        anomalyType,
						Description: parsed.Message,
						Severity:    severity,
						Status:      "active",
						CreatedAt:   parsed.Timestamp,
						UpdatedAt:   parsed.Timestamp,
					}

					if err := c.repo.SaveAnomaly(c.ctx, anomaly); err != nil {
						c.logger.Error("Failed to save UniFi syslog anomaly to database", slog.String("error", err.Error()))
					}
				}
			}
		}
	}
}

// ExtractUniFiCategory extracts the UniFi SIEM category from the log message text and severity.
func ExtractUniFiCategory(msg string, syslogSev int) string {
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "netconsole") {
		return "Netconsole"
	}
	if strings.Contains(lower, "security detection") || strings.Contains(lower, "ips") || strings.Contains(lower, "ids") || strings.Contains(lower, "threat") || strings.Contains(lower, "blocked") {
		return "Security Detections"
	}
	if strings.Contains(lower, "admin activity") || strings.Contains(lower, "admin") || strings.Contains(lower, "login") {
		return "Admin Activity"
	}
	if strings.Contains(lower, "vpn") {
		return "VPN"
	}
	if strings.Contains(lower, "update") || strings.Contains(lower, "upgrade") {
		return "Updates"
	}
	if strings.Contains(lower, "critical") || syslogSev <= 2 {
		return "Critical"
	}
	if strings.Contains(lower, "device") {
		return "Devices"
	}
	if strings.Contains(lower, "client") {
		return "Clients"
	}
	if strings.Contains(lower, "trigger") {
		return "Triggers"
	}
	return "Other"
}

// ExtractIP searches for the first IPv4 or IPv6 address in the message text.
func ExtractIP(msg string) string {
	tokenRegex := regexp.MustCompile(`[0-9a-fA-F:\.]+`)
	matches := tokenRegex.FindAllString(msg, -1)
	for _, match := range matches {
		match = strings.Trim(match, ".:")
		if ip := net.ParseIP(match); ip != nil {
			return match
		}
	}
	return ""
}

// mapSyslogSeverity maps raw syslog severity level and category to standard severity (low, medium, high, critical).
func mapSyslogSeverity(syslogSev int, category string) string {
	if category == "Security Detections" {
		if syslogSev <= 3 {
			return "critical"
		}
		return "high"
	}
	switch syslogSev {
	case 0, 1, 2:
		return "critical"
	case 3:
		return "high"
	case 4:
		return "medium"
	default:
		return "low"
	}
}

func (c *FlowCollector) incrementUniFiDrop() {
	c.statsMu.Lock()
	c.droppedCount++
	c.droppedUniFiCount++
	c.statsMu.Unlock()
}

func (c *FlowCollector) incrementUniFiDecodeError() {
	c.statsMu.Lock()
	c.decodeErrCount++
	c.decodeErrUniFiCount++
	c.statsMu.Unlock()
}

func parseUniFiSyslogAllowlist(entries []string) (uniFiSyslogAllowlist, error) {
	out := uniFiSyslogAllowlist{ips: map[netip.Addr]struct{}{}}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return out, fmt.Errorf("invalid CIDR %q: %w", entry, err)
			}
			out.prefixes = append(out.prefixes, prefix)
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return out, fmt.Errorf("invalid IP %q: %w", entry, err)
		}
		out.ips[addr] = struct{}{}
	}
	return out, nil
}

func (a uniFiSyslogAllowlist) allows(ip net.IP) bool {
	if len(a.ips) == 0 && len(a.prefixes) == 0 {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if _, ok := a.ips[addr]; ok {
		return true
	}
	for _, prefix := range a.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ParseUniFiSyslog parses a bounded RFC5424/RFC3164-like syslog datagram.
func ParseUniFiSyslog(data []byte, now time.Time) (UniFiSyslogEvent, error) {
	if len(data) == 0 {
		return UniFiSyslogEvent{}, errors.New("empty syslog message")
	}
	if len(data) > maxUniFiSyslogDatagramBytes {
		return UniFiSyslogEvent{}, errors.New("syslog message exceeds size limit")
	}

	text := strings.TrimRight(string(data), "\x00\r\n")
	if strings.TrimSpace(text) == "" {
		return UniFiSyslogEvent{}, errors.New("blank syslog message")
	}
	priority, rest, err := parseSyslogPriority(text)
	if err != nil {
		return UniFiSyslogEvent{}, err
	}

	event := UniFiSyslogEvent{
		Timestamp: now.UTC(),
		Facility:  priority / 8,
		Severity:  priority % 8,
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return UniFiSyslogEvent{}, errors.New("syslog message has no body")
	}
	if event5424, ok, err := parseRFC5424Syslog(rest, event); ok || err != nil {
		return event5424, err
	}
	return parseRFC3164Syslog(rest, event, now)
}

func parseSyslogPriority(text string) (int, string, error) {
	if !strings.HasPrefix(text, "<") {
		return 0, "", errors.New("syslog priority prefix missing")
	}
	end := strings.IndexByte(text, '>')
	if end < 2 || end > 4 {
		return 0, "", errors.New("invalid syslog priority prefix")
	}
	priority, err := strconv.Atoi(text[1:end])
	if err != nil || priority < 0 || priority > 191 {
		return 0, "", errors.New("invalid syslog priority value")
	}
	return priority, text[end+1:], nil
}

func parseRFC5424Syslog(body string, base UniFiSyslogEvent) (UniFiSyslogEvent, bool, error) {
	fields := strings.SplitN(body, " ", 7)
	if len(fields) < 7 || fields[0] != "1" {
		return UniFiSyslogEvent{}, false, nil
	}
	ts, err := time.Parse(time.RFC3339Nano, fields[1])
	if err != nil {
		return UniFiSyslogEvent{}, true, fmt.Errorf("invalid RFC5424 timestamp: %w", err)
	}
	base.Timestamp = ts.UTC()
	base.Host = dashToEmpty(fields[2])
	base.AppName = dashToEmpty(fields[3])
	base.ProcID = dashToEmpty(fields[4])
	base.MsgID = dashToEmpty(fields[5])
	base.Message = strings.TrimSpace(stripStructuredData(fields[6]))
	if base.Message == "" {
		return UniFiSyslogEvent{}, true, errors.New("RFC5424 message body is empty")
	}
	return base, true, nil
}

func parseRFC3164Syslog(body string, base UniFiSyslogEvent, now time.Time) (UniFiSyslogEvent, error) {
	if len(body) < len("Jan  2 15:04:05 ") {
		return UniFiSyslogEvent{}, errors.New("RFC3164 message too short")
	}
	tsText := body[:15]
	ts, err := time.ParseInLocation("Jan _2 15:04:05", tsText, time.Local)
	if err != nil {
		return UniFiSyslogEvent{}, fmt.Errorf("invalid RFC3164 timestamp: %w", err)
	}
	base.Timestamp = time.Date(now.Year(), ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), 0, now.Location()).UTC()
	rest := strings.TrimSpace(body[15:])
	if rest == "" {
		return UniFiSyslogEvent{}, errors.New("RFC3164 message body is empty")
	}
	host, message, ok := strings.Cut(rest, " ")
	if !ok || strings.TrimSpace(message) == "" {
		return UniFiSyslogEvent{}, errors.New("RFC3164 host or message missing")
	}
	base.Host = host
	base.AppName, base.ProcID, base.Message = splitRFC3164Tag(strings.TrimSpace(message))
	if base.Message == "" {
		return UniFiSyslogEvent{}, errors.New("RFC3164 message body is empty")
	}
	return base, nil
}

func splitRFC3164Tag(message string) (string, string, string) {
	tag, body, ok := strings.Cut(message, ":")
	if !ok {
		return "", "", strings.TrimSpace(message)
	}
	if strings.ContainsFunc(tag, unicode.IsSpace) {
		return "", "", strings.TrimSpace(message)
	}
	tag = strings.TrimSpace(tag)
	body = strings.TrimSpace(body)
	if tag == "" {
		return "", "", body
	}
	if open := strings.IndexByte(tag, '['); open >= 0 && strings.HasSuffix(tag, "]") {
		return tag[:open], strings.TrimSuffix(tag[open+1:], "]"), body
	}
	return tag, "", body
}

func stripStructuredData(rest string) string {
	rest = strings.TrimSpace(rest)
	if rest == "" || rest == "-" {
		return ""
	}
	if rest[0] != '[' {
		if strings.HasPrefix(rest, "- ") {
			return strings.TrimSpace(rest[2:])
		}
		return rest
	}
	depth := 0
	for i, r := range rest {
		switch r {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return strings.TrimSpace(rest[i+1:])
			}
		}
	}
	return ""
}

func dashToEmpty(v string) string {
	if v == "-" {
		return ""
	}
	return v
}
