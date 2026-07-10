package suricata

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/storage"
)

// EveAlert holds specific Suricata threat signature alert fields.
type EveAlert struct {
	SignatureID uint32 `json:"signature_id"`
	Signature   string `json:"signature"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
}

// EveEvent represents a parsed EVE JSON line from Suricata eve.json.
type EveEvent struct {
	Timestamp string    `json:"timestamp"`
	EventType string    `json:"event_type"`
	SrcIP     string    `json:"src_ip"`
	DestIP    string    `json:"dest_ip"`
	Alert     *EveAlert `json:"alert"`
}

// Tailer reads and tails a Suricata eve.json log file to register alerts.
type Tailer struct {
	repo         storage.DeviceRepository
	logger       *slog.Logger
	filePath     string
	localSubnets []*net.IPNet

	// Control channels
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Deduplication cache
	mu                sync.Mutex
	alertDeduplicator map[string]time.Time
}

// NewTailer creates a new Suricata log tailing agent.
func NewTailer(
	repo storage.DeviceRepository,
	logger *slog.Logger,
	filePath string,
	subnets []string,
) *Tailer {
	var parsed []*net.IPNet
	for _, cidr := range subnets {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			logger.Error("Failed to parse local subnet CIDR in Suricata tailer",
				slog.String("cidr", cidr),
				slog.String("error", err.Error()))
			continue
		}
		parsed = append(parsed, ipNet)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Tailer{
		repo:              repo,
		logger:            logger,
		filePath:          filePath,
		localSubnets:      parsed,
		alertDeduplicator: make(map[string]time.Time),
		ctx:               ctx,
		cancel:            cancel,
	}
}

// Start spawns the tailing background loop.
func (t *Tailer) Start() {
	if t.filePath == "" {
		t.logger.Info("Suricata eve.json path is not configured. Tailer is disabled.")
		return
	}

	t.logger.Info("Starting Suricata eve.json tail worker...", slog.String("path", t.filePath))
	t.wg.Add(1)
	go t.tailLoop()
}

// Shutdown stops the tail worker cleanly.
func (t *Tailer) Shutdown() {
	if t.filePath == "" {
		return
	}

	t.logger.Info("Shutting down Suricata eve.json tail worker...")
	t.cancel()
	t.wg.Wait()
	t.logger.Info("Suricata eve.json tail worker shut down successfully.")
}

// tailLoop handles file open, reading, EOF checking, and rotation.
func (t *Tailer) tailLoop() {
	defer t.wg.Done()

	var file *os.File
	var reader *bufio.Reader
	var offset int64

	// Open initial file (retry periodically if it doesn't exist yet)
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		f, err := os.Open(t.filePath)
		if err != nil {
			t.logger.Debug("Waiting for Suricata eve.json file to be created...", slog.String("path", t.filePath))
			time.Sleep(2 * time.Second)
			continue
		}

		// Seek to end of file on startup to avoid processing massive old backlogs
		fi, err := f.Stat()
		if err == nil {
			offset = fi.Size()
			_, _ = f.Seek(offset, io.SeekStart)
		}

		file = f
		reader = bufio.NewReader(file)
		break
	}

	defer func() {
		if file != nil {
			file.Close()
		}
	}()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			// Read all new lines
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					if errors.Is(err, io.EOF) {
						// Check for log rotation
						fi, statErr := os.Stat(t.filePath)
						if statErr == nil {
							// If file is truncated (size is smaller than current offset), reopen it
							if fi.Size() < offset {
								t.logger.Info("Suricata eve.json log rotation detected. Reopening file.")
								file.Close()
								f, openErr := os.Open(t.filePath)
								if openErr == nil {
									file = f
									reader = bufio.NewReader(file)
									offset = 0
								}
							}
						}
						break // Exit inner loop to wait on next tick
					}
					t.logger.Error("Error reading eve.json line", slog.String("error", err.Error()))
					break
				}

				// Update offset
				offset += int64(len(line))
				t.processLine(line)
			}
		}
	}
}

// processLine parses a single eve.json log line and flags alerts.
func (t *Tailer) processLine(line string) {
	if line == "" {
		return
	}

	var event EveEvent
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		return // Skip malformed JSON lines
	}

	// Filter to only capture security alerts
	if event.EventType != "alert" || event.Alert == nil {
		return
	}

	// Locate if local device is involved (victim or attacker)
	localIP := ""
	if t.isLocalIP(event.DestIP) {
		localIP = event.DestIP
	} else if t.isLocalIP(event.SrcIP) {
		localIP = event.SrcIP
	}

	if localIP == "" {
		return // Ignore alerts that do not touch local subnets
	}

	// Convert Suricata severity (1 = high, 2 = medium, 3 = low) to internal status
	severity := "medium"
	switch event.Alert.Severity {
	case 1:
		severity = "high"
	case 2:
		severity = "medium"
	case 3:
		severity = "low"
	}

	// Format description explaining what occurred
	description := fmt.Sprintf("IDS Alert: %s (Category: %s, Signature ID: %d)",
		event.Alert.Signature, event.Alert.Category, event.Alert.SignatureID)

	t.triggerAlert(localIP, "SURICATA_ALERT", description, severity, event.Alert.SignatureID)
}

// isLocalIP checks if an IP is within the configured subnets.
func (t *Tailer) isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, subnet := range t.localSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// triggerAlert records the alert to database if not deduplicated.
func (t *Tailer) triggerAlert(ip string, alertType string, reason string, severity string, sigID uint32) {
	t.mu.Lock()
	dedupKey := fmt.Sprintf("%s|%d", ip, sigID)
	lastTriggered, exists := t.alertDeduplicator[dedupKey]
	now := time.Now()

	// Deduplicate: ignore similar IDS alert for same IP within 15 minutes
	if exists && now.Sub(lastTriggered) < 15*time.Minute {
		t.mu.Unlock()
		return
	}

	t.alertDeduplicator[dedupKey] = now
	t.mu.Unlock()

	t.logger.Warn("Triggering Suricata IDS alert",
		slog.String("ip", ip),
		slog.Uint64("sig_id", uint64(sigID)),
		slog.String("reason", reason))

	anom := &storage.Anomaly{
		IP:          ip,
		Type:        alertType,
		Description: reason,
		Severity:    severity,
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Write to database
	go func() {
		dbCtx, dbCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer dbCancel()
		if err := t.repo.SaveAnomaly(dbCtx, anom); err != nil {
			t.logger.Error("Failed to save triggered Suricata anomaly to database", slog.String("error", err.Error()))
		}
	}()
}
