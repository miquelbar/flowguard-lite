package ddos

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"strings"

	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

// DeviceRates tracks packet and byte counters atomically inside the sliding window.
type DeviceRates struct {
	PacketsIn     uint64
	BytesIn       uint64
	SYNPacketsIn  uint64
	UDPPacketsIn  uint64
	ICMPPacketsIn uint64
}

// DDoSDetector monitors real-time packet/byte rates to identify volumetric floods.
type DDoSDetector struct {
	repo          storage.DeviceRepository
	logger        *slog.Logger
	cfg           *config.Config
	nextProcessor flow.FlowProcessor

	// Subnet lists for matching victims
	localSubnets []*net.IPNet

	// In-memory atomic device counters map
	mu    sync.RWMutex
	rates map[string]*DeviceRates

	// Goroutine lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Alert deduplicator cache
	alertMu           sync.Mutex
	alertDeduplicator map[string]time.Time
}

// NewDDoSDetector instantiates a new DDoSDetector agent.
func NewDDoSDetector(
	repo storage.DeviceRepository,
	logger *slog.Logger,
	cfg *config.Config,
	next flow.FlowProcessor,
) *DDoSDetector {
	var parsed []*net.IPNet
	for _, cidr := range cfg.LocalSubnets {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			logger.Error("Failed to parse local subnet CIDR in DDoS detector",
				slog.String("cidr", cidr),
				slog.String("error", err.Error()))
			continue
		}
		parsed = append(parsed, ipNet)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &DDoSDetector{
		repo:              repo,
		logger:            logger,
		cfg:               cfg,
		nextProcessor:     next,
		localSubnets:      parsed,
		rates:             make(map[string]*DeviceRates),
		alertDeduplicator: make(map[string]time.Time),
		ctx:               ctx,
		cancel:            cancel,
	}
}

// Start launches the background ticker thread evaluating traffic rates every 5 seconds.
func (d *DDoSDetector) Start() {
	d.logger.Info("Starting DDoS Volumetric Detection engine...")
	d.wg.Add(1)
	go d.monitorRatesLoop()
}

// Shutdown stops the background ticker thread safely.
func (d *DDoSDetector) Shutdown() {
	d.logger.Info("Shutting down DDoS Detection engine...")
	d.cancel()
	d.wg.Wait()
	d.logger.Info("DDoS Detection engine shut down successfully.")
}

// Process implements the flow.FlowProcessor interface to aggregate incoming traffic metrics.
func (d *DDoSDetector) Process(event *flow.FlowEvent) {
	// Identify if the destination IP is a local network device (DDoS victim)
	if d.isLocalIP(event.DstIP) {
		d.accumulateRates(event.DstIP, event)
	}

	// Forward flows downstream to subsequent processors (e.g. DeviceProfiler)
	if d.nextProcessor != nil {
		d.nextProcessor.Process(event)
	}
}

// isLocalIP checks if an IP matches configured subnets.
func (d *DDoSDetector) isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, subnet := range d.localSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// accumulateRates increments the atomic counters for the target IP address.
func (d *DDoSDetector) accumulateRates(ip string, event *flow.FlowEvent) {
	// Read lock to fetch existing rates
	d.mu.RLock()
	r, exists := d.rates[ip]
	d.mu.RUnlock()

	if !exists {
		// Write lock to initialize rates map entry
		d.mu.Lock()
		r, exists = d.rates[ip]
		if !exists {
			r = &DeviceRates{}
			d.rates[ip] = r
		}
		d.mu.Unlock()
	}

	// Atomic additions for high speed concurrent safety
	atomic.AddUint64(&r.PacketsIn, event.Packets)
	atomic.AddUint64(&r.BytesIn, event.Bytes)

	// TCP SYN Flag check (SYN=0x02, SYN-ACK=0x12)
	// Let's check if protocol is TCP (6) and flags contain SYN (0x02) and not ACK (0x10) to count SYN packets
	if event.Protocol == 6 && (event.TCPFlags&0x02) != 0 && (event.TCPFlags&0x10) == 0 {
		atomic.AddUint64(&r.SYNPacketsIn, event.Packets)
	}

	// UDP check (17)
	if event.Protocol == 17 {
		atomic.AddUint64(&r.UDPPacketsIn, event.Packets)
	}

	// ICMP check (1 or 58 for IPv6)
	if event.Protocol == 1 || event.Protocol == 58 {
		atomic.AddUint64(&r.ICMPPacketsIn, event.Packets)
	}
}

// monitorRatesLoop periodically evaluates atomic counters every 5 seconds.
func (d *DDoSDetector) monitorRatesLoop() {
	defer d.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.evaluateRates()
		}
	}
}

// evaluateRates checks rates against configured flood thresholds and resets counters.
func (d *DDoSDetector) evaluateRates() {
	d.mu.Lock()
	// Clone current states to evaluate offline without holding lock
	ratesSnapshot := make(map[string]DeviceRates)
	for ip, r := range d.rates {
		ratesSnapshot[ip] = DeviceRates{
			PacketsIn:     atomic.SwapUint64(&r.PacketsIn, 0),
			BytesIn:       atomic.SwapUint64(&r.BytesIn, 0),
			SYNPacketsIn:  atomic.SwapUint64(&r.SYNPacketsIn, 0),
			UDPPacketsIn:  atomic.SwapUint64(&r.UDPPacketsIn, 0),
			ICMPPacketsIn: atomic.SwapUint64(&r.ICMPPacketsIn, 0),
		}
	}
	d.mu.Unlock()

	for ip, r := range ratesSnapshot {
		// Calculate rates per second over the 5-second interval
		pps := r.PacketsIn / 5
		bps := r.BytesIn / 5
		synPps := r.SYNPacketsIn / 5
		udpPps := r.UDPPacketsIn / 5
		icmpPps := r.ICMPPacketsIn / 5

		// Check global volumetric PPS
		if pps > uint64(d.cfg.DDoSThresholdPPS) {
			reason := fmt.Sprintf("Victim receiving high traffic rate of %d PPS, exceeding threshold limit of %d PPS", pps, d.cfg.DDoSThresholdPPS)
			d.triggerAlert(ip, "DDOS_ATTACK", reason, "high")
		}

		// Check global volumetric BPS
		if bps > uint64(d.cfg.DDoSThresholdBPS) {
			reason := fmt.Sprintf("Victim receiving high bandwidth rate of %d B/s, exceeding threshold limit of %d B/s", bps, d.cfg.DDoSThresholdBPS)
			d.triggerAlert(ip, "DDOS_ATTACK", reason, "high")
		}

		// Check TCP SYN Flood
		if synPps > uint64(d.cfg.SYNFloodThresholdPPS) {
			reason := fmt.Sprintf("Victim receiving high TCP SYN rate of %d PPS, indicating SYN flood attack (threshold limit: %d PPS)", synPps, d.cfg.SYNFloodThresholdPPS)
			d.triggerAlert(ip, "DDOS_SYN_FLOOD", reason, "high")
		}

		// Check UDP Flood
		if udpPps > uint64(d.cfg.UDPFloodThresholdPPS) {
			reason := fmt.Sprintf("Victim receiving high UDP rate of %d PPS, indicating UDP flood/amplification attack (threshold limit: %d PPS)", udpPps, d.cfg.UDPFloodThresholdPPS)
			d.triggerAlert(ip, "DDOS_UDP_FLOOD", reason, "high")
		}

		// Check ICMP Flood
		if icmpPps > uint64(d.cfg.ICMPFloodThresholdPPS) {
			reason := fmt.Sprintf("Victim receiving high ICMP rate of %d PPS, indicating ICMP ping storm (threshold limit: %d PPS)", icmpPps, d.cfg.ICMPFloodThresholdPPS)
			d.triggerAlert(ip, "DDOS_ICMP_FLOOD", reason, "high")
		}
	}
}

// triggerAlert registers the DDoS anomaly in the database.
func (d *DDoSDetector) triggerAlert(ip string, alertType string, reason string, severity string) {
	d.alertMu.Lock()
	dedupKey := fmt.Sprintf("%s|%s", ip, alertType)
	lastTriggered, exists := d.alertDeduplicator[dedupKey]
	now := time.Now()

	// Deduplicate: ignore if triggered in the last 10 minutes to avoid flood clutter
	if exists && now.Sub(lastTriggered) < 10*time.Minute {
		d.alertMu.Unlock()
		return
	}

	d.alertDeduplicator[dedupKey] = now
	d.alertMu.Unlock()

	d.logger.Warn("Triggering DDoS Anomaly alert",
		slog.String("ip", ip),
		slog.String("type", alertType),
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

	// Write to database asynchronously
	go func() {
		dbCtx, dbCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer dbCancel()
		if err := d.repo.SaveAnomaly(dbCtx, anom); err != nil {
			d.logger.Error("Failed saving triggered DDoS anomaly into database", slog.String("error", err.Error()))
		}
	}()
}

// UpdateLocalSubnets dynamically re-configures the local subnets list at runtime.
func (d *DDoSDetector) UpdateLocalSubnets(subnets []string) {
	var parsed []*net.IPNet
	for _, cidr := range subnets {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err == nil {
			parsed = append(parsed, ipNet)
		}
	}
	d.mu.Lock()
	d.localSubnets = parsed
	d.mu.Unlock()
	d.logger.Info("Dynamically updated DDoSDetector local subnets", slog.Int("count", len(parsed)))
}
