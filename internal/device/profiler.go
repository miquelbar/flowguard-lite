package device

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

type dnsCacheEntry struct {
	hostname  string
	resolved  bool
	checkedAt time.Time
}

// DeviceProfiler inspects traffic flow events, identifies local devices, and resolves hostnames.
type DeviceProfiler struct {
	repo          storage.DeviceRepository
	logger        *slog.Logger
	nextProcessor flow.FlowProcessor

	// Subnet filters
	localSubnets []*net.IPNet

	// Reverse DNS Cache
	dnsMu    sync.RWMutex
	dnsCache map[string]*dnsCacheEntry

	// Workers
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Async lookup channel
	lookupChan chan string
}

// NewDeviceProfiler instantiates a new DeviceProfiler component.
func NewDeviceProfiler(
	repo storage.DeviceRepository,
	logger *slog.Logger,
	subnets []string,
	next flow.FlowProcessor,
) *DeviceProfiler {
	var parsed []*net.IPNet
	for _, cidr := range subnets {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			logger.Error("Failed to parse CIDR configured for local subnet",
				slog.String("cidr", cidr),
				slog.String("error", err.Error()))
			continue
		}
		parsed = append(parsed, ipNet)
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &DeviceProfiler{
		repo:          repo,
		logger:        logger,
		nextProcessor: next,
		localSubnets:  parsed,
		dnsCache:      make(map[string]*dnsCacheEntry),
		ctx:           ctx,
		cancel:        cancel,
		lookupChan:    make(chan string, 1000),
	}

	return p
}

// Start launches the background worker pool for reverse DNS resolution.
func (p *DeviceProfiler) Start() {
	p.logger.Info("Starting Device Profiler...")

	// Spawn 3 background DNS lookup worker threads
	for i := 0; i < 3; i++ {
		p.wg.Add(1)
		go p.dnsLookupWorker()
	}
}

// Shutdown halts the background DNS worker goroutines.
func (p *DeviceProfiler) Shutdown() {
	p.logger.Info("Shutting down Device Profiler...")
	p.cancel()
	close(p.lookupChan)
	p.wg.Wait()
	p.logger.Info("Device Profiler shut down successfully.")
}

// Process implements the flow.FlowProcessor interface to intercept and inspect flow telemetry.
func (p *DeviceProfiler) Process(event *flow.FlowEvent) {
	// 1. Discovery SrcIP if local
	if p.isLocalIP(event.SrcIP) {
		p.discoverDevice(event.SrcIP, event.Timestamp)
	}

	// 2. Discovery DstIP if local
	if p.isLocalIP(event.DstIP) {
		p.discoverDevice(event.DstIP, event.Timestamp)
	}

	// 3. Chain call downstream processor (e.g., flow aggregator)
	if p.nextProcessor != nil {
		p.nextProcessor.Process(event)
	}
}

// isLocalIP checks if an IP is a private local IP based on configuration subnets.
func (p *DeviceProfiler) isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Do not profile loopbacks, multicast, or unspecified IPs
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}

	// Match against configured local subnets
	for _, subnet := range p.localSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}

	return false
}

// discoverDevice registers the device or updates its last seen timestamp.
func (p *DeviceProfiler) discoverDevice(ip string, seenTime time.Time) {
	// First upsert immediately to register IP and last seen (no DNS name block)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		hostname := p.getCachedHostname(ip)
		if err := p.repo.UpsertDevice(ctx, ip, hostname, seenTime); err != nil {
			p.logger.Error("Failed to register discovered device",
				slog.String("ip", ip),
				slog.String("error", err.Error()))
		}
	}()

	// Trigger async reverse DNS lookup check if needed
	p.queueDNSLookup(ip)
}

// queueDNSLookup schedules an IP for reverse DNS lookup check if cache is expired or missing.
func (p *DeviceProfiler) queueDNSLookup(ip string) {
	p.dnsMu.Lock()
	entry, ok := p.dnsCache[ip]
	now := time.Now()

	// If missing, or if checked over 24 hours ago, queue it for lookup
	if !ok || now.Sub(entry.checkedAt) > 24*time.Hour {
		if !ok {
			p.dnsCache[ip] = &dnsCacheEntry{checkedAt: now}
		} else {
			entry.checkedAt = now
		}
		p.dnsMu.Unlock()

		select {
		case p.lookupChan <- ip:
		default:
			// Drop lookup request if queue is full to preserve processor throughput
		}
		return
	}
	p.dnsMu.Unlock()
}

// getCachedHostname returns the cached hostname if present.
func (p *DeviceProfiler) getCachedHostname(ip string) string {
	p.dnsMu.RLock()
	defer p.dnsMu.RUnlock()
	if entry, ok := p.dnsCache[ip]; ok {
		return entry.hostname
	}
	return ""
}

// dnsLookupWorker resolves reverse DNS address names asynchronously.
func (p *DeviceProfiler) dnsLookupWorker() {
	defer p.wg.Done()

	for ip := range p.lookupChan {
		select {
		case <-p.ctx.Done():
			return
		default:
			p.logger.Debug("Resolving reverse DNS for device", slog.String("ip", ip))

			// Perform lookup with context timeout
			resolver := &net.Resolver{}
			ctx, cancel := context.WithTimeout(p.ctx, 3*time.Second)
			names, err := resolver.LookupAddr(ctx, ip)
			cancel()

			var hostname string
			if err == nil && len(names) > 0 {
				hostname = strings.TrimSuffix(names[0], ".")
				p.logger.Debug("Resolved device hostname", slog.String("ip", ip), slog.String("hostname", hostname))
			}

			// Update Cache
			p.dnsMu.Lock()
			entry, ok := p.dnsCache[ip]
			if !ok {
				entry = &dnsCacheEntry{}
				p.dnsCache[ip] = entry
			}
			entry.hostname = hostname
			entry.resolved = (hostname != "")
			entry.checkedAt = time.Now()
			p.dnsMu.Unlock()

			// Update persistent database with the newly resolved hostname
			if hostname != "" {
				dbCtx, dbCancel := context.WithTimeout(context.Background(), 2*time.Second)
				if err := p.repo.UpsertDevice(dbCtx, ip, hostname, time.Now()); err != nil {
					p.logger.Error("Failed updating database with resolved hostname",
						slog.String("ip", ip),
						slog.String("hostname", hostname),
						slog.String("error", err.Error()))
				}
				dbCancel()
			}
		}
	}
}

// UpdateLocalSubnets dynamically re-configures the local subnets list at runtime.
func (p *DeviceProfiler) UpdateLocalSubnets(subnets []string) {
	var parsed []*net.IPNet
	for _, cidr := range subnets {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err == nil {
			parsed = append(parsed, ipNet)
		}
	}
	p.dnsMu.Lock()
	p.localSubnets = parsed
	p.dnsMu.Unlock()
	p.logger.Info("Dynamically updated DeviceProfiler local subnets", slog.Int("count", len(parsed)))
}
