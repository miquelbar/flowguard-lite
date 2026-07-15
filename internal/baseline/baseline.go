package baseline

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/storage"
)

// BaselineEngine manages calculation of historical device baselines and anomaly checks.
type BaselineEngine struct {
	repo   storage.DeviceRepository
	logger *slog.Logger

	// Subnet or helper configs
	minBytesThreshold   uint64
	minPacketsThreshold uint64
	minPeersThreshold   int

	mu              sync.RWMutex
	cachedBaselines map[string]*storage.DeviceBaseline
}

// NewBaselineEngine instantiates a new BaselineEngine.
func NewBaselineEngine(repo storage.DeviceRepository, logger *slog.Logger) *BaselineEngine {
	return &BaselineEngine{
		repo:                repo,
		logger:              logger,
		minBytesThreshold:   1024 * 1024, // 1MB minimum to trigger bytes anomaly
		minPacketsThreshold: 2500,        // 2500 packets/min minimum to trigger packets anomaly
		minPeersThreshold:   25,          // 25 peers/min minimum to trigger peer count anomaly
		cachedBaselines:     make(map[string]*storage.DeviceBaseline),
	}
}

// LoadBaselines fetches all persisted baselines from database into cache.
func (e *BaselineEngine) LoadBaselines(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	devices, err := e.repo.ListDevices(ctx)
	if err != nil {
		return err
	}

	for _, dev := range devices {
		b, err := e.repo.GetBaseline(ctx, dev.IP)
		if err != nil {
			e.logger.Warn("Failed to fetch baseline for device", slog.String("ip", dev.IP), slog.String("error", err.Error()))
			continue
		}
		if b != nil {
			e.cachedBaselines[dev.IP] = b
		}
	}

	e.logger.Info("Loaded device baselines into cache", slog.Int("count", len(e.cachedBaselines)))
	return nil
}

// GetCachedBaseline returns the active cached baseline for the given IP.
func (e *BaselineEngine) GetCachedBaseline(ip string) *storage.DeviceBaseline {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cachedBaselines[ip]
}

// CalculateBaselines scans retained flow aggregate history and recalculates statistical metrics for all devices.
func (e *BaselineEngine) CalculateBaselines(ctx context.Context, flowRepo storage.BaselineSampleRepository) error {
	devices, err := e.repo.ListDevices(ctx)
	if err != nil {
		return err
	}

	e.logger.Info("Recalculating baselines for discovered devices...", slog.Int("devices", len(devices)))

	// Check the past 7 days of daily shards
	end := time.Now()
	start := end.AddDate(0, 0, -7)

	for _, dev := range devices {
		// Calculate metrics over historical database shards
		baseline, err := e.computeDeviceBaseline(ctx, flowRepo, dev.IP, start, end)
		if err != nil {
			e.logger.Warn("Failed computing baseline statistics", slog.String("ip", dev.IP), slog.String("error", err.Error()))
			continue
		}

		if baseline == nil {
			// Not enough data samples (needs at least 5 active minutes)
			continue
		}

		// Save to persistent database
		if err := e.repo.SaveBaseline(ctx, baseline); err != nil {
			e.logger.Error("Failed to save calculated baseline", slog.String("ip", dev.IP), slog.String("error", err.Error()))
			continue
		}

		// Update Cache
		e.mu.Lock()
		e.cachedBaselines[dev.IP] = baseline
		e.mu.Unlock()

		e.logger.Info("Calculated new device baseline",
			slog.String("ip", dev.IP),
			slog.Float64("mean_bytes", baseline.MeanBytes),
			slog.Float64("stddev_bytes", baseline.StdDevBytes))
	}

	return nil
}

// IsAnomaly checks if current minute traffic for a device is a statistical outlier.
func (e *BaselineEngine) IsAnomaly(ip string, bytesVal uint64, packetsVal uint64, peersVal int) (bool, string) {
	b := e.GetCachedBaseline(ip)
	if b == nil {
		return false, ""
	}

	// 1. Check Bytes Outlier
	if bytesVal > e.minBytesThreshold {
		limit := b.MeanBytes + (3 * b.StdDevBytes)
		if float64(bytesVal) > limit {
			reason := fmt.Sprintf("traffic volume of %d bytes exceeded statistical limit of %.0f bytes (mean: %.0f, stddev: %.0f)",
				bytesVal, limit, b.MeanBytes, b.StdDevBytes)
			return true, reason
		}
	}

	// 2. Check Packets Outlier
	if packetsVal > e.minPacketsThreshold {
		limit := b.MeanPackets + (3 * b.StdDevPackets)
		if float64(packetsVal) > limit {
			reason := fmt.Sprintf("packet count of %d packets exceeded statistical limit of %.0f packets (mean: %.0f, stddev: %.0f)",
				packetsVal, limit, b.MeanPackets, b.StdDevPackets)
			return true, reason
		}
	}

	// 3. Check Peers Outlier
	if peersVal > e.minPeersThreshold {
		limit := b.MeanPeers + (3 * b.StdDevPeers)
		if float64(peersVal) > limit {
			reason := fmt.Sprintf("unique contacting peers of %d exceeded statistical limit of %.0f (mean: %.0f, stddev: %.0f)",
				peersVal, limit, b.MeanPeers, b.StdDevPeers)
			return true, reason
		}
	}

	return false, ""
}

// computeDeviceBaseline queries retained aggregate history and computes Mean and StdDev.
func (e *BaselineEngine) computeDeviceBaseline(
	ctx context.Context,
	flowRepo storage.BaselineSampleRepository,
	ip string,
	start, end time.Time,
) (*storage.DeviceBaseline, error) {
	if flowRepo == nil {
		return nil, fmt.Errorf("flow repository is not configured")
	}

	samples, err := flowRepo.GetDeviceBaselineSamples(ctx, ip, start, end)
	if err != nil {
		return nil, err
	}

	if len(samples) < 5 {
		// Not enough traffic samples to construct a reliable baseline profile
		return nil, nil
	}

	bytesSamples := make([]float64, 0, len(samples))
	packetsSamples := make([]float64, 0, len(samples))
	peersSamples := make([]float64, 0, len(samples))
	for _, sample := range samples {
		bytesSamples = append(bytesSamples, sample.Bytes)
		packetsSamples = append(packetsSamples, sample.Packets)
		peersSamples = append(peersSamples, sample.Peers)
	}

	// Calculate Means
	meanBytes := calcMean(bytesSamples)
	meanPackets := calcMean(packetsSamples)
	meanPeers := calcMean(peersSamples)

	// Calculate Standard Deviations
	stdDevBytes := calcStdDev(bytesSamples, meanBytes)
	stdDevPackets := calcStdDev(packetsSamples, meanPackets)
	stdDevPeers := calcStdDev(peersSamples, meanPeers)

	return &storage.DeviceBaseline{
		IP:            ip,
		MeanBytes:     meanBytes,
		StdDevBytes:   stdDevBytes,
		MeanPackets:   meanPackets,
		StdDevPackets: stdDevPackets,
		MeanPeers:     meanPeers,
		StdDevPeers:   stdDevPeers,
		UpdatedAt:     time.Now(),
	}, nil
}

// calcMean helper
func calcMean(samples []float64) float64 {
	var sum float64
	for _, val := range samples {
		sum += val
	}
	return sum / float64(len(samples))
}

// calcStdDev helper
func calcStdDev(samples []float64, mean float64) float64 {
	var sumSquares float64
	for _, val := range samples {
		diff := val - mean
		sumSquares += diff * diff
	}
	variance := sumSquares / float64(len(samples))
	return math.Sqrt(variance)
}
