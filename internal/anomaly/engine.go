package anomaly

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/baseline"
	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

const (
	destinationFanoutMin        = 32
	destinationFanoutMaxLimit   = 4096
	portFanoutMin               = 16
	maxFanoutCardinality        = 4096
	maxScanPacketsPerTarget     = 12
	beaconMinObservations       = 12
	beaconMaxObservations       = 18
	beaconMaxSeries             = 8192
	beaconStateRetention        = 2 * time.Hour
	beaconMinInterval           = 90 * time.Second
	beaconMaxInterval           = 30 * time.Minute
	beaconJitterRatio           = 0.20
	beaconJitterFloor           = 20 * time.Second
	beaconMaxPackets            = 20
	beaconMaxBytes              = 64 * 1024
	nightMinDaytimeWindows      = 12
	nightExpectedWindows        = 3
	nightMaxDevices             = 4096
	nightStateRetention         = 14 * 24 * time.Hour
	nightStartHour              = 0
	nightEndHour                = 5
	daytimeStartHour            = 7
	daytimeEndHour              = 23
	nightMinBytes               = 128 * 1024
	nightMinPackets             = 100
	nightMinDestinations        = 5
	profileLearningWindows      = 12
	profileDominanceWindows     = 9
	profileConfirmWindows       = 3
	profileMaxDevices           = 4096
	profileMaxSignatures        = 8
	profileStateRetention       = 14 * 24 * time.Hour
	internalPeerLearningWindows = 12
	internalPeerConfirmWindows  = 2
	internalPeerMaxDevices      = 4096
	internalPeerMaxPeers        = 256
	internalPeerStateRetention  = 14 * 24 * time.Hour
)

type deviceMetrics struct {
	bytes                uint64
	packets              uint64
	dstIPs               map[string]bool
	dstPorts             map[int]bool
	dstIPByPort          map[int]string
	internalDstIPs       map[string]bool
	portsByDestination   map[string]map[int]bool
	packetsByDestination map[string]uint64
	protocols            map[int]bool
	dstIPsTruncated      bool
	timestamp            time.Time
}

type beaconKey struct {
	srcIP    string
	dstIP    string
	dstPort  int
	protocol int
}

type beaconSeries struct {
	observations []time.Time
	lastSeen     time.Time
}

type activityProfile struct {
	daytimeBuckets   []int64
	nighttimeBuckets []int64
	lastSeen         time.Time
}

type deviceFeatureProfile struct {
	baseline         string
	learning         map[string]uint8
	learningWindows  uint8
	candidate        string
	candidateWindows uint8
	lastBucket       int64
	lastSeen         time.Time
}

type internalPeerProfile struct {
	known            map[string]bool
	learning         map[string]bool
	learningWindows  uint8
	candidate        string
	candidateWindows uint8
	lastBucket       int64
	lastSeen         time.Time
}

type detectionControls struct {
	disabledTypes                   map[string]bool
	mutedSubnets                    []*net.IPNet
	newDestinationMinHistoryBuckets int
	beaconMinObservations           int
	beaconMinInterval               time.Duration
}

// AnomalyEngine processes aggregated flows to detect traffic spikes, new ports, and new destinations.
type AnomalyEngine struct {
	repo           storage.DeviceRepository
	logger         *slog.Logger
	baselineEngine *baseline.BaselineEngine

	// Local network subnet matchers (to identify local source devices)
	localSubnets []*net.IPNet

	// In-memory cache to deduplicate alerts triggered in the last 15 minutes
	mu                sync.Mutex
	alertDeduplicator map[string]time.Time

	controlsMu sync.RWMutex
	controls   detectionControls

	beaconMu        sync.Mutex
	beacons         map[beaconKey]*beaconSeries
	beaconWatermark time.Time

	activityMu        sync.Mutex
	activityProfiles  map[string]*activityProfile
	activityWatermark time.Time
	location          *time.Location

	profileMu        sync.Mutex
	deviceProfiles   map[string]*deviceFeatureProfile
	profileWatermark time.Time

	internalPeerMu        sync.Mutex
	internalPeerProfiles  map[string]*internalPeerProfile
	internalPeerWatermark time.Time
}

// NewAnomalyEngine instantiates a new AnomalyEngine.
func NewAnomalyEngine(
	repo storage.DeviceRepository,
	logger *slog.Logger,
	baseEngine *baseline.BaselineEngine,
	subnets []string,
) *AnomalyEngine {
	var parsed []*net.IPNet
	for _, cidr := range subnets {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			logger.Error("Failed to parse CIDR configured for local subnet in anomaly engine",
				slog.String("cidr", cidr),
				slog.String("error", err.Error()))
			continue
		}
		parsed = append(parsed, ipNet)
	}

	return &AnomalyEngine{
		repo:                 repo,
		logger:               logger,
		baselineEngine:       baseEngine,
		localSubnets:         parsed,
		alertDeduplicator:    make(map[string]time.Time),
		beacons:              make(map[beaconKey]*beaconSeries),
		activityProfiles:     make(map[string]*activityProfile),
		location:             time.Local,
		deviceProfiles:       make(map[string]*deviceFeatureProfile),
		internalPeerProfiles: make(map[string]*internalPeerProfile),
		controls: detectionControls{
			disabledTypes:                   make(map[string]bool),
			newDestinationMinHistoryBuckets: minNewDestinationHistoryBuckets,
			beaconMinObservations:           beaconMinObservations,
			beaconMinInterval:               beaconMinInterval,
		},
	}
}

// UpdateConfig applies runtime detection controls from daemon configuration.
func (e *AnomalyEngine) UpdateConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	controls := detectionControls{
		disabledTypes:                   make(map[string]bool),
		newDestinationMinHistoryBuckets: cfg.NewDestinationMinHistoryBuckets,
		beaconMinObservations:           cfg.BeaconMinObservations,
		beaconMinInterval:               time.Duration(cfg.BeaconMinIntervalSeconds) * time.Second,
	}
	for _, item := range cfg.DisabledAnomalyTypes {
		controls.disabledTypes[item] = true
	}
	for _, cidr := range cfg.MutedAnomalySubnets {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			controls.mutedSubnets = append(controls.mutedSubnets, ipNet)
		}
	}
	if controls.newDestinationMinHistoryBuckets <= 0 {
		controls.newDestinationMinHistoryBuckets = minNewDestinationHistoryBuckets
	}
	if controls.beaconMinObservations <= 0 {
		controls.beaconMinObservations = beaconMinObservations
	}
	if controls.beaconMinInterval <= 0 {
		controls.beaconMinInterval = beaconMinInterval
	}
	e.controlsMu.Lock()
	e.controls = controls
	e.controlsMu.Unlock()
}

// AnalyzeBatch inspects a flushed batch of 1-minute flow events to detect anomalies.
func (e *AnomalyEngine) AnalyzeBatch(ctx context.Context, flowRepo storage.FlowHistoryRepository, batch []flow.FlowEvent) {
	if len(batch) == 0 {
		return
	}

	// 1. Group bounded metrics by local source IP.
	metrics := e.aggregateDeviceMetrics(batch)

	// 2. Process each local device
	for ip, m := range metrics {
		// A. Check abnormal byte/packet volume. Peer cardinality is handled by
		// the dedicated fan-out detector below to avoid duplicate alert types.
		if ok, reason := e.baselineEngine.IsAnomaly(ip, m.bytes, m.packets, 0); ok {
			e.triggerAlert(ctx, ip, "TRAFFIC_SPIKE", reason, "high")
		}

		// B. Detect horizontal destination scans and vertical port scans.
		e.checkFanout(ctx, ip, m)

		// C. Detect activity that is unexpected for a learned daytime device.
		e.checkNighttime(ctx, ip, m)

		// D. Detect stable, persistent changes in coarse device behavior.
		e.checkDeviceProfile(ctx, ip, m)

		// E. Detect new local east-west communication after peer learning.
		e.checkNewInternalCommunication(ctx, ip, m)

		// F. Check for new destination IPs and Ports.
		if flowRepo == nil {
			continue
		}
		e.checkNewDestinations(ctx, flowRepo, ip, m)
	}

	// 3. Track low-volume periodic communication across minute batches.
	e.checkBeaconing(ctx, batch)
}
