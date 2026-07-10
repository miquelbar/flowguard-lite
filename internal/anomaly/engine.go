package anomaly

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/baseline"
	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

const (
	destinationFanoutMin        = 32
	destinationFanoutMaxLimit   = 4096
	portFanoutMin               = 16
	maxFanoutCardinality        = 4096
	maxScanPacketsPerTarget     = 12
	beaconMinObservations       = 6
	beaconMaxObservations       = 12
	beaconMaxSeries             = 8192
	beaconStateRetention        = 2 * time.Hour
	beaconMinInterval           = 30 * time.Second
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
	}
}

// AnalyzeBatch inspects a flushed batch of 1-minute flow events to detect anomalies.
func (e *AnomalyEngine) AnalyzeBatch(ctx context.Context, flowRepo storage.FlowRepository, batch []flow.FlowEvent) {
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
		sqliteRepo, ok := flowRepo.(*storage.SQLiteRepository)
		if !ok {
			continue
		}
		e.checkNewDestinations(ctx, sqliteRepo, ip, m)
	}

	// 3. Track low-volume periodic communication across minute batches.
	e.checkBeaconing(ctx, batch)
}

func (e *AnomalyEngine) checkBeaconing(ctx context.Context, batch []flow.FlowEvent) {
	for _, event := range batch {
		if event.Timestamp.IsZero() ||
			!e.isLocalIP(event.SrcIP) ||
			e.isLocalIP(event.DstIP) ||
			!isFanoutDestination(event.DstIP) ||
			event.DstPort <= 0 ||
			event.Packets == 0 ||
			event.Packets > beaconMaxPackets ||
			event.Bytes > beaconMaxBytes {
			continue
		}

		key := beaconKey{
			srcIP: event.SrcIP, dstIP: event.DstIP,
			dstPort: event.DstPort, protocol: event.Protocol,
		}
		period, jitter, observations, detected := e.observeBeacon(key, event.Timestamp.UTC())
		if !detected {
			continue
		}

		reason := fmt.Sprintf(
			"what happened: device contacted %s:%d over protocol %d on a repeating schedule; why unusual: low-volume communication repeated with stable timing can indicate command-and-control beaconing; baseline used: %d recent observations with maximum tolerated jitter of %.0f%% or %s; current value: %d observations at an average interval of %s with %.1f%% jitter; expected value: irregular timing or an explicitly approved scheduled service; confidence: high; recommended next check: identify the owning process and verify the destination, certificate, DNS history, and scheduled-task configuration",
			key.dstIP, key.dstPort, key.protocol,
			beaconMinObservations, beaconJitterRatio*100, beaconJitterFloor,
			observations, period.Round(time.Second), jitter*100,
		)
		e.triggerAlert(ctx, key.srcIP, "BEACONING", reason, "high")
	}
}

func (e *AnomalyEngine) observeBeacon(key beaconKey, timestamp time.Time) (time.Duration, float64, int, bool) {
	e.beaconMu.Lock()
	defer e.beaconMu.Unlock()

	if timestamp.After(e.beaconWatermark) {
		e.beaconWatermark = timestamp
		e.pruneBeaconsLocked(timestamp.Add(-beaconStateRetention))
	}

	series, exists := e.beacons[key]
	if !exists {
		if len(e.beacons) >= beaconMaxSeries {
			return 0, 0, 0, false
		}
		series = &beaconSeries{}
		e.beacons[key] = series
	}

	index := sort.Search(len(series.observations), func(i int) bool {
		return !series.observations[i].Before(timestamp)
	})
	if index < len(series.observations) && series.observations[index].Equal(timestamp) {
		return 0, 0, len(series.observations), false
	}
	series.observations = append(series.observations, time.Time{})
	copy(series.observations[index+1:], series.observations[index:])
	series.observations[index] = timestamp
	if len(series.observations) > beaconMaxObservations {
		series.observations = series.observations[len(series.observations)-beaconMaxObservations:]
	}
	series.lastSeen = series.observations[len(series.observations)-1]

	if len(series.observations) < beaconMinObservations {
		return 0, 0, len(series.observations), false
	}
	recent := series.observations[len(series.observations)-beaconMinObservations:]
	intervals := make([]time.Duration, 0, len(recent)-1)
	var total time.Duration
	for i := 1; i < len(recent); i++ {
		interval := recent[i].Sub(recent[i-1])
		if interval < beaconMinInterval || interval > beaconMaxInterval {
			return 0, 0, len(recent), false
		}
		intervals = append(intervals, interval)
		total += interval
	}

	mean := total / time.Duration(len(intervals))
	tolerance := time.Duration(float64(mean) * beaconJitterRatio)
	if tolerance < beaconJitterFloor {
		tolerance = beaconJitterFloor
	}
	var maxDeviation time.Duration
	for _, interval := range intervals {
		deviation := interval - mean
		if deviation < 0 {
			deviation = -deviation
		}
		if deviation > maxDeviation {
			maxDeviation = deviation
		}
	}
	if maxDeviation > tolerance {
		return mean, float64(maxDeviation) / float64(mean), len(recent), false
	}
	return mean, float64(maxDeviation) / float64(mean), len(recent), true
}

func (e *AnomalyEngine) pruneBeaconsLocked(cutoff time.Time) {
	for key, series := range e.beacons {
		if series.lastSeen.Before(cutoff) {
			delete(e.beacons, key)
		}
	}
}

func (e *AnomalyEngine) aggregateDeviceMetrics(batch []flow.FlowEvent) map[string]*deviceMetrics {
	metrics := make(map[string]*deviceMetrics)
	for _, f := range batch {
		if !e.isLocalIP(f.SrcIP) {
			continue
		}

		m, ok := metrics[f.SrcIP]
		if !ok {
			m = &deviceMetrics{
				dstIPs:               make(map[string]bool),
				dstPorts:             make(map[int]bool),
				internalDstIPs:       make(map[string]bool),
				portsByDestination:   make(map[string]map[int]bool),
				packetsByDestination: make(map[string]uint64),
				protocols:            make(map[int]bool),
			}
			metrics[f.SrcIP] = m
		}

		m.bytes += f.Bytes
		m.packets += f.Packets
		if len(m.protocols) < 256 {
			m.protocols[f.Protocol] = true
		}
		if f.Timestamp.After(m.timestamp) {
			m.timestamp = f.Timestamp.UTC()
		}
		if isFanoutDestination(f.DstIP) {
			if len(m.dstIPs) < maxFanoutCardinality {
				m.dstIPs[f.DstIP] = true
			} else if !m.dstIPs[f.DstIP] {
				m.dstIPsTruncated = true
			}
		}
		if f.DstIP != f.SrcIP && e.isLocalIP(f.DstIP) && len(m.internalDstIPs) < internalPeerMaxPeers {
			m.internalDstIPs[f.DstIP] = true
		}
		if f.DstPort > 0 && f.DstPort <= 65535 {
			if len(m.dstPorts) < maxFanoutCardinality {
				m.dstPorts[f.DstPort] = true
			}
			ports, exists := m.portsByDestination[f.DstIP]
			if !exists && len(m.portsByDestination) < maxFanoutCardinality {
				ports = make(map[int]bool)
				m.portsByDestination[f.DstIP] = ports
			}
			if ports != nil && len(ports) < maxFanoutCardinality {
				ports[f.DstPort] = true
				m.packetsByDestination[f.DstIP] += f.Packets
			}
		}
	}
	return metrics
}

func (e *AnomalyEngine) checkDeviceProfile(ctx context.Context, ip string, metrics *deviceMetrics) {
	if metrics.timestamp.IsZero() {
		return
	}
	signature := deviceProfileSignature(metrics)
	oldProfile, newProfile, detected := e.observeDeviceProfile(ip, signature, metrics.timestamp)
	if !detected {
		return
	}

	reason := fmt.Sprintf(
		"what happened: device behavior changed persistently from [%s] to [%s]; why unusual: the new coarse protocol/service/peer pattern repeated for %d consecutive one-minute windows after a stable baseline was learned; baseline used: dominant signature in at least %d of %d learning windows; current value: %s; expected value: %s; confidence: high; recommended next check: verify device role, software or firmware changes, newly exposed services, and whether the device identity or ownership changed",
		oldProfile, newProfile, profileConfirmWindows,
		profileDominanceWindows, profileLearningWindows,
		newProfile, oldProfile,
	)
	e.triggerAlert(ctx, ip, "DEVICE_PROFILE_CHANGE", reason, "high")
}

func (e *AnomalyEngine) checkNewInternalCommunication(ctx context.Context, ip string, metrics *deviceMetrics) {
	if metrics.timestamp.IsZero() || len(metrics.internalDstIPs) == 0 {
		return
	}
	destination, detected := e.observeInternalPeer(ip, metrics.internalDstIPs, metrics.timestamp)
	if !detected {
		return
	}

	reason := fmt.Sprintf(
		"what happened: device contacted internal peer %s after its east-west peer set was learned; why unusual: this local-to-local communication pattern was not present in the learned internal peer baseline and repeated for %d consecutive one-minute windows; baseline used: %d learned windows of internal destination peers capped at %d peers; current value: new internal peer %s; expected value: communication only with previously learned internal peers or an explicitly approved local service; confidence: medium; recommended next check: verify whether file sharing, admin access, service discovery, or lateral movement explains this new internal path",
		destination, internalPeerConfirmWindows,
		internalPeerLearningWindows, internalPeerMaxPeers,
		destination,
	)
	e.triggerAlertWithDestination(ctx, ip, destination, "NEW_INTERNAL_COMMUNICATION", reason, "medium")
}

func (e *AnomalyEngine) observeInternalPeer(ip string, peers map[string]bool, timestamp time.Time) (string, bool) {
	e.internalPeerMu.Lock()
	defer e.internalPeerMu.Unlock()

	if timestamp.After(e.internalPeerWatermark) {
		e.internalPeerWatermark = timestamp
		cutoff := timestamp.Add(-internalPeerStateRetention)
		for deviceIP, profile := range e.internalPeerProfiles {
			if profile.lastSeen.Before(cutoff) {
				delete(e.internalPeerProfiles, deviceIP)
			}
		}
	}

	profile, exists := e.internalPeerProfiles[ip]
	if !exists {
		if len(e.internalPeerProfiles) >= internalPeerMaxDevices {
			return "", false
		}
		profile = &internalPeerProfile{
			known:    make(map[string]bool),
			learning: make(map[string]bool),
		}
		e.internalPeerProfiles[ip] = profile
	}

	bucket := timestamp.Truncate(time.Minute).Unix()
	if bucket == profile.lastBucket {
		return "", false
	}
	profile.lastBucket = bucket
	profile.lastSeen = timestamp

	if profile.learningWindows < internalPeerLearningWindows {
		for peer := range peers {
			if len(profile.learning) < internalPeerMaxPeers {
				profile.learning[peer] = true
			}
		}
		profile.learningWindows++
		if profile.learningWindows == internalPeerLearningWindows {
			profile.known = profile.learning
			profile.learning = nil
		}
		return "", false
	}

	unknown := firstUnknownInternalPeer(peers, profile.known)
	if unknown == "" {
		profile.candidate = ""
		profile.candidateWindows = 0
		return "", false
	}
	if unknown != profile.candidate {
		profile.candidate = unknown
		profile.candidateWindows = 1
		return "", false
	}
	profile.candidateWindows++
	if profile.candidateWindows < internalPeerConfirmWindows {
		return "", false
	}
	if len(profile.known) < internalPeerMaxPeers {
		profile.known[unknown] = true
	}
	profile.candidate = ""
	profile.candidateWindows = 0
	return unknown, true
}

func firstUnknownInternalPeer(peers, known map[string]bool) string {
	var unknown []string
	for peer := range peers {
		if !known[peer] {
			unknown = append(unknown, peer)
		}
	}
	sort.Strings(unknown)
	if len(unknown) == 0 {
		return ""
	}
	return unknown[0]
}

func deviceProfileSignature(metrics *deviceMetrics) string {
	protocols := make([]int, 0, len(metrics.protocols))
	for protocol := range metrics.protocols {
		protocols = append(protocols, protocol)
	}
	sort.Ints(protocols)
	protocolNames := make([]string, 0, len(protocols))
	for _, protocol := range protocols {
		switch protocol {
		case 1:
			protocolNames = append(protocolNames, "icmp")
		case 6:
			protocolNames = append(protocolNames, "tcp")
		case 17:
			protocolNames = append(protocolNames, "udp")
		default:
			protocolNames = append(protocolNames, fmt.Sprintf("ip-%d", protocol))
		}
	}
	if len(protocolNames) == 0 {
		protocolNames = append(protocolNames, "none")
	}

	serviceSet := make(map[string]bool)
	for port := range metrics.dstPorts {
		serviceSet[serviceCategory(port)] = true
	}
	services := make([]string, 0, len(serviceSet))
	for service := range serviceSet {
		services = append(services, service)
	}
	sort.Strings(services)
	if len(services) == 0 {
		services = append(services, "none")
	}

	peerBand := "1"
	switch peers := len(metrics.dstIPs); {
	case peers == 0:
		peerBand = "0"
	case peers <= 4:
		peerBand = "1-4"
	case peers <= 15:
		peerBand = "5-15"
	default:
		peerBand = "16+"
	}
	return fmt.Sprintf("protocols=%s services=%s peers=%s",
		strings.Join(protocolNames, ","), strings.Join(services, ","), peerBand)
}

func serviceCategory(port int) string {
	switch port {
	case 53:
		return "dns"
	case 80, 443, 8080, 8443:
		return "web"
	case 22, 23, 3389, 5900:
		return "remote-admin"
	case 25, 110, 143, 465, 587, 993, 995:
		return "mail"
	case 139, 445, 2049:
		return "file-sharing"
	case 1433, 1521, 3306, 5432, 6379, 27017:
		return "database"
	default:
		if port > 0 && port < 1024 {
			return "other-system"
		}
		return "high-port"
	}
}

func (e *AnomalyEngine) observeDeviceProfile(ip, signature string, timestamp time.Time) (string, string, bool) {
	e.profileMu.Lock()
	defer e.profileMu.Unlock()

	if timestamp.After(e.profileWatermark) {
		e.profileWatermark = timestamp
		cutoff := timestamp.Add(-profileStateRetention)
		for deviceIP, profile := range e.deviceProfiles {
			if profile.lastSeen.Before(cutoff) {
				delete(e.deviceProfiles, deviceIP)
			}
		}
	}

	profile, exists := e.deviceProfiles[ip]
	if !exists {
		if len(e.deviceProfiles) >= profileMaxDevices {
			return "", "", false
		}
		profile = &deviceFeatureProfile{learning: make(map[string]uint8)}
		e.deviceProfiles[ip] = profile
	}
	bucket := timestamp.Truncate(time.Minute).Unix()
	if bucket == profile.lastBucket {
		return "", "", false
	}
	profile.lastBucket = bucket
	profile.lastSeen = timestamp

	if profile.baseline == "" {
		if _, exists := profile.learning[signature]; !exists && len(profile.learning) >= profileMaxSignatures {
			return "", "", false
		}
		profile.learning[signature]++
		profile.learningWindows++
		if profile.learningWindows < profileLearningWindows {
			return "", "", false
		}

		var dominant string
		var dominantCount uint8
		for candidate, count := range profile.learning {
			if count > dominantCount || (count == dominantCount && (dominant == "" || candidate < dominant)) {
				dominant, dominantCount = candidate, count
			}
		}
		profile.learning = make(map[string]uint8)
		profile.learningWindows = 0
		if dominantCount >= profileDominanceWindows {
			profile.baseline = dominant
		}
		return "", "", false
	}

	if signature == profile.baseline {
		profile.candidate = ""
		profile.candidateWindows = 0
		return "", "", false
	}
	if signature != profile.candidate {
		profile.candidate = signature
		profile.candidateWindows = 1
		return "", "", false
	}
	profile.candidateWindows++
	if profile.candidateWindows < profileConfirmWindows {
		return "", "", false
	}

	oldProfile := profile.baseline
	profile.baseline = profile.candidate
	profile.candidate = ""
	profile.candidateWindows = 0
	return oldProfile, profile.baseline, true
}

func (e *AnomalyEngine) checkNighttime(ctx context.Context, ip string, metrics *deviceMetrics) {
	if metrics.timestamp.IsZero() {
		return
	}
	localTime := metrics.timestamp.In(e.location)
	hour := localTime.Hour()
	isNight := hour >= nightStartHour && hour < nightEndHour
	isDaytime := hour >= daytimeStartHour && hour < daytimeEndHour
	if !isNight && !isDaytime {
		return
	}
	significant := metrics.bytes >= nightMinBytes ||
		metrics.packets >= nightMinPackets ||
		len(metrics.dstIPs) >= nightMinDestinations
	if !significant {
		return
	}

	daytimeWindows, priorNightWindows := e.observeActivity(ip, metrics.timestamp, isDaytime, isNight)
	if !isNight ||
		daytimeWindows < nightMinDaytimeWindows ||
		priorNightWindows >= nightExpectedWindows {
		return
	}

	reason := fmt.Sprintf(
		"what happened: device generated significant traffic at %s during the configured nighttime window %02d:00-%02d:00; why unusual: its learned in-memory activity profile contains %d distinct daytime windows and only %d prior nighttime windows; baseline used: at least %d daytime windows with fewer than %d prior nighttime windows; current value: %d bytes, %d packets, and %d unique destinations; expected value: no significant activity during nighttime or an explicitly approved overnight schedule; confidence: medium; recommended next check: verify the device owner, scheduled jobs, remote sessions, update tasks, and destination activity",
		localTime.Format("15:04 MST"), nightStartHour, nightEndHour,
		daytimeWindows, priorNightWindows, nightMinDaytimeWindows, nightExpectedWindows,
		metrics.bytes, metrics.packets, len(metrics.dstIPs),
	)
	e.triggerAlert(ctx, ip, "NIGHTTIME_TRAFFIC", reason, "medium")
}

func (e *AnomalyEngine) observeActivity(ip string, timestamp time.Time, isDaytime, isNight bool) (int, int) {
	e.activityMu.Lock()
	defer e.activityMu.Unlock()

	if timestamp.After(e.activityWatermark) {
		e.activityWatermark = timestamp
		cutoff := timestamp.Add(-nightStateRetention)
		for deviceIP, profile := range e.activityProfiles {
			if profile.lastSeen.Before(cutoff) {
				delete(e.activityProfiles, deviceIP)
			}
		}
	}

	profile, exists := e.activityProfiles[ip]
	if !exists {
		if len(e.activityProfiles) >= nightMaxDevices {
			return 0, 0
		}
		profile = &activityProfile{}
		e.activityProfiles[ip] = profile
	}
	profile.lastSeen = timestamp
	bucket := timestamp.Truncate(time.Minute).Unix()
	priorNightWindows := len(profile.nighttimeBuckets)
	if isDaytime {
		profile.daytimeBuckets = appendUniqueBucket(profile.daytimeBuckets, bucket, nightMinDaytimeWindows)
	}
	if isNight {
		profile.nighttimeBuckets = appendUniqueBucket(profile.nighttimeBuckets, bucket, nightExpectedWindows)
	}
	return len(profile.daytimeBuckets), priorNightWindows
}

func appendUniqueBucket(buckets []int64, bucket int64, limit int) []int64 {
	index := sort.Search(len(buckets), func(i int) bool { return buckets[i] >= bucket })
	if index < len(buckets) && buckets[index] == bucket {
		return buckets
	}
	buckets = append(buckets, 0)
	copy(buckets[index+1:], buckets[index:])
	buckets[index] = bucket
	if len(buckets) > limit {
		buckets = buckets[len(buckets)-limit:]
	}
	return buckets
}

func isFanoutDestination(ipString string) bool {
	ip := net.ParseIP(ipString)
	return ip != nil && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback()
}

func (e *AnomalyEngine) checkFanout(ctx context.Context, ip string, m *deviceMetrics) {
	destinationCount := len(m.dstIPs)
	destinationLimit := destinationFanoutMin
	baselineDescription := fmt.Sprintf("absolute minimum of %d unique destinations per one-minute window", destinationFanoutMin)
	confidence := "medium"

	if b := e.baselineEngine.GetCachedBaseline(ip); b != nil {
		statisticalLimit := int(math.Ceil(b.MeanPeers + 3*b.StdDevPeers))
		if statisticalLimit > destinationLimit {
			destinationLimit = statisticalLimit
		}
		if destinationLimit > destinationFanoutMaxLimit {
			destinationLimit = destinationFanoutMaxLimit
		}
		baselineDescription = fmt.Sprintf(
			"device baseline mean %.1f plus 3 standard deviations (%.1f), with threshold %d",
			b.MeanPeers, b.StdDevPeers, destinationLimit,
		)
		confidence = "high"
	}

	if destinationCount >= destinationLimit &&
		m.packets <= uint64(destinationCount*maxScanPacketsPerTarget) {
		current := fmt.Sprintf("%d unique destinations", destinationCount)
		if m.dstIPsTruncated {
			current = fmt.Sprintf("at least %d unique destinations", destinationCount)
		}
		reason := fmt.Sprintf(
			"what happened: device contacted %s in one minute; why unusual: broad low-density fan-out can indicate horizontal scanning; baseline used: %s; current value: %s and %d packets; expected value: fewer than %d unique destinations; confidence: %s; recommended next check: review the destination list and verify whether discovery or inventory software was expected",
			current, baselineDescription, current, m.packets, destinationLimit, confidence,
		)
		e.triggerAlert(ctx, ip, "DESTINATION_FANOUT", reason, "high")
	}

	target, portCount, packetCount := highestPortFanout(m)
	if portCount >= portFanoutMin &&
		packetCount <= uint64(portCount*maxScanPacketsPerTarget) {
		reason := fmt.Sprintf(
			"what happened: device contacted %d unique destination ports on %s in one minute; why unusual: broad low-density port fan-out can indicate vertical port scanning; baseline used: absolute minimum of %d unique ports per destination per one-minute window; current value: %d unique ports and %d packets; expected value: fewer than %d unique ports on one destination; confidence: medium; recommended next check: inspect the target service inventory and confirm whether an authorized vulnerability scan was running",
			portCount, target, portFanoutMin, portCount, packetCount, portFanoutMin,
		)
		e.triggerAlert(ctx, ip, "PORT_FANOUT", reason, "high")
	}
}

func highestPortFanout(m *deviceMetrics) (target string, portCount int, packetCount uint64) {
	for destination, ports := range m.portsByDestination {
		count := len(ports)
		if count > portCount || (count == portCount && count > 0 && (target == "" || destination < target)) {
			target = destination
			portCount = count
			packetCount = m.packetsByDestination[destination]
		}
	}
	return target, portCount, packetCount
}

// isLocalIP checks if an IP is a private local IP based on configuration subnets.
func (e *AnomalyEngine) isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, subnet := range e.localSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// checkNewDestinations queries historical databases to see if IPs or Ports are new.
func (e *AnomalyEngine) checkNewDestinations(ctx context.Context, repo *storage.SQLiteRepository, ip string, m *deviceMetrics) {
	// Look back 7 days
	end := time.Now()
	start := end.AddDate(0, 0, -7)

	dbs, err := repo.GetShardsInRange(start, end)
	if err != nil {
		e.logger.Error("Failed to query historical shards for new destination checks", slog.String("error", err.Error()))
		return
	}

	// Check new destination IPs
	for dstIP := range m.dstIPs {
		// Skip checking if destination IP is private local to focus on external peers
		if e.isLocalIP(dstIP) {
			continue
		}

		found := false
		for _, db := range dbs {
			var count int
			err := db.QueryRowContext(ctx, `
				SELECT COUNT(1) FROM flow_aggregates WHERE src_ip = ? AND dst_ip = ? LIMIT 1
			`, ip, dstIP).Scan(&count)
			if err == nil && count > 0 {
				found = true
				break
			}
		}

		if !found && len(dbs) > 0 {
			reason := fmt.Sprintf(
				"what happened: device contacted external destination IP %s for the first time in the past 7 days; why unusual: the destination was absent from the device's retained aggregate history; baseline used: 7 days of stored flow aggregates for this source/destination pair; current value: destination %s present in this one-minute batch; expected value: destination previously observed or explicitly approved; confidence: medium; recommended next check: verify DNS, certificate, owner, and whether the destination belongs to a new approved service",
				dstIP, dstIP,
			)
			e.triggerAlertWithDestination(ctx, ip, dstIP, "NEW_DESTINATION", reason, "medium")
		}
	}

	// Check new destination ports
	for dstPort := range m.dstPorts {
		found := false
		for _, db := range dbs {
			var count int
			err := db.QueryRowContext(ctx, `
				SELECT COUNT(1) FROM flow_aggregates WHERE src_ip = ? AND dst_port = ? LIMIT 1
			`, ip, dstPort).Scan(&count)
			if err == nil && count > 0 {
				found = true
				break
			}
		}

		if !found && len(dbs) > 0 {
			reason := fmt.Sprintf(
				"what happened: device contacted destination port %d for the first time in the past 7 days; why unusual: the port was absent from the device's retained aggregate history; baseline used: 7 days of stored flow aggregates for this source/port pair; current value: destination port %d present in this one-minute batch; expected value: port previously observed or explicitly approved; confidence: low; recommended next check: verify the application protocol and whether a new service, update, or admin workflow introduced this port",
				dstPort, dstPort,
			)
			e.triggerAlert(ctx, ip, "NEW_PORT", reason, "low")
		}
	}
}

// triggerAlert records the anomaly in database if not deduplicated.
func (e *AnomalyEngine) triggerAlert(ctx context.Context, ip string, alertType string, reason string, severity string) {
	e.triggerAlertWithDestination(ctx, ip, "", alertType, reason, severity)
}

func (e *AnomalyEngine) triggerAlertWithDestination(ctx context.Context, ip string, destinationIP string, alertType string, reason string, severity string) {
	e.mu.Lock()
	dedupKey := fmt.Sprintf("%s|%s", ip, alertType)
	lastTriggered, exists := e.alertDeduplicator[dedupKey]
	now := time.Now()

	// Deduplicate: ignore same alert type for same IP if triggered in the last 15 minutes
	if exists && now.Sub(lastTriggered) < 15*time.Minute {
		e.mu.Unlock()
		return
	}

	e.alertDeduplicator[dedupKey] = now
	e.mu.Unlock()

	e.logger.Warn("Triggering behavioral anomaly alert",
		slog.String("ip", ip),
		slog.String("type", alertType),
		slog.String("reason", reason))

	anom := &storage.Anomaly{
		IP:            ip,
		DestinationIP: destinationIP,
		Type:          alertType,
		Description:   reason,
		Severity:      severity,
		Status:        "active",
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	// Write to database
	go func() {
		dbCtx, dbCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer dbCancel()
		if err := e.repo.SaveAnomaly(dbCtx, anom); err != nil {
			e.logger.Error("Failed to save triggered anomaly into database", slog.String("error", err.Error()))
		}
	}()
}
