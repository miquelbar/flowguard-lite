package anomaly

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

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
		if e.profileWatermark.IsZero() || timestamp.Sub(e.profileWatermark) >= 1*time.Minute {
			cutoff := timestamp.Add(-profileStateRetention)
			for deviceIP, profile := range e.deviceProfiles {
				if profile.lastSeen.Before(cutoff) {
					delete(e.deviceProfiles, deviceIP)
				}
			}
		}
		e.profileWatermark = timestamp
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
