package anomaly

import (
	"context"
	"fmt"
	"sort"
	"time"
)

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
