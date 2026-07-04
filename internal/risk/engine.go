package risk

import (
	"context"
	"math"
	"sort"
	"time"

	"github.com/flowguard/flowguard/internal/storage"
)

// EvidenceRef represents an individual security event contributing to the device's threat level.
type EvidenceRef struct {
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}

// DeviceRisk represents a computed security threat score, classification level, and supporting evidence.
type DeviceRisk struct {
	IP               string        `json:"ip"`
	Label            string        `json:"label"`
	Hostname         string        `json:"hostname"`
	RiskScore        int           `json:"risk_score"`
	RiskLevel        string        `json:"risk_level"` // "low", "medium", "high"
	ActiveAlertCount int           `json:"active_alert_count"`
	Explanations     []string      `json:"explanations"`
	Evidence         []EvidenceRef `json:"evidence"`
}

// RiskEngine handles threat scoring, temporal alert decay, and multi-source event correlation.
type RiskEngine struct {
	repo storage.DeviceRepository
}

// NewRiskEngine instantiates a new RiskEngine.
func NewRiskEngine(repo storage.DeviceRepository) *RiskEngine {
	return &RiskEngine{repo: repo}
}

// CalculateDeviceRisks queries active anomalies over the past 24 hours, correlates multiple sources, and compiles the ranking list.
func (e *RiskEngine) CalculateDeviceRisks(ctx context.Context) ([]DeviceRisk, error) {
	devices, err := e.repo.ListDevices(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	since := now.Add(-24 * time.Hour)

	activeAnomalies, err := e.repo.GetActiveAnomalies(ctx, since)
	if err != nil {
		return nil, err
	}

	// Map IP address -> active anomalies
	deviceAnomalies := make(map[string][]storage.Anomaly)
	for _, a := range activeAnomalies {
		deviceAnomalies[a.IP] = append(deviceAnomalies[a.IP], a)
	}

	var results []DeviceRisk

	for _, d := range devices {
		anoms, exists := deviceAnomalies[d.IP]
		if !exists || len(anoms) == 0 {
			continue
		}

		var rawScore float64
		var explanations []string
		var evidence []EvidenceRef

		var hasSuricata bool
		var hasFlowAnomaly bool
		var suricataTimes []time.Time
		var flowAnomalyTimes []time.Time

		for _, a := range anoms {
			// Determine base severity weight
			weight := 10.0 // low
			switch a.Severity {
			case "high":
				weight = 40.0
			case "medium":
				weight = 20.0
			}

			// Linear decay over 24 hours
			age := now.Sub(a.CreatedAt).Hours()
			decay := 1.0 - (age / 24.0)
			if decay < 0.0 {
				decay = 0.0
			}

			decayedWeight := weight * decay
			rawScore += decayedWeight

			explanations = append(explanations, a.Description)
			evidence = append(evidence, EvidenceRef{
				Type:      a.Type,
				Severity:  a.Severity,
				Timestamp: a.CreatedAt,
				Message:   a.Description,
			})

			// Classify for correlation checks
			if a.Type == "SURICATA_ALERT" {
				hasSuricata = true
				suricataTimes = append(suricataTimes, a.CreatedAt)
			} else {
				// Traffic spikes, port anomalies, or DDoS events
				hasFlowAnomaly = true
				flowAnomalyTimes = append(flowAnomalyTimes, a.CreatedAt)
			}
		}

		// Perform correlation checks: if there is both a Suricata alert and a flow anomaly within 1 hour
		correlated := false
		if hasSuricata && hasFlowAnomaly {
			for _, sTime := range suricataTimes {
				for _, fTime := range flowAnomalyTimes {
					diff := sTime.Sub(fTime)
					if diff < 0 {
						diff = -diff
					}
					if diff <= 1*time.Hour {
						correlated = true
						break
					}
				}
				if correlated {
					break
				}
			}
		}

		// Apply correlation booster
		if correlated {
			rawScore += 20.0
			explanations = append(explanations, "Correlated signature-based IDS alert with flow-based anomaly within 1 hour (+20 correlation boost)")
		}

		// Cap score between 0 and 100
		score := int(math.Round(rawScore))
		if score > 100 {
			score = 100
		}
		if score < 0 {
			score = 0
		}

		// Skip devices with 0 active score to keep list focused on threats
		if score == 0 {
			continue
		}

		level := "low"
		if score >= 70 {
			level = "high"
		} else if score >= 30 {
			level = "medium"
		}

		results = append(results, DeviceRisk{
			IP:               d.IP,
			Label:            d.Label,
			Hostname:         d.Hostname,
			RiskScore:        score,
			RiskLevel:        level,
			ActiveAlertCount: len(anoms),
			Explanations:     explanations,
			Evidence:         evidence,
		})
	}

	// Sort results by RiskScore descending, then by IP ascending
	sort.Slice(results, func(i, j int) bool {
		if results[i].RiskScore != results[j].RiskScore {
			return results[i].RiskScore > results[j].RiskScore
		}
		return results[i].IP < results[j].IP
	})

	if results == nil {
		results = []DeviceRisk{}
	}
	return results, nil
}
