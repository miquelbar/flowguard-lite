package risk

import (
	"context"
	"math"
	"sort"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/storage"
)

const (
	activeRiskWindow     = 7 * 24 * time.Hour
	activeRiskDecayFloor = 0.15
)

// EvidenceRef represents an individual security event contributing to the device's threat level.
type EvidenceRef struct {
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}

// AlertContributor represents an active alert contributing to the threat risk.
type AlertContributor struct {
	ID           int64     `json:"id"`
	Type         string    `json:"type"`
	Severity     string    `json:"severity"`
	CreatedAt    time.Time `json:"created_at"`
	AgeHours     float64   `json:"age_hours"`
	BaseWeight   float64   `json:"base_weight"`
	DecayFactor  float64   `json:"decay_factor"`
	Contribution float64   `json:"contribution"`
	Description  string    `json:"description"`
}

// RiskBreakdown aggregates all components contributing to a device's risk score.
type RiskBreakdown struct {
	BaseScore        float64            `json:"base_score"`
	CorrelationBoost float64            `json:"correlation_boost"`
	ActiveAlertCount int                `json:"active_alert_count"`
	AlertBreakdown   []AlertContributor `json:"alert_breakdown"`
	LowThreshold     int                `json:"low_threshold"`
	MediumThreshold  int                `json:"medium_threshold"`
	HighThreshold    int                `json:"high_threshold"`
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
	Breakdown        RiskBreakdown `json:"breakdown"`
}

// RiskEngine handles threat scoring, temporal alert decay, and multi-source event correlation.
type RiskEngine struct {
	repo storage.DeviceRepository
}

// NewRiskEngine instantiates a new RiskEngine.
func NewRiskEngine(repo storage.DeviceRepository) *RiskEngine {
	return &RiskEngine{repo: repo}
}

// CalculateDeviceRisks queries active anomalies over the retained dashboard window,
// correlates multiple sources, and compiles the ranking list.
func (e *RiskEngine) CalculateDeviceRisks(ctx context.Context) ([]DeviceRisk, error) {
	devices, err := e.repo.ListDevices(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	since := now.Add(-activeRiskWindow)

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

		var alertBreakdown []AlertContributor
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
			case storage.SeverityHigh:
				weight = 40.0
			case storage.SeverityMedium:
				weight = 20.0
			}

			// Linear decay over 24 hours with a floor for unresolved active alerts.
			// Active alerts should become less prominent over time, but should not
			// disappear from the threat ranking while still unresolved and within
			// the bounded dashboard retention window.
			age := now.Sub(a.CreatedAt).Hours()
			decay := 1.0 - (age / 24.0)
			if decay < activeRiskDecayFloor {
				decay = activeRiskDecayFloor
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

			// Add contributor details
			alertBreakdown = append(alertBreakdown, AlertContributor{
				ID:           a.ID,
				Type:         a.Type,
				Severity:     a.Severity,
				CreatedAt:    a.CreatedAt,
				AgeHours:     age,
				BaseWeight:   weight,
				DecayFactor:  decay,
				Contribution: decayedWeight,
				Description:  a.Description,
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
		var correlationBoost float64
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
			correlationBoost = 20.0
			rawScore += correlationBoost
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

		level := storage.SeverityLow
		if score >= 70 {
			level = storage.SeverityHigh
		} else if score >= 30 {
			level = storage.SeverityMedium
		}

		breakdown := RiskBreakdown{
			BaseScore:        rawScore - correlationBoost,
			CorrelationBoost: correlationBoost,
			ActiveAlertCount: len(anoms),
			AlertBreakdown:   alertBreakdown,
			LowThreshold:     0,
			MediumThreshold:  30,
			HighThreshold:    70,
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
			Breakdown:        breakdown,
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
