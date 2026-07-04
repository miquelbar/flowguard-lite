package risk

import (
	"context"
	"math"
	"sort"
	"time"

	"github.com/flowguard/flowguard/internal/storage"
)

// DeviceRisk represents a computed security threat score and details for a device.
type DeviceRisk struct {
	IP               string   `json:"ip"`
	Label            string   `json:"label"`
	Hostname         string   `json:"hostname"`
	RiskScore        int      `json:"risk_score"`
	RiskLevel        string   `json:"risk_level"` // "low", "medium", "high"
	ActiveAlertCount int      `json:"active_alert_count"`
	Explanations     []string `json:"explanations"`
}

// RiskEngine handles threat scoring and temporal alert decay formulas.
type RiskEngine struct {
	repo storage.DeviceRepository
}

// NewRiskEngine instantiates a new RiskEngine.
func NewRiskEngine(repo storage.DeviceRepository) *RiskEngine {
	return &RiskEngine{repo: repo}
}

// CalculateDeviceRisks queries active anomalies over the past 24 hours and compiles a list of risky devices.
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
		activeCount := 0

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
			activeCount++

			explanations = append(explanations, a.Description)
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
			ActiveAlertCount: activeCount,
			Explanations:     explanations,
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
