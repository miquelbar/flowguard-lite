package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/storage"
)

// handleMetrics formats and exports Prometheus scraper metrics.
func (s *APIServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	// 1. Write Collector Metrics
	if s.collector != nil {
		stats := s.collector.GetStats()
		fmt.Fprintf(w, "# HELP flowguard_collector_packets_total Total number of packets received by the collector.\n")
		fmt.Fprintf(w, "# TYPE flowguard_collector_packets_total counter\n")
		fmt.Fprintf(w, "flowguard_collector_packets_total{protocol=\"netflow\"} %d\n", stats.PacketsNetflow)
		fmt.Fprintf(w, "flowguard_collector_packets_total{protocol=\"sflow\"} %d\n", stats.PacketsSflow)

		fmt.Fprintf(w, "# HELP flowguard_collector_drops_total Total number of packets dropped due to queue overflow.\n")
		fmt.Fprintf(w, "# TYPE flowguard_collector_drops_total counter\n")
		fmt.Fprintf(w, "flowguard_collector_drops_total %d\n", stats.PacketsDropped)

		fmt.Fprintf(w, "# HELP flowguard_collector_errors_total Total number of flow decode errors.\n")
		fmt.Fprintf(w, "# TYPE flowguard_collector_errors_total counter\n")
		fmt.Fprintf(w, "flowguard_collector_errors_total %d\n", stats.DecodeErrors)

		fmt.Fprintf(w, "# HELP flowguard_collector_source_enabled Whether a bounded collector source is enabled.\n")
		fmt.Fprintf(w, "# TYPE flowguard_collector_source_enabled gauge\n")
		fmt.Fprintf(w, "# HELP flowguard_collector_source_packets_total Packets received by bounded collector source where available.\n")
		fmt.Fprintf(w, "# TYPE flowguard_collector_source_packets_total counter\n")
		fmt.Fprintf(w, "# HELP flowguard_collector_source_drops_total Packets dropped by bounded collector source where available.\n")
		fmt.Fprintf(w, "# TYPE flowguard_collector_source_drops_total counter\n")
		fmt.Fprintf(w, "# HELP flowguard_collector_source_errors_total Decode or parse errors by bounded collector source where available.\n")
		fmt.Fprintf(w, "# TYPE flowguard_collector_source_errors_total counter\n")
		for _, src := range stats.Sources {
			fmt.Fprintf(w, "flowguard_collector_source_enabled{kind=%q,id=%q} %d\n", src.Kind, src.ID, boolGauge(src.Enabled))
			fmt.Fprintf(w, "flowguard_collector_source_packets_total{kind=%q,id=%q} %d\n", src.Kind, src.ID, src.Packets)
			fmt.Fprintf(w, "flowguard_collector_source_drops_total{kind=%q,id=%q} %d\n", src.Kind, src.ID, src.Drops)
			fmt.Fprintf(w, "flowguard_collector_source_errors_total{kind=%q,id=%q} %d\n", src.Kind, src.ID, src.DecodeErrors)
		}
	}

	// 2. Write Device Metrics
	if s.deviceRepo != nil {
		devices, err := s.deviceRepo.ListDevices(r.Context())
		if err != nil {
			s.logger.Error("Failed to list devices for metrics", slog.String("error", err.Error()))
		} else {
			fmt.Fprintf(w, "# HELP flowguard_discovered_devices_total Total number of discovered local devices.\n")
			fmt.Fprintf(w, "# TYPE flowguard_discovered_devices_total gauge\n")
			fmt.Fprintf(w, "flowguard_discovered_devices_total %d\n", len(devices))
		}

		// 3. Write Threat / Anomaly Metrics
		activeAnomalies, err := s.deviceRepo.GetActiveAnomalies(r.Context(), time.Now().Add(-30*24*time.Hour))
		if err != nil {
			s.logger.Error("Failed to get active anomalies for metrics", slog.String("error", err.Error()))
		} else {
			// Aggregate active anomalies by severity and type
			counts := make(map[string]map[string]int) // severity -> type -> count
			for _, sev := range []string{storage.SeverityLow, storage.SeverityMedium, storage.SeverityHigh} {
				counts[sev] = make(map[string]int)
			}

			for _, a := range activeAnomalies {
				sev := strings.ToLower(a.Severity)
				if counts[sev] == nil {
					counts[sev] = make(map[string]int)
				}
				counts[sev][a.Type]++
			}

			fmt.Fprintf(w, "# HELP flowguard_active_anomalies Total number of active security anomalies.\n")
			fmt.Fprintf(w, "# TYPE flowguard_active_anomalies gauge\n")

			if len(activeAnomalies) == 0 {
				fmt.Fprintf(w, "flowguard_active_anomalies{severity=\"high\",type=\"ddos\"} 0\n")
				fmt.Fprintf(w, "flowguard_active_anomalies{severity=\"high\",type=\"suricata\"} 0\n")
			} else {
				for sev, types := range counts {
					for t, count := range types {
						fmt.Fprintf(w, "flowguard_active_anomalies{severity=\"%s\",type=\"%s\"} %d\n", sev, t, count)
					}
				}
			}
		}
	}
}

func boolGauge(v bool) int {
	if v {
		return 1
	}
	return 0
}

// handleTestAlert dispatches a mock anomaly alert to verify Slack/Telegram/Webhook channel setups.
func (s *APIServer) handleTestAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.webhookEngine == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "webhook engine is not initialized")
		return
	}

	testAnomaly := &storage.Anomaly{
		IP:          "192.168.1.99",
		Type:        "test_alert",
		Description: "This is a FlowGuard Lite notification test alert. Your channel configuration is verified and active!",
		Severity:    "info",
		Status:      storage.AnomalyStatusActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	s.logger.Info("Dispatching manual notification test alert...")
	s.webhookEngine.SendAnomalyAlert(r.Context(), testAnomaly)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "test alert dispatched successfully"})
}
