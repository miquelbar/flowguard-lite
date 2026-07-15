package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/risk"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

// handleListDevices returns the list of discovered devices.
func (s *APIServer) handleListDevices(w http.ResponseWriter, r *http.Request) {
	if s.deviceRepo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "device metadata repository is not configured")
		return
	}

	devices, err := s.deviceRepo.ListDevices(r.Context())
	if err != nil {
		s.logger.Error("Failed to list discovered devices", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database error")
		return
	}
	if len(devices) == 0 {
		if err := s.reconcileLocalDevicesFromAggregates(r.Context()); err != nil {
			s.logger.Warn("Failed to reconcile local devices from retained flow aggregates", slog.String("error", err.Error()))
		} else {
			devices, err = s.deviceRepo.ListDevices(r.Context())
			if err != nil {
				s.logger.Error("Failed to list reconciled devices", slog.String("error", err.Error()))
				writeError(w, s.logger, http.StatusInternalServerError, "internal database error")
				return
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(devices); err != nil {
		s.logger.Error("Failed to encode devices list response", slog.String("error", err.Error()))
	}
}

func (s *APIServer) reconcileLocalDevicesFromAggregates(ctx context.Context) error {
	if s.cfg == nil || s.repo == nil || s.deviceRepo == nil || len(s.cfg.LocalSubnets) == 0 {
		return nil
	}

	localNets := make([]*net.IPNet, 0, len(s.cfg.LocalSubnets))
	for _, cidr := range s.cfg.LocalSubnets {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		localNets = append(localNets, ipNet)
	}
	if len(localNets) == 0 {
		return nil
	}

	now := time.Now().UTC()
	start := now.Add(-24 * time.Hour)
	const candidateLimit = 1000

	candidates := make(map[string]struct{})
	collectLocalCandidates := func(items []flow.TopResult) {
		for _, item := range items {
			if isConfiguredLocalIP(item.Key, localNets) {
				candidates[item.Key] = struct{}{}
			}
		}
	}

	sources, err := s.repo.GetTopSources(ctx, start, now, candidateLimit)
	if err != nil {
		return fmt.Errorf("query top sources for device reconciliation: %w", err)
	}
	collectLocalCandidates(sources)

	destinations, err := s.repo.GetTopDestinations(ctx, start, now, candidateLimit)
	if err != nil {
		return fmt.Errorf("query top destinations for device reconciliation: %w", err)
	}
	collectLocalCandidates(destinations)

	for ip := range candidates {
		if err := s.deviceRepo.UpsertDevice(ctx, ip, "", now); err != nil {
			return fmt.Errorf("upsert reconciled device %s: %w", ip, err)
		}
	}
	return nil
}

func isConfiguredLocalIP(ipStr string, localNets []*net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, localNet := range localNets {
		if localNet.Contains(ip) {
			return true
		}
	}
	return false
}

// handleUpdateDeviceLabel updates the manual label of a device.
func (s *APIServer) handleUpdateDeviceLabel(w http.ResponseWriter, r *http.Request) {
	if s.deviceRepo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "device metadata repository is not configured")
		return
	}

	ip := r.PathValue("ip")
	if net.ParseIP(ip) == nil {
		writeError(w, s.logger, http.StatusBadRequest, "invalid IP address format")
		return
	}

	var req struct {
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, s.logger, http.StatusBadRequest, "failed parsing request body")
		return
	}

	// Validate input length
	if len(req.Label) > 100 {
		writeError(w, s.logger, http.StatusBadRequest, "device label must be 100 characters or less")
		return
	}

	err := s.deviceRepo.UpdateDeviceLabel(r.Context(), ip, req.Label)
	if err != nil {
		s.logger.Error("Failed updating device label",
			slog.String("ip", ip),
			slog.String("label", req.Label),
			slog.String("error", err.Error()))

		if err.Error() == "device not found" {
			writeError(w, s.logger, http.StatusNotFound, "device not found in inventory")
			return
		}
		writeError(w, s.logger, http.StatusInternalServerError, "internal database update error")
		return
	}

	// Save audit log record
	_ = s.deviceRepo.SaveAuditLog(r.Context(), "update_device_label", fmt.Sprintf("Updated device %s label to %q", ip, req.Label))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// handleGetDeviceBaseline returns the baseline statistical values for a device.
func (s *APIServer) handleGetDeviceBaseline(w http.ResponseWriter, r *http.Request) {
	if s.baselineEngine == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "baseline engine is not configured")
		return
	}

	ip := r.PathValue("ip")
	if net.ParseIP(ip) == nil {
		writeError(w, s.logger, http.StatusBadRequest, "invalid IP address format")
		return
	}

	// Fetch cached or database baseline
	baseLine := s.baselineEngine.GetCachedBaseline(ip)
	if baseLine == nil {
		// Fallback to database lookup in case cache is being calculated/re-initialized
		var err error
		baseLine, err = s.deviceRepo.GetBaseline(r.Context(), ip)
		if err != nil {
			s.logger.Error("Failed querying baseline from database", slog.String("ip", ip), slog.String("error", err.Error()))
			writeError(w, s.logger, http.StatusInternalServerError, "internal database error")
			return
		}
	}

	if baseLine == nil {
		writeError(w, s.logger, http.StatusNotFound, "baseline profile not found for this device")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(baseLine); err != nil {
		s.logger.Error("Failed to encode device baseline response", slog.String("error", err.Error()))
	}
}

// handleGetDeviceProfile returns the unified profile page JSON for a device.
func (s *APIServer) handleGetDeviceProfile(w http.ResponseWriter, r *http.Request) {
	if s.deviceRepo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "device metadata repository is not configured")
		return
	}

	ip := r.PathValue("ip")
	if net.ParseIP(ip) == nil {
		writeError(w, s.logger, http.StatusBadRequest, "invalid IP address format")
		return
	}

	dev, err := s.deviceRepo.GetDevice(r.Context(), ip)
	if err != nil {
		s.logger.Error("Failed to fetch device metadata", slog.String("ip", ip), slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database error")
		return
	}

	if dev == nil {
		writeError(w, s.logger, http.StatusNotFound, "device not found in inventory")
		return
	}

	// 1. Classify Subnet / VLAN
	subnetVLAN := "Unknown"
	if s.cfg != nil {
		ipObj := net.ParseIP(ip)
		for _, cidr := range s.cfg.LocalSubnets {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err == nil && ipNet.Contains(ipObj) {
				subnetVLAN = cidr
				break
			}
		}
	}
	if subnetVLAN == "Unknown" {
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			subnetVLAN = fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		}
	}

	// 2. Fetch baseline data
	var baselineData *storage.DeviceBaseline
	if s.baselineEngine != nil {
		baselineData = s.baselineEngine.GetCachedBaseline(ip)
	}
	if baselineData == nil {
		var err error
		baselineData, err = s.deviceRepo.GetBaseline(r.Context(), ip)
		if err != nil {
			s.logger.Warn("Failed to fetch baseline for profile", slog.String("ip", ip), slog.String("error", err.Error()))
		}
	}

	// 3. Fetch anomalies associated with this IP
	anomalies, err := s.deviceRepo.GetAnomaliesForIP(r.Context(), ip, 50)
	if err != nil {
		s.logger.Warn("Failed to fetch anomalies for profile", slog.String("ip", ip), slog.String("error", err.Error()))
		anomalies = []storage.Anomaly{}
	}

	// 4. Calculate Risk breakdown
	var devRisk *risk.DeviceRisk
	if s.riskEngine != nil {
		risks, err := s.riskEngine.CalculateDeviceRisks(r.Context())
		if err == nil {
			for _, rk := range risks {
				if rk.IP == ip {
					devRisk = &rk
					break
				}
			}
		}
	}
	if devRisk == nil {
		devRisk = &risk.DeviceRisk{
			IP:               ip,
			Label:            dev.Label,
			Hostname:         dev.Hostname,
			RiskScore:        0,
			RiskLevel:        storage.SeverityLow,
			ActiveAlertCount: 0,
			Explanations:     []string{},
			Evidence:         []risk.EvidenceRef{},
		}
	}

	// 5. Fetch applied policies
	appliedPolicies := []storage.Policy{}
	appliedPoliciesNames := []string{}
	status := "no_policy"
	if s.deviceRepo != nil {
		pols, err := s.deviceRepo.GetPoliciesForIP(r.Context(), ip)
		if err == nil {
			appliedPolicies = pols
			for _, p := range pols {
				appliedPoliciesNames = append(appliedPoliciesNames, p.Name)
			}
			if len(pols) > 0 {
				status = "active_policy"
			}
		}
	}
	policySummary := map[string]interface{}{
		"status":           status,
		"applied_policies": appliedPoliciesNames,
		"policies":         appliedPolicies,
	}

	response := map[string]interface{}{
		"ip":             dev.IP,
		"label":          dev.Label,
		"hostname":       dev.Hostname,
		"vendor":         dev.Vendor,
		"first_seen":     dev.FirstSeen,
		"last_seen":      dev.LastSeen,
		"subnet_vlan":    subnetVLAN,
		"risk":           devRisk,
		"baseline":       baselineData,
		"anomalies":      anomalies,
		"policy_summary": policySummary,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode device profile response", slog.String("ip", ip), slog.String("error", err.Error()))
	}
}

// handleGetDeviceFlows returns the device-specific traffic flows, top peers and top ports.
func (s *APIServer) handleGetDeviceFlows(w http.ResponseWriter, r *http.Request) {
	if s.repo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "database repository is not configured")
		return
	}

	ip := r.PathValue("ip")
	if net.ParseIP(ip) == nil {
		writeError(w, s.logger, http.StatusBadRequest, "invalid IP address format")
		return
	}

	start, end, limit, err := parseQueryParams(r)
	if err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}

	bucketSeconds, err := parseBucketSeconds(r)
	if err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}

	timeSeries, err := s.repo.GetDeviceTrafficTimeSeries(r.Context(), ip, start, end, bucketSeconds)
	if err != nil {
		s.logger.Error("Failed to query device traffic time series", slog.String("ip", ip), slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database query error")
		return
	}

	topPeers, err := s.repo.GetDeviceTopPeers(r.Context(), ip, start, end, limit)
	if err != nil {
		s.logger.Error("Failed to query device top peers", slog.String("ip", ip), slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database query error")
		return
	}

	topPorts, err := s.repo.GetDeviceTopPorts(r.Context(), ip, start, end, limit)
	if err != nil {
		s.logger.Error("Failed to query device top ports", slog.String("ip", ip), slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database query error")
		return
	}

	response := map[string]interface{}{
		"time_series": timeSeries,
		"top_peers":   topPeers,
		"top_ports":   topPorts,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("Failed to encode device flows response", slog.String("ip", ip), slog.String("error", err.Error()))
	}
}
