package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/flowguard/flowguard/internal/config"
	"github.com/flowguard/flowguard/internal/risk"
	"github.com/flowguard/flowguard/internal/storage"
)

// parseQueryParams parses start, end and limit parameters from request query.
func parseQueryParams(r *http.Request) (time.Time, time.Time, int, error) {
	q := r.URL.Query()

	// Default limit: 10, max: 100
	limit := 10
	if limitStr := q.Get("limit"); limitStr != "" {
		val, err := strconv.Atoi(limitStr)
		if err != nil || val <= 0 {
			return time.Time{}, time.Time{}, 0, errors.New("invalid limit parameter; must be a positive integer")
		}
		if val > 100 {
			val = 100
		}
		limit = val
	}

	// Default end: now
	end := time.Now()
	if endStr := q.Get("end"); endStr != "" {
		val, err := time.Parse(time.RFC3339, endStr)
		if err != nil {
			return time.Time{}, time.Time{}, 0, errors.New("invalid end timestamp; must be RFC3339 formatted")
		}
		end = val
	}

	// Default start: 1 hour ago
	start := end.Add(-1 * time.Hour)
	if startStr := q.Get("start"); startStr != "" {
		val, err := time.Parse(time.RFC3339, startStr)
		if err != nil {
			return time.Time{}, time.Time{}, 0, errors.New("invalid start timestamp; must be RFC3339 formatted")
		}
		start = val
	}

	// Safety range check
	if start.After(end) {
		return time.Time{}, time.Time{}, 0, errors.New("start timestamp cannot be after end timestamp")
	}

	// Limit query duration to 7 days to preserve small-hardware performance
	if end.Sub(start) > 7*24*time.Hour {
		return time.Time{}, time.Time{}, 0, errors.New("query range exceeds maximum limit of 7 days")
	}

	return start, end, limit, nil
}

func parseBucketSeconds(r *http.Request) (int, error) {
	bucketSeconds := 300
	if raw := r.URL.Query().Get("bucket_seconds"); raw != "" {
		val, err := strconv.Atoi(raw)
		if err != nil {
			return 0, errors.New("invalid bucket_seconds parameter; must be an integer")
		}
		bucketSeconds = val
	}

	switch bucketSeconds {
	case 60, 300, 900, 3600:
		return bucketSeconds, nil
	default:
		return 0, errors.New("bucket_seconds must be one of 60, 300, 900, or 3600")
	}
}

// writeError Helper to output standardized JSON error payloads.
func writeError(w http.ResponseWriter, logger *slog.Logger, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	errPayload := map[string]string{"error": msg}
	if err := json.NewEncoder(w).Encode(errPayload); err != nil {
		logger.Error("Failed encoding JSON error response", slog.String("error", err.Error()))
	}
}

// handleTopSources processes queries for the top traffic sources.
func (s *APIServer) handleTopSources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if s.repo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "database repository is not configured")
		return
	}

	start, end, limit, err := parseQueryParams(r)
	if err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}

	res, err := s.repo.GetTopSources(r.Context(), start, end, limit)
	if err != nil {
		s.logger.Error("Failed to query top sources from database", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database query error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		s.logger.Error("Failed to encode top sources response", slog.String("error", err.Error()))
	}
}

// handleTopDestinations processes queries for the top traffic destinations.
func (s *APIServer) handleTopDestinations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if s.repo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "database repository is not configured")
		return
	}

	start, end, limit, err := parseQueryParams(r)
	if err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}

	res, err := s.repo.GetTopDestinations(r.Context(), start, end, limit)
	if err != nil {
		s.logger.Error("Failed to query top destinations from database", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database query error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		s.logger.Error("Failed to encode top destinations response", slog.String("error", err.Error()))
	}
}

// handleTopPorts processes queries for the top destination ports.
func (s *APIServer) handleTopPorts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if s.repo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "database repository is not configured")
		return
	}

	start, end, limit, err := parseQueryParams(r)
	if err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}

	res, err := s.repo.GetTopPorts(r.Context(), start, end, limit)
	if err != nil {
		s.logger.Error("Failed to query top ports from database", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database query error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		s.logger.Error("Failed to encode top ports response", slog.String("error", err.Error()))
	}
}

// handleTopProtocols processes queries for the top transport protocols.
func (s *APIServer) handleTopProtocols(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if s.repo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "database repository is not configured")
		return
	}

	start, end, limit, err := parseQueryParams(r)
	if err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}

	res, err := s.repo.GetTopProtocols(r.Context(), start, end, limit)
	if err != nil {
		s.logger.Error("Failed to query top protocols from database", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database query error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		s.logger.Error("Failed to encode top protocols response", slog.String("error", err.Error()))
	}
}

// handleTrafficTimeSeries returns bounded aggregate traffic counters for network charts.
func (s *APIServer) handleTrafficTimeSeries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if s.repo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "database repository is not configured")
		return
	}

	start, end, _, err := parseQueryParams(r)
	if err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}
	bucketSeconds, err := parseBucketSeconds(r)
	if err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}

	res, err := s.repo.GetTrafficTimeSeries(r.Context(), start, end, bucketSeconds)
	if err != nil {
		s.logger.Error("Failed to query traffic time series from database", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database query error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		s.logger.Error("Failed to encode traffic time series response", slog.String("error", err.Error()))
	}
}

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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(devices); err != nil {
		s.logger.Error("Failed to encode devices list response", slog.String("error", err.Error()))
	}
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
			RiskLevel:        "low",
			ActiveAlertCount: 0,
			Explanations:     []string{},
			Evidence:         []risk.EvidenceRef{},
		}
	}

	// 5. Placeholder Policy Summary (M18 Policies is future milestone)
	policySummary := map[string]interface{}{
		"status":           "no_policy",
		"applied_policies": []string{},
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

// handleListAnomalies returns the list of recent triggered alerts.
func (s *APIServer) handleListAnomalies(w http.ResponseWriter, r *http.Request) {
	if s.deviceRepo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "device metadata repository is not configured")
		return
	}

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		val, err := strconv.Atoi(limitStr)
		if err == nil && val > 0 {
			if val > 200 {
				val = 200
			}
			limit = val
		}
	}

	list, err := s.deviceRepo.ListAnomalies(r.Context(), limit)
	if err != nil {
		s.logger.Error("Failed listing anomalies", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(list); err != nil {
		s.logger.Error("Failed to encode anomalies list response", slog.String("error", err.Error()))
	}
}

// handleUpdateAnomalyStatus updates the lifecycle review status of a triggered alert.
func (s *APIServer) handleUpdateAnomalyStatus(w http.ResponseWriter, r *http.Request) {
	if s.deviceRepo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "device metadata repository is not configured")
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, s.logger, http.StatusBadRequest, "invalid anomaly ID parameter")
		return
	}

	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, s.logger, http.StatusBadRequest, "failed parsing request body")
		return
	}

	if req.Status != "active" && req.Status != "acknowledged" && req.Status != "silenced" {
		writeError(w, s.logger, http.StatusBadRequest, "invalid status; must be active, acknowledged, or silenced")
		return
	}

	err = s.deviceRepo.UpdateAnomalyStatus(r.Context(), id, req.Status)
	if err != nil {
		s.logger.Error("Failed updating anomaly status", slog.Int64("id", id), slog.String("status", req.Status), slog.String("error", err.Error()))
		if err.Error() == "anomaly not found" {
			writeError(w, s.logger, http.StatusNotFound, "anomaly not found")
			return
		}
		writeError(w, s.logger, http.StatusInternalServerError, "internal database update error")
		return
	}

	// Save audit log record
	_ = s.deviceRepo.SaveAuditLog(r.Context(), "update_anomaly_status", fmt.Sprintf("Updated anomaly ID %d status to %q", id, req.Status))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// handleListRiskDevices returns the sorted list of devices ranked by threat risk scoring.
func (s *APIServer) handleListRiskDevices(w http.ResponseWriter, r *http.Request) {
	if s.riskEngine == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "threat risk scoring engine is not configured")
		return
	}

	list, err := s.riskEngine.CalculateDeviceRisks(r.Context())
	if err != nil {
		s.logger.Error("Failed calculating device threat risks", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal calculation error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(list); err != nil {
		s.logger.Error("Failed to encode device threat risks response", slog.String("error", err.Error()))
	}
}

// handleListAuditLogs returns a list of recent security audit log events.
func (s *APIServer) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	if s.deviceRepo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "device metadata repository is not configured")
		return
	}

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 {
			limit = val
			if limit > 100 {
				limit = 100
			}
		}
	}

	list, err := s.deviceRepo.ListAuditLogs(r.Context(), limit)
	if err != nil {
		s.logger.Error("Failed querying audit logs", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(list); err != nil {
		s.logger.Error("Failed to encode audit logs response", slog.String("error", err.Error()))
	}
}

// handleGetFirewallRules returns read-only block rules templates for a target IP address.
func (s *APIServer) handleGetFirewallRules(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if net.ParseIP(ip) == nil {
		writeError(w, s.logger, http.StatusBadRequest, "invalid or missing IP address parameter")
		return
	}

	templates := map[string]string{
		"ip": ip,
		"unifi": fmt.Sprintf("UniFi Network Controller:\n"+
			"1. Go to Settings -> Routing & Firewall -> Firewall -> WAN IN -> Create New Rule\n"+
			"2. Name: \"Block FlowGuard Attacker\"\n"+
			"3. Action: Drop\n"+
			"4. Source: Address Group -> Create Group -> Add IP: %s\n"+
			"5. Save", ip),
		"opnsense": fmt.Sprintf("OPNsense Web GUI:\n"+
			"1. Go to Firewall -> Rules -> WAN -> Add Rule (Up arrow/top of list)\n"+
			"2. Action: Block\n"+
			"3. Interface: WAN\n"+
			"4. Protocol: any\n"+
			"5. Source: Single host or Network -> %s\n"+
			"6. Description: \"FlowGuard Lite Block Rule\"\n"+
			"7. Save & Apply Changes", ip),
		"mikrotik": fmt.Sprintf("/ip firewall filter add action=drop chain=input src-address=%s comment=\"FlowGuard Lite Block Rule\"", ip),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(templates); err != nil {
		s.logger.Error("Failed to encode firewall rules templates response", slog.String("error", err.Error()))
	}
}

// SettingsPayload represents the JSON payload structure for reading and updating configurations.
type SettingsPayload struct {
	Port              string            `json:"port"`
	NetflowPort       int               `json:"netflow_port"`
	SflowPort         int               `json:"sflow_port"`
	StorageDir        string            `json:"storage_dir"`
	LogLevel          string            `json:"log_level"`
	Environment       string            `json:"environment"`
	LocalSubnets      []string          `json:"local_subnets"`
	WebhookURL        string            `json:"webhook_url"`
	WebhookFormat     string            `json:"webhook_format"`
	WebhookHeaders    map[string]string `json:"webhook_headers"`
	TelegramEnabled   bool              `json:"telegram_enabled"`
	TelegramToken     string            `json:"telegram_token"`
	TelegramChatID    string            `json:"telegram_chat_id"`
	StorageBackend    string            `json:"storage_backend"`
	FirstRunCompleted bool              `json:"first_run_completed"`
}

// handleGetSettings yields the current daemon settings.
func (s *APIServer) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	payload := SettingsPayload{
		Port:              s.cfg.Port,
		NetflowPort:       s.cfg.NetflowPort,
		SflowPort:         s.cfg.SflowPort,
		StorageDir:        s.cfg.StorageDir,
		LogLevel:          s.cfg.LogLevel,
		Environment:       s.cfg.Environment,
		LocalSubnets:      s.cfg.LocalSubnets,
		WebhookURL:        s.cfg.WebhookURL,
		WebhookFormat:     s.cfg.WebhookFormat,
		WebhookHeaders:    s.cfg.WebhookHeaders,
		TelegramEnabled:   s.cfg.TelegramEnabled,
		TelegramToken:     s.cfg.TelegramToken,
		TelegramChatID:    s.cfg.TelegramChatID,
		StorageBackend:    s.cfg.StorageBackend,
		FirstRunCompleted: s.cfg.FirstRunCompleted,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Error("Failed to encode settings response", slog.String("error", err.Error()))
	}
}

// handlePostSettings updates daemon settings and persists them to the configuration file.
func (s *APIServer) handlePostSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var payload SettingsPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, s.logger, http.StatusBadRequest, "invalid request JSON body")
		return
	}

	// 1. Validate inputs
	if payload.NetflowPort < 1 || payload.NetflowPort > 65535 {
		writeError(w, s.logger, http.StatusBadRequest, "Netflow port must be between 1 and 65535")
		return
	}
	if payload.SflowPort < 1 || payload.SflowPort > 65535 {
		writeError(w, s.logger, http.StatusBadRequest, "sFlow port must be between 1 and 65535")
		return
	}
	if payload.StorageBackend != "sqlite" && payload.StorageBackend != "duckdb" {
		writeError(w, s.logger, http.StatusBadRequest, "Storage backend must be 'sqlite' or 'duckdb'")
		return
	}
	for _, subnet := range payload.LocalSubnets {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(subnet)); err != nil {
			writeError(w, s.logger, http.StatusBadRequest, fmt.Sprintf("invalid CIDR subnet: %s", subnet))
			return
		}
	}

	// 2. Update config struct in memory
	s.cfg.Port = payload.Port
	s.cfg.NetflowPort = payload.NetflowPort
	s.cfg.SflowPort = payload.SflowPort
	s.cfg.StorageDir = payload.StorageDir
	s.cfg.LogLevel = payload.LogLevel
	s.cfg.Environment = payload.Environment
	s.cfg.LocalSubnets = payload.LocalSubnets
	s.cfg.WebhookURL = payload.WebhookURL
	s.cfg.WebhookFormat = payload.WebhookFormat
	s.cfg.WebhookHeaders = payload.WebhookHeaders
	s.cfg.TelegramEnabled = payload.TelegramEnabled
	s.cfg.TelegramToken = payload.TelegramToken
	s.cfg.TelegramChatID = payload.TelegramChatID
	s.cfg.StorageBackend = payload.StorageBackend
	s.cfg.FirstRunCompleted = payload.FirstRunCompleted

	// 3. Persist back to disk if path is provided
	if s.configPath != "" {
		if err := config.SaveConfig(s.configPath, s.cfg); err != nil {
			s.logger.Error("Failed persisting settings to config file", slog.String("path", s.configPath), slog.String("error", err.Error()))
			writeError(w, s.logger, http.StatusInternalServerError, "failed to persist settings to disk")
			return
		}
		s.logger.Info("Saved configuration settings back to disk", slog.String("path", s.configPath))
	}

	// 4. Propagate updates dynamically to running engines
	if s.profiler != nil {
		s.profiler.UpdateLocalSubnets(s.cfg.LocalSubnets)
	}
	if s.ddosDetector != nil {
		s.ddosDetector.UpdateLocalSubnets(s.cfg.LocalSubnets)
	}
	if s.webhookEngine != nil {
		s.webhookEngine.UpdateConfig(s.cfg.WebhookURL, s.cfg.WebhookFormat, s.cfg.WebhookHeaders, s.cfg.TelegramEnabled, s.cfg.TelegramToken, s.cfg.TelegramChatID)
	}

	// 5. Log audit action
	if s.deviceRepo != nil {
		_ = s.deviceRepo.SaveAuditLog(r.Context(), "update_settings", "Dynamic daemon settings updated successfully")
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Error("Failed to encode settings response", slog.String("error", err.Error()))
	}
}

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
			for _, sev := range []string{"low", "medium", "high"} {
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
		Status:      "active",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	s.logger.Info("Dispatching manual notification test alert...")
	s.webhookEngine.SendAnomalyAlert(r.Context(), testAnomaly)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "test alert dispatched successfully"})
}
