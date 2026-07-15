package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/webhook"
)

// SettingsPayload represents the JSON payload structure for reading and updating configurations.
type SettingsPayload struct {
	Port                            string            `json:"port"`
	NetflowPort                     int               `json:"netflow_port"`
	SflowPort                       int               `json:"sflow_port"`
	CaptureInterface                string            `json:"capture_interface"`
	CaptureBPFFilter                string            `json:"capture_bpf_filter"`
	CapturePromiscuous              bool              `json:"capture_promiscuous"`
	UniFiSyslogEnabled              bool              `json:"unifi_syslog_enabled"`
	UniFiSyslogPort                 int               `json:"unifi_syslog_port"`
	UniFiSyslogAllowedIPs           []string          `json:"unifi_syslog_allowed_ips"`
	StorageDir                      string            `json:"storage_dir"`
	LogLevel                        string            `json:"log_level"`
	Environment                     string            `json:"environment"`
	LocalSubnets                    []string          `json:"local_subnets"`
	SlackWebhookURL                 string            `json:"slack_webhook_url"`
	WebhookURL                      string            `json:"webhook_url"`
	WebhookFormat                   string            `json:"webhook_format"`
	WebhookHeaders                  map[string]string `json:"webhook_headers"`
	TelegramEnabled                 bool              `json:"telegram_enabled"`
	TelegramToken                   string            `json:"telegram_token"`
	TelegramChatID                  string            `json:"telegram_chat_id"`
	StorageBackend                  string            `json:"storage_backend"`
	FirstRunCompleted               bool              `json:"first_run_completed"`
	RetentionDays                   int               `json:"retention_days"`
	DisabledAnomalyTypes            []string          `json:"disabled_anomaly_types"`
	MutedAnomalySubnets             []string          `json:"muted_anomaly_subnets"`
	NotifyAllowedSubnets            []string          `json:"notify_allowed_subnets"`
	NotifySuppressedTypes           []string          `json:"notify_suppressed_types"`
	NewDestinationMinHistoryBuckets int               `json:"new_destination_min_history_buckets"`
	BeaconMinObservations           int               `json:"beacon_min_observations"`
	BeaconMinIntervalSeconds        int               `json:"beacon_min_interval_seconds"`
	TrafficSpikeMinPackets          int               `json:"traffic_spike_min_packets"`
	TrafficSpikeMinBytes            int               `json:"traffic_spike_min_bytes"`
	DDoSThresholdPPS                int               `json:"ddos_threshold_pps"`
	DDoSThresholdBPS                int               `json:"ddos_threshold_bps"`
	DDoSThresholdFPS                int               `json:"ddos_threshold_fps"`
	SYNFloodThresholdPPS            int               `json:"syn_flood_threshold_pps"`
	UDPFloodThresholdPPS            int               `json:"udp_flood_threshold_pps"`
	ICMPFloodThresholdPPS           int               `json:"icmp_flood_threshold_pps"`
	SuricataEvePath                 string            `json:"suricata_eve_path"`
	AdminPassword                   string            `json:"admin_password,omitempty"`
}

func maskedHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return make(map[string]string)
	}
	res := make(map[string]string)
	for k, v := range headers {
		lowerK := strings.ToLower(k)
		if strings.Contains(lowerK, "auth") || strings.Contains(lowerK, "key") || strings.Contains(lowerK, "token") || strings.Contains(lowerK, "secret") {
			res[k] = "******"
		} else {
			res[k] = v
		}
	}
	return res
}

// handleGetSettings yields the current daemon settings.
func (s *APIServer) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	telegramToken := s.cfg.TelegramToken
	if telegramToken != "" {
		telegramToken = "******"
	}

	payload := SettingsPayload{
		Port:                            s.cfg.Port,
		NetflowPort:                     s.cfg.NetflowPort,
		SflowPort:                       s.cfg.SflowPort,
		CaptureInterface:                s.cfg.CaptureInterface,
		CaptureBPFFilter:                s.cfg.CaptureBPFFilter,
		CapturePromiscuous:              s.cfg.CapturePromiscuous,
		UniFiSyslogEnabled:              s.cfg.UniFiSyslogEnabled,
		UniFiSyslogPort:                 s.cfg.UniFiSyslogPort,
		UniFiSyslogAllowedIPs:           s.cfg.UniFiSyslogAllowedIPs,
		StorageDir:                      s.cfg.StorageDir,
		LogLevel:                        s.cfg.LogLevel,
		Environment:                     s.cfg.Environment,
		LocalSubnets:                    s.cfg.LocalSubnets,
		SlackWebhookURL:                 s.cfg.SlackWebhookURL,
		WebhookURL:                      s.cfg.WebhookURL,
		WebhookFormat:                   s.cfg.WebhookFormat,
		WebhookHeaders:                  maskedHeaders(s.cfg.WebhookHeaders),
		TelegramEnabled:                 s.cfg.TelegramEnabled,
		TelegramToken:                   telegramToken,
		TelegramChatID:                  s.cfg.TelegramChatID,
		StorageBackend:                  s.cfg.StorageBackend,
		FirstRunCompleted:               s.cfg.FirstRunCompleted,
		RetentionDays:                   s.cfg.RetentionDays,
		DisabledAnomalyTypes:            s.cfg.DisabledAnomalyTypes,
		MutedAnomalySubnets:             s.cfg.MutedAnomalySubnets,
		NotifyAllowedSubnets:            s.cfg.NotifyAllowedSubnets,
		NotifySuppressedTypes:           s.cfg.NotifySuppressedTypes,
		NewDestinationMinHistoryBuckets: s.cfg.NewDestinationMinHistoryBuckets,
		BeaconMinObservations:           s.cfg.BeaconMinObservations,
		BeaconMinIntervalSeconds:        s.cfg.BeaconMinIntervalSeconds,
		TrafficSpikeMinPackets:          s.cfg.TrafficSpikeMinPackets,
		TrafficSpikeMinBytes:            s.cfg.TrafficSpikeMinBytes,
		DDoSThresholdPPS:                s.cfg.DDoSThresholdPPS,
		DDoSThresholdBPS:                s.cfg.DDoSThresholdBPS,
		DDoSThresholdFPS:                s.cfg.DDoSThresholdFPS,
		SYNFloodThresholdPPS:            s.cfg.SYNFloodThresholdPPS,
		UDPFloodThresholdPPS:            s.cfg.UDPFloodThresholdPPS,
		ICMPFloodThresholdPPS:           s.cfg.ICMPFloodThresholdPPS,
		SuricataEvePath:                 s.cfg.SuricataEvePath,
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
	if payload.StorageDir == "" {
		payload.StorageDir = s.cfg.StorageDir
	}
	if payload.WebhookFormat == "" {
		payload.WebhookFormat = s.cfg.WebhookFormat
	}
	if payload.WebhookHeaders == nil {
		payload.WebhookHeaders = s.cfg.WebhookHeaders
	}
	if payload.DisabledAnomalyTypes == nil {
		payload.DisabledAnomalyTypes = s.cfg.DisabledAnomalyTypes
	}
	if payload.MutedAnomalySubnets == nil {
		payload.MutedAnomalySubnets = s.cfg.MutedAnomalySubnets
	}
	if payload.NotifyAllowedSubnets == nil {
		payload.NotifyAllowedSubnets = s.cfg.NotifyAllowedSubnets
	}
	if payload.NotifySuppressedTypes == nil {
		payload.NotifySuppressedTypes = s.cfg.NotifySuppressedTypes
	}
	if payload.NewDestinationMinHistoryBuckets == 0 {
		payload.NewDestinationMinHistoryBuckets = s.cfg.NewDestinationMinHistoryBuckets
	}
	if payload.BeaconMinObservations == 0 {
		payload.BeaconMinObservations = s.cfg.BeaconMinObservations
	}
	if payload.BeaconMinIntervalSeconds == 0 {
		payload.BeaconMinIntervalSeconds = s.cfg.BeaconMinIntervalSeconds
	}
	if payload.TrafficSpikeMinPackets == 0 {
		payload.TrafficSpikeMinPackets = s.cfg.TrafficSpikeMinPackets
	}
	if payload.TrafficSpikeMinBytes == 0 {
		payload.TrafficSpikeMinBytes = s.cfg.TrafficSpikeMinBytes
	}

	// 1. Validate inputs
	portNum, err := strconv.Atoi(payload.Port)
	if err != nil || portNum < 1 || portNum > 65535 {
		writeError(w, s.logger, http.StatusBadRequest, "Web server port must be between 1 and 65535")
		return
	}
	if payload.NetflowPort < 0 || payload.NetflowPort > 65535 {
		writeError(w, s.logger, http.StatusBadRequest, "Netflow port must be between 0 and 65535")
		return
	}
	if payload.SflowPort < 0 || payload.SflowPort > 65535 {
		writeError(w, s.logger, http.StatusBadRequest, "sFlow port must be between 0 and 65535")
		return
	}
	if payload.UniFiSyslogPort < 0 || payload.UniFiSyslogPort > 65535 {
		writeError(w, s.logger, http.StatusBadRequest, "UniFi syslog port must be between 0 and 65535")
		return
	}
	if payload.UniFiSyslogEnabled && payload.UniFiSyslogPort == 0 {
		writeError(w, s.logger, http.StatusBadRequest, "UniFi syslog port must be greater than 0 when enabled")
		return
	}
	payload.CaptureInterface = strings.TrimSpace(payload.CaptureInterface)
	payload.CaptureBPFFilter = strings.TrimSpace(payload.CaptureBPFFilter)
	if payload.CaptureInterface == "" && payload.CaptureBPFFilter == "" {
		payload.CaptureBPFFilter = "ip or ip6"
	}
	if len(payload.CaptureInterface) > 128 || strings.ContainsAny(payload.CaptureInterface, "\x00\r\n") {
		writeError(w, s.logger, http.StatusBadRequest, "Capture interface must be at most 128 characters and contain no control line breaks")
		return
	}
	if len(payload.CaptureBPFFilter) > 1024 || strings.ContainsRune(payload.CaptureBPFFilter, '\x00') {
		writeError(w, s.logger, http.StatusBadRequest, "Capture BPF filter must be at most 1024 characters and contain no null bytes")
		return
	}
	if payload.CaptureInterface != "" && payload.CaptureBPFFilter == "" {
		writeError(w, s.logger, http.StatusBadRequest, "Capture BPF filter is required when passive capture is enabled")
		return
	}
	payload.UniFiSyslogAllowedIPs = normalizeAllowedSources(payload.UniFiSyslogAllowedIPs)
	if len(payload.UniFiSyslogAllowedIPs) > 32 {
		writeError(w, s.logger, http.StatusBadRequest, "UniFi syslog allowed sources supports at most 32 entries")
		return
	}
	for _, item := range payload.UniFiSyslogAllowedIPs {
		if ip := net.ParseIP(item); ip != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(item); err != nil {
			writeError(w, s.logger, http.StatusBadRequest, "UniFi syslog allowed sources must be IP addresses or CIDR ranges")
			return
		}
	}
	if err := validateSettingsCollectorPorts(payload); err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
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
	if payload.RetentionDays < 1 {
		writeError(w, s.logger, http.StatusBadRequest, "Retention days must be at least 1")
		return
	}
	if payload.RetentionDays > config.MaxRetentionDays {
		writeError(w, s.logger, http.StatusBadRequest, fmt.Sprintf("Retention days must be at most %d", config.MaxRetentionDays))
		return
	}
	if payload.DDoSThresholdPPS < 1 || payload.DDoSThresholdFPS < 1 || payload.SYNFloodThresholdPPS < 1 || payload.UDPFloodThresholdPPS < 1 || payload.ICMPFloodThresholdPPS < 1 {
		writeError(w, s.logger, http.StatusBadRequest, "DDoS PPS thresholds must be at least 1")
		return
	}
	if payload.DDoSThresholdBPS < 1 {
		writeError(w, s.logger, http.StatusBadRequest, "DDoS BPS threshold must be at least 1")
		return
	}
	payload.DisabledAnomalyTypes = normalizeStringList(payload.DisabledAnomalyTypes)
	payload.NotifySuppressedTypes = normalizeStringList(payload.NotifySuppressedTypes)
	payload.MutedAnomalySubnets = normalizeStringList(payload.MutedAnomalySubnets)
	payload.NotifyAllowedSubnets = normalizeStringList(payload.NotifyAllowedSubnets)
	if err := validateSettingsAnomalyTypes("disabled anomaly types", payload.DisabledAnomalyTypes); err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateSettingsAnomalyTypes("notification suppressed types", payload.NotifySuppressedTypes); err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateSettingsCIDRs("muted anomaly subnets", payload.MutedAnomalySubnets); err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateSettingsCIDRs("notification allowed subnets", payload.NotifyAllowedSubnets); err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}
	if payload.NewDestinationMinHistoryBuckets < 1 || payload.NewDestinationMinHistoryBuckets > 10080 {
		writeError(w, s.logger, http.StatusBadRequest, "New destination history buckets must be between 1 and 10080")
		return
	}
	if payload.BeaconMinObservations < 3 || payload.BeaconMinObservations > 60 {
		writeError(w, s.logger, http.StatusBadRequest, "Beacon observations must be between 3 and 60")
		return
	}
	if payload.BeaconMinIntervalSeconds < 1 || payload.BeaconMinIntervalSeconds > 86400 {
		writeError(w, s.logger, http.StatusBadRequest, "Beacon minimum interval must be between 1 and 86400 seconds")
		return
	}
	if payload.TrafficSpikeMinPackets < 1 || payload.TrafficSpikeMinPackets > 100000000 {
		writeError(w, s.logger, http.StatusBadRequest, "Traffic spike minimum packets must be between 1 and 100000000")
		return
	}
	if payload.TrafficSpikeMinBytes < 1 {
		writeError(w, s.logger, http.StatusBadRequest, "Traffic spike minimum bytes must be at least 1")
		return
	}
	if payload.LogLevel != "debug" && payload.LogLevel != "info" && payload.LogLevel != "warn" && payload.LogLevel != "error" {
		writeError(w, s.logger, http.StatusBadRequest, "Log level must be debug, info, warn, or error")
		return
	}
	if payload.Environment != "production" && payload.Environment != "development" {
		writeError(w, s.logger, http.StatusBadRequest, "Environment must be production or development")
		return
	}
	if payload.AdminPassword != "" && len(payload.AdminPassword) < 10 {
		writeError(w, s.logger, http.StatusBadRequest, "Admin password must be at least 10 characters long")
		return
	}

	// 2. Identify changes for audit logs
	var categories []string
	if s.cfg.Port != payload.Port || !equalStringSlices(s.cfg.LocalSubnets, payload.LocalSubnets) {
		categories = append(categories, "network")
	}
	if s.cfg.NetflowPort != payload.NetflowPort ||
		s.cfg.SflowPort != payload.SflowPort ||
		s.cfg.UniFiSyslogEnabled != payload.UniFiSyslogEnabled ||
		s.cfg.UniFiSyslogPort != payload.UniFiSyslogPort ||
		!equalStringSlices(s.cfg.UniFiSyslogAllowedIPs, payload.UniFiSyslogAllowedIPs) ||
		s.cfg.SuricataEvePath != payload.SuricataEvePath ||
		s.cfg.CaptureInterface != payload.CaptureInterface ||
		s.cfg.CaptureBPFFilter != payload.CaptureBPFFilter ||
		s.cfg.CapturePromiscuous != payload.CapturePromiscuous {
		categories = append(categories, "collectors")
	}
	if s.cfg.StorageBackend != payload.StorageBackend || s.cfg.StorageDir != payload.StorageDir || s.cfg.RetentionDays != payload.RetentionDays {
		categories = append(categories, "storage")
	}
	if s.cfg.DDoSThresholdPPS != payload.DDoSThresholdPPS || s.cfg.DDoSThresholdBPS != payload.DDoSThresholdBPS || s.cfg.DDoSThresholdFPS != payload.DDoSThresholdFPS || s.cfg.SYNFloodThresholdPPS != payload.SYNFloodThresholdPPS || s.cfg.UDPFloodThresholdPPS != payload.UDPFloodThresholdPPS || s.cfg.ICMPFloodThresholdPPS != payload.ICMPFloodThresholdPPS || s.cfg.NewDestinationMinHistoryBuckets != payload.NewDestinationMinHistoryBuckets || s.cfg.BeaconMinObservations != payload.BeaconMinObservations || s.cfg.BeaconMinIntervalSeconds != payload.BeaconMinIntervalSeconds || s.cfg.TrafficSpikeMinPackets != payload.TrafficSpikeMinPackets || s.cfg.TrafficSpikeMinBytes != payload.TrafficSpikeMinBytes || !equalStringSlices(s.cfg.DisabledAnomalyTypes, payload.DisabledAnomalyTypes) || !equalStringSlices(s.cfg.MutedAnomalySubnets, payload.MutedAnomalySubnets) || !equalStringSlices(s.cfg.NotifyAllowedSubnets, payload.NotifyAllowedSubnets) || !equalStringSlices(s.cfg.NotifySuppressedTypes, payload.NotifySuppressedTypes) {
		categories = append(categories, "thresholds")
	}

	// Handle token and headers merging
	telegramTokenChanged := false
	if payload.TelegramToken != "" && payload.TelegramToken != "******" {
		if s.cfg.TelegramToken != payload.TelegramToken {
			s.cfg.TelegramToken = payload.TelegramToken
			telegramTokenChanged = true
		}
	}

	newHeaders := make(map[string]string)
	headersChanged := false
	for k, v := range payload.WebhookHeaders {
		if v == "******" {
			if oldVal, ok := s.cfg.WebhookHeaders[k]; ok {
				newHeaders[k] = oldVal
			} else {
				newHeaders[k] = ""
				headersChanged = true
			}
		} else {
			if s.cfg.WebhookHeaders[k] != v {
				headersChanged = true
			}
			newHeaders[k] = v
		}
	}
	if len(s.cfg.WebhookHeaders) != len(newHeaders) {
		headersChanged = true
	}
	s.cfg.WebhookHeaders = newHeaders

	if s.cfg.SlackWebhookURL != payload.SlackWebhookURL || s.cfg.WebhookURL != payload.WebhookURL || s.cfg.WebhookFormat != payload.WebhookFormat || s.cfg.TelegramEnabled != payload.TelegramEnabled || s.cfg.TelegramChatID != payload.TelegramChatID || telegramTokenChanged || headersChanged {
		categories = append(categories, "notifications")
	}
	if s.cfg.LogLevel != payload.LogLevel || s.cfg.Environment != payload.Environment {
		categories = append(categories, "system")
	}

	// 3. Update config struct in memory
	s.cfg.Port = payload.Port
	s.cfg.NetflowPort = payload.NetflowPort
	s.cfg.SflowPort = payload.SflowPort
	s.cfg.UniFiSyslogEnabled = payload.UniFiSyslogEnabled
	s.cfg.UniFiSyslogPort = payload.UniFiSyslogPort
	s.cfg.UniFiSyslogAllowedIPs = payload.UniFiSyslogAllowedIPs
	s.cfg.CaptureInterface = payload.CaptureInterface
	s.cfg.CaptureBPFFilter = payload.CaptureBPFFilter
	s.cfg.CapturePromiscuous = payload.CapturePromiscuous
	s.cfg.StorageDir = payload.StorageDir
	s.cfg.LogLevel = payload.LogLevel
	s.cfg.Environment = payload.Environment
	s.cfg.LocalSubnets = payload.LocalSubnets
	s.cfg.SlackWebhookURL = payload.SlackWebhookURL
	s.cfg.WebhookURL = payload.WebhookURL
	s.cfg.WebhookFormat = payload.WebhookFormat
	s.cfg.TelegramEnabled = payload.TelegramEnabled
	s.cfg.TelegramChatID = payload.TelegramChatID
	s.cfg.StorageBackend = payload.StorageBackend
	s.cfg.FirstRunCompleted = payload.FirstRunCompleted
	s.cfg.RetentionDays = payload.RetentionDays
	s.cfg.DisabledAnomalyTypes = payload.DisabledAnomalyTypes
	s.cfg.MutedAnomalySubnets = payload.MutedAnomalySubnets
	s.cfg.NotifyAllowedSubnets = payload.NotifyAllowedSubnets
	s.cfg.NotifySuppressedTypes = payload.NotifySuppressedTypes
	s.cfg.NewDestinationMinHistoryBuckets = payload.NewDestinationMinHistoryBuckets
	s.cfg.BeaconMinObservations = payload.BeaconMinObservations
	s.cfg.BeaconMinIntervalSeconds = payload.BeaconMinIntervalSeconds
	s.cfg.TrafficSpikeMinPackets = payload.TrafficSpikeMinPackets
	s.cfg.TrafficSpikeMinBytes = payload.TrafficSpikeMinBytes
	s.cfg.DDoSThresholdPPS = payload.DDoSThresholdPPS
	s.cfg.DDoSThresholdBPS = payload.DDoSThresholdBPS
	s.cfg.DDoSThresholdFPS = payload.DDoSThresholdFPS
	s.cfg.SYNFloodThresholdPPS = payload.SYNFloodThresholdPPS
	s.cfg.UDPFloodThresholdPPS = payload.UDPFloodThresholdPPS
	s.cfg.ICMPFloodThresholdPPS = payload.ICMPFloodThresholdPPS
	s.cfg.SuricataEvePath = payload.SuricataEvePath

	passwordChanged := false
	if payload.AdminPassword != "" {
		hash, err := hashPassword(payload.AdminPassword)
		if err != nil {
			writeError(w, s.logger, http.StatusInternalServerError, "failed to hash password")
			return
		}
		s.cfg.AdminPasswordHash = hash
		passwordChanged = true
		categories = append(categories, "access")
	}

	// 4. Persist back to disk if path is provided
	if s.configPath != "" {
		if err := config.SaveConfig(s.configPath, s.cfg); err != nil {
			s.logger.Error("Failed persisting settings to config file", slog.String("path", s.configPath), slog.String("error", err.Error()))
			writeError(w, s.logger, http.StatusInternalServerError, "failed to persist settings to disk")
			return
		}
		s.logger.Info("Saved configuration settings back to disk", slog.String("path", s.configPath))
	}

	// 5. Propagate updates dynamically to running engines
	if s.profiler != nil {
		s.profiler.UpdateLocalSubnets(s.cfg.LocalSubnets)
	}
	if s.ddosDetector != nil {
		s.ddosDetector.UpdateLocalSubnets(s.cfg.LocalSubnets)
	}
	if s.baselineEngine != nil {
		s.baselineEngine.UpdateThresholds(uint64(s.cfg.TrafficSpikeMinBytes), uint64(s.cfg.TrafficSpikeMinPackets))
	}
	if s.anomalyEngine != nil {
		s.anomalyEngine.UpdateConfig(s.cfg)
	}
	if s.webhookEngine != nil {
		s.webhookEngine.UpdateConfig(s.cfg.SlackWebhookURL, s.cfg.WebhookURL, s.cfg.WebhookFormat, s.cfg.WebhookHeaders, s.cfg.TelegramEnabled, s.cfg.TelegramToken, s.cfg.TelegramChatID)
		s.webhookEngine.UpdateNoiseControls(webhook.NoiseControls{SuppressedTypes: s.cfg.NotifySuppressedTypes, AllowedSubnets: s.cfg.NotifyAllowedSubnets})
	}

	// 6. Log granular audit actions
	if s.deviceRepo != nil {
		for _, cat := range categories {
			action := fmt.Sprintf("update_settings_%s", cat)
			details := fmt.Sprintf("Updated dynamic configuration parameters in section: %s", cat)
			if cat == "access" && passwordChanged {
				details = "Administrator password updated successfully"
			}
			_ = s.deviceRepo.SaveAuditLog(r.Context(), action, details)
		}
		if len(categories) == 0 {
			_ = s.deviceRepo.SaveAuditLog(r.Context(), "update_settings", "Settings POST request processed with no configuration modifications")
		}
	}

	// Mask token in response payload
	if payload.TelegramToken != "" {
		payload.TelegramToken = "******"
	}
	payload.WebhookHeaders = maskedHeaders(payload.WebhookHeaders)
	payload.AdminPassword = ""

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Error("Failed to encode settings response", slog.String("error", err.Error()))
	}
}

func normalizeAllowedSources(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func validateSettingsCollectorPorts(payload SettingsPayload) error {
	used := make(map[int]string)
	for _, item := range []struct {
		name    string
		port    int
		enabled bool
	}{
		{name: "NetFlow", port: payload.NetflowPort, enabled: payload.NetflowPort > 0},
		{name: "sFlow", port: payload.SflowPort, enabled: payload.SflowPort > 0},
		{name: "UniFi syslog", port: payload.UniFiSyslogPort, enabled: payload.UniFiSyslogEnabled && payload.UniFiSyslogPort > 0},
	} {
		if !item.enabled {
			continue
		}
		if previous, ok := used[item.port]; ok {
			return fmt.Errorf("%s port conflicts with %s on UDP port %d", item.name, previous, item.port)
		}
		used[item.port] = item.name
	}
	return nil
}

func normalizeStringList(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func validateSettingsAnomalyTypes(label string, items []string) error {
	if len(items) > 64 {
		return fmt.Errorf("%s supports at most 64 entries", label)
	}
	for _, item := range items {
		if !config.IsKnownAnomalyType(item) {
			return fmt.Errorf("invalid %s entry: %s", label, item)
		}
	}
	return nil
}

func validateSettingsCIDRs(label string, items []string) error {
	if len(items) > 64 {
		return fmt.Errorf("%s supports at most 64 entries", label)
	}
	for _, item := range items {
		if _, _, err := net.ParseCIDR(item); err != nil {
			return fmt.Errorf("invalid %s entry: %s", label, item)
		}
	}
	return nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// handleTestChannel synchronously tests a Slack/Telegram/generic Webhook channel and returns the remote response.
func (s *APIServer) handleTestChannel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var payload TestChannelPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, s.logger, http.StatusBadRequest, "invalid request JSON body")
		return
	}

	if payload.Channel != "telegram" && payload.Channel != "slack" && payload.Channel != "webhook" {
		writeError(w, s.logger, http.StatusBadRequest, "invalid channel value (must be 'telegram', 'slack', or 'webhook')")
		return
	}
	if s.channelTester == nil {
		s.channelTester = NewNotificationChannelTester(http.DefaultClient)
	}
	result := s.channelTester.Test(r.Context(), s.cfg, payload)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}
