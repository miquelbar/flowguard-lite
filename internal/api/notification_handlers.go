package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/storage"
)

// handleListNotificationRules returns all active notification routing rules.
func (s *APIServer) handleListNotificationRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	rules, err := s.deviceRepo.ListNotificationRules(r.Context())
	if err != nil {
		s.logger.Error("Failed to list notification rules", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "failed to query notification rules")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rules)
}

// handleSaveNotificationRule creates or updates a notification rule.
func (s *APIServer) handleSaveNotificationRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var rule storage.NotificationRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeError(w, s.logger, http.StatusBadRequest, "invalid request payload")
		return
	}

	if rule.Name == "" {
		writeError(w, s.logger, http.StatusBadRequest, "notification rule name cannot be empty")
		return
	}

	// Validate rule severity
	switch strings.ToLower(rule.SeverityMin) {
	case storage.SeverityLow, storage.SeverityMedium, storage.SeverityHigh:
		// valid
	case "":
		rule.SeverityMin = storage.SeverityLow
	default:
		writeError(w, s.logger, http.StatusBadRequest, "invalid severity threshold: must be 'low', 'medium', or 'high'")
		return
	}

	// Validate channel targets
	if len(rule.ChannelTargets) == 0 {
		writeError(w, s.logger, http.StatusBadRequest, "at least one channel target must be selected")
		return
	}
	for _, ch := range rule.ChannelTargets {
		switch strings.ToLower(ch) {
		case storage.NotificationChannelWebhook, storage.NotificationChannelSlack, storage.NotificationChannelTelegram:
			// valid
		default:
			writeError(w, s.logger, http.StatusBadRequest, fmt.Sprintf("invalid channel target: '%s'", ch))
			return
		}
	}

	// Validate scope & target CIDR/IP
	switch rule.Scope {
	case storage.NotificationScopeGlobal:
		rule.Target = ""
	case storage.NotificationScopeIP:
		if net.ParseIP(rule.Target) == nil {
			writeError(w, s.logger, http.StatusBadRequest, "invalid target IP address")
			return
		}
	case storage.NotificationScopeSubnet:
		_, _, err := net.ParseCIDR(rule.Target)
		if err != nil {
			writeError(w, s.logger, http.StatusBadRequest, "invalid target CIDR range")
			return
		}
	case "":
		rule.Scope = storage.NotificationScopeGlobal
		rule.Target = ""
	default:
		writeError(w, s.logger, http.StatusBadRequest, "invalid scope: must be 'global', 'ip', or 'subnet'")
		return
	}

	if rule.CooldownSeconds < 0 {
		rule.CooldownSeconds = 0
	}

	// If PUT, parse and override ID from path parameter
	if r.Method == http.MethodPut {
		idStr := r.PathValue("id")
		var id int64
		_, err := fmt.Sscanf(idStr, "%d", &id)
		if err != nil || id <= 0 {
			writeError(w, s.logger, http.StatusBadRequest, "invalid rule ID path parameter")
			return
		}
		rule.ID = id
	}

	if err := s.deviceRepo.SaveNotificationRule(r.Context(), &rule); err != nil {
		s.logger.Warn("Failed to save notification rule", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rule)
}

// handleDeleteNotificationRule deletes a notification rule.
func (s *APIServer) handleDeleteNotificationRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	idStr := r.PathValue("id")
	var id int64
	_, err := fmt.Sscanf(idStr, "%d", &id)
	if err != nil || id <= 0 {
		writeError(w, s.logger, http.StatusBadRequest, "invalid notification rule ID")
		return
	}

	if err := s.deviceRepo.DeleteNotificationRule(r.Context(), id); err != nil {
		s.logger.Error("Failed to delete notification rule", slog.Int64("id", id), slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "failed to delete notification rule")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// handleListNotificationLogs returns recent notification logs.
func (s *APIServer) handleListNotificationLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	limit := 100
	limitStr := r.URL.Query().Get("limit")
	if limitStr != "" {
		var customLimit int
		_, err := fmt.Sscanf(limitStr, "%d", &customLimit)
		if err == nil && customLimit > 0 {
			limit = customLimit
		}
	}

	logs, err := s.deviceRepo.ListNotificationLogs(r.Context(), limit)
	if err != nil {
		s.logger.Error("Failed to list notification logs", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "failed to query notification logs")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(logs)
}

// handleTestNotificationRule retrieves the rule, generates a matching mock anomaly, and dispatches it directly via webhookEngine.
func (s *APIServer) handleTestNotificationRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.webhookEngine == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "webhook engine is not initialized")
		return
	}

	idStr := r.PathValue("id")
	var id int64
	_, err := fmt.Sscanf(idStr, "%d", &id)
	if err != nil || id <= 0 {
		writeError(w, s.logger, http.StatusBadRequest, "invalid notification rule ID")
		return
	}

	rule, err := s.deviceRepo.GetNotificationRule(r.Context(), id)
	if err != nil {
		writeError(w, s.logger, http.StatusNotFound, "notification rule not found")
		return
	}

	// Generate matching mock anomaly
	mockIP := "192.168.1.99"
	if rule.Scope == storage.NotificationScopeIP && rule.Target != "" {
		mockIP = rule.Target
	} else if rule.Scope == storage.NotificationScopeSubnet && rule.Target != "" {
		if ip, _, err := net.ParseCIDR(rule.Target); err == nil {
			mockIP = ip.String()
		}
	}

	mockType := "test_alert"
	if len(rule.AlertTypes) > 0 {
		mockType = rule.AlertTypes[0]
	}

	mockSeverity := rule.SeverityMin
	if mockSeverity == "" {
		mockSeverity = "info"
	}

	testAnomaly := &storage.Anomaly{
		IP:          mockIP,
		Type:        mockType,
		Description: fmt.Sprintf("FlowGuard Lite notification test alert for rule: %s", rule.Name),
		Severity:    mockSeverity,
		Status:      storage.AnomalyStatusActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Save test anomaly to satisfy foreign key constraints for logs
	err = s.deviceRepo.SaveAnomaly(r.Context(), testAnomaly)
	if err != nil {
		s.logger.Error("Failed to save test anomaly for notification rule test", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "failed to persist test anomaly")
		return
	}

	s.logger.Info("Dispatching test notification rule alert...", slog.Int64("rule_id", id))
	s.webhookEngine.SendTestAlert(r.Context(), rule, testAnomaly)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":     "test alert dispatched successfully",
		"anomaly_id": fmt.Sprintf("%d", testAnomaly.ID),
	})
}
