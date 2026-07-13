package api

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"github.com/miquelbar/flowguard-lite/internal/storage"
)

// handleListUniFiEvents handles GET /api/security/unifi-events.
func (s *APIServer) handleListUniFiEvents(w http.ResponseWriter, r *http.Request) {
	uRepo, ok := s.deviceRepo.(storage.UniFiEventRepository)
	if !ok {
		writeError(w, s.logger, http.StatusInternalServerError, "UniFi event repository is not configured")
		return
	}

	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if val, err := strconv.Atoi(lStr); err == nil && val > 0 {
			limit = val
			if limit > 100 {
				limit = 100
			}
		}
	}

	events, err := uRepo.ListUniFiEvents(r.Context(), limit)
	if err != nil {
		s.logger.Error("Failed to list UniFi events", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(events); err != nil {
		s.logger.Error("Failed to encode UniFi events list response", slog.String("error", err.Error()))
	}
}

// handleGetDeviceUniFiEvents handles GET /api/devices/{ip}/unifi-events.
func (s *APIServer) handleGetDeviceUniFiEvents(w http.ResponseWriter, r *http.Request) {
	uRepo, ok := s.deviceRepo.(storage.UniFiEventRepository)
	if !ok {
		writeError(w, s.logger, http.StatusInternalServerError, "UniFi event repository is not configured")
		return
	}

	ip := r.PathValue("ip")
	if net.ParseIP(ip) == nil {
		writeError(w, s.logger, http.StatusBadRequest, "invalid IP address format")
		return
	}

	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if val, err := strconv.Atoi(lStr); err == nil && val > 0 {
			limit = val
			if limit > 100 {
				limit = 100
			}
		}
	}

	events, err := uRepo.GetUniFiEventsForIP(r.Context(), ip, limit)
	if err != nil {
		s.logger.Error("Failed to query UniFi events for IP", slog.String("ip", ip), slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(events); err != nil {
		s.logger.Error("Failed to encode device UniFi events response", slog.String("ip", ip), slog.String("error", err.Error()))
	}
}
