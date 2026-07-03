package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

