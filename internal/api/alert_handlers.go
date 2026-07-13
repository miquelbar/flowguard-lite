package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/miquelbar/flowguard-lite/internal/storage"
)

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

	if req.Status != storage.AnomalyStatusActive &&
		req.Status != storage.AnomalyStatusAcknowledged &&
		req.Status != storage.AnomalyStatusSilenced {
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
