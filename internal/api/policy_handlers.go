package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/miquelbar/flowguard-lite/internal/storage"
)

// handleListPolicies returns all active policies.
func (s *APIServer) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	policies, err := s.deviceRepo.ListPolicies(r.Context())
	if err != nil {
		s.logger.Error("Failed to list policies", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "failed to query policies")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(policies)
}

// handleSavePolicy creates or updates a policy.
func (s *APIServer) handleSavePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var p storage.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, s.logger, http.StatusBadRequest, "invalid request payload")
		return
	}

	// If PUT, parse and override ID from path parameter
	if r.Method == http.MethodPut {
		idStr := r.PathValue("id")
		var id int64
		_, err := fmt.Sscanf(idStr, "%d", &id)
		if err != nil || id <= 0 {
			writeError(w, s.logger, http.StatusBadRequest, "invalid policy ID path parameter")
			return
		}
		p.ID = id
	}

	if err := s.deviceRepo.SavePolicy(r.Context(), &p); err != nil {
		s.logger.Warn("Failed to save policy", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(p)
}

// handleDeletePolicy deletes a policy.
func (s *APIServer) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	idStr := r.PathValue("id")
	var id int64
	_, err := fmt.Sscanf(idStr, "%d", &id)
	if err != nil || id <= 0 {
		writeError(w, s.logger, http.StatusBadRequest, "invalid policy ID")
		return
	}

	if err := s.deviceRepo.DeletePolicy(r.Context(), id); err != nil {
		s.logger.Error("Failed to delete policy", slog.Int64("id", id), slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "failed to delete policy")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}
