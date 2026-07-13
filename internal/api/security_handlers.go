package api

import (
	"log/slog"
	"net/http"
)

func (s *APIServer) handleSecuritySummary(w http.ResponseWriter, r *http.Request) {
	if s.deviceRepo == nil || s.riskEngine == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "security summary dependencies are not configured")
		return
	}

	res, err := newSecurityQueryService(s.cfg, s.deviceRepo, s.riskEngine, s.collector).BuildSummary(r.Context())
	if err != nil {
		s.logger.Error("Failed building security summary", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database error")
		return
	}

	writeJSON(w, s.logger, http.StatusOK, res, "security summary")
}

func (s *APIServer) handleSecurityTimeline(w http.ResponseWriter, r *http.Request) {
	if s.deviceRepo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "device metadata repository is not configured")
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

	res, err := newSecurityQueryService(s.cfg, s.deviceRepo, s.riskEngine, s.collector).BuildTimeline(r.Context(), start, end, bucketSeconds)
	if err != nil {
		s.logger.Error("Failed querying active anomalies for security timeline", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database error")
		return
	}

	writeJSON(w, s.logger, http.StatusOK, res, "security timeline")
}
