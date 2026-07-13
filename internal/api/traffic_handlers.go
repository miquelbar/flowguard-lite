package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/flow"
)

// parseQueryParams parses start, end and limit parameters from request query.
func parseQueryParams(r *http.Request) (time.Time, time.Time, int, error) {
	window, err := parseQueryWindow(r)
	if err != nil {
		return time.Time{}, time.Time{}, 0, err
	}
	return window.Start, window.End, window.Limit, nil
}

// handleTopSources processes queries for the top traffic sources.
func (s *APIServer) handleTopSources(w http.ResponseWriter, r *http.Request) {
	s.handleFlowTopResponse(w, r, "top sources", func(start, end time.Time, limit int) ([]flow.TopResult, error) {
		return s.repo.GetTopSources(r.Context(), start, end, limit)
	})
}

// handleTopDestinations processes queries for the top traffic destinations.
func (s *APIServer) handleTopDestinations(w http.ResponseWriter, r *http.Request) {
	s.handleFlowTopResponse(w, r, "top destinations", func(start, end time.Time, limit int) ([]flow.TopResult, error) {
		return s.repo.GetTopDestinations(r.Context(), start, end, limit)
	})
}

// handleTopPorts processes queries for the top destination ports.
func (s *APIServer) handleTopPorts(w http.ResponseWriter, r *http.Request) {
	s.handleFlowTopResponse(w, r, "top ports", func(start, end time.Time, limit int) ([]flow.TopResult, error) {
		return s.repo.GetTopPorts(r.Context(), start, end, limit)
	})
}

// handleTopProtocols processes queries for the top transport protocols.
func (s *APIServer) handleTopProtocols(w http.ResponseWriter, r *http.Request) {
	s.handleFlowTopResponse(w, r, "top protocols", func(start, end time.Time, limit int) ([]flow.TopResult, error) {
		return s.repo.GetTopProtocols(r.Context(), start, end, limit)
	})
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

type flowAggregateRecordRepository interface {
	QueryFlowAggregateRecords(ctx context.Context, start, end time.Time, q string, protocol, dstPort, limit int) ([]flow.AggregateRecord, error)
}

func (s *APIServer) handleTrafficRecords(w http.ResponseWriter, r *http.Request) {
	if s.repo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "database repository is not configured")
		return
	}
	recordRepo, ok := s.repo.(flowAggregateRecordRepository)
	if !ok {
		writeError(w, s.logger, http.StatusInternalServerError, "flow aggregate explorer is not supported by this storage backend")
		return
	}

	start, end, limit, err := parseQueryParams(r)
	if err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}
	if limit > 500 {
		limit = 500
	}

	protocol := 0
	if raw := r.URL.Query().Get("protocol"); raw != "" {
		protocol, err = strconv.Atoi(raw)
		if err != nil || protocol < 0 || protocol > 255 {
			writeError(w, s.logger, http.StatusBadRequest, "protocol must be an integer between 0 and 255")
			return
		}
	}

	dstPort := 0
	if raw := r.URL.Query().Get("dst_port"); raw != "" {
		dstPort, err = strconv.Atoi(raw)
		if err != nil || dstPort < 0 || dstPort > 65535 {
			writeError(w, s.logger, http.StatusBadRequest, "dst_port must be an integer between 0 and 65535")
			return
		}
	}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 128 {
		writeError(w, s.logger, http.StatusBadRequest, "q must be 128 characters or fewer")
		return
	}

	res, err := recordRepo.QueryFlowAggregateRecords(r.Context(), start, end, q, protocol, dstPort, limit)
	if err != nil {
		s.logger.Error("Failed to query flow aggregate records", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database query error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		s.logger.Error("Failed to encode flow aggregate records response", slog.String("error", err.Error()))
	}
}

func (s *APIServer) handleStatsProtocols(w http.ResponseWriter, r *http.Request) {
	s.handleFlowTopResponse(w, r, "stats protocols", func(start, end time.Time, limit int) ([]flow.TopResult, error) {
		return s.repo.GetTopProtocols(r.Context(), start, end, limit)
	})
}

func (s *APIServer) handleStatsTopDevices(w http.ResponseWriter, r *http.Request) {
	s.handleFlowTopResponse(w, r, "stats top devices", func(start, end time.Time, limit int) ([]flow.TopResult, error) {
		return s.repo.GetTopDevicesByVolume(r.Context(), start, end, limit)
	})
}

func (s *APIServer) handleStatsHeatmap(w http.ResponseWriter, r *http.Request) {
	if s.repo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "database repository is not configured")
		return
	}
	start, end, limit, err := parseQueryParams(r)
	if err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}
	if limit > 20 {
		limit = 20
	}
	res, err := s.repo.GetDeviceActivityHeatmap(r.Context(), start, end, limit)
	if err != nil {
		s.logger.Error("Failed to query stats heatmap", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database query error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		s.logger.Error("Failed to encode stats heatmap response", slog.String("error", err.Error()))
	}
}

func (s *APIServer) handleStatsCollectorHealth(w http.ResponseWriter, r *http.Request) {
	if s.collector == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "collector is not configured")
		return
	}

	limit := 120
	if raw := r.URL.Query().Get("limit"); raw != "" {
		val, err := strconv.Atoi(raw)
		if err != nil || val <= 0 {
			writeError(w, s.logger, http.StatusBadRequest, "invalid limit parameter; must be a positive integer")
			return
		}
		limit = val
	}
	if limit > maxCollectorHealthSamples {
		limit = maxCollectorHealthSamples
	}

	samples := s.collectorHealthSamples(limit)
	if len(samples) == 0 {
		s.recordCollectorStats(time.Now().UTC())
		samples = s.collectorHealthSamples(limit)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(samples); err != nil {
		s.logger.Error("Failed to encode collector health stats response", slog.String("error", err.Error()))
	}
}

func (s *APIServer) handleFlowTopResponse(w http.ResponseWriter, r *http.Request, label string, query func(start, end time.Time, limit int) ([]flow.TopResult, error)) {
	if s.repo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "database repository is not configured")
		return
	}
	start, end, limit, err := parseQueryParams(r)
	if err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}
	res, err := query(start, end, limit)
	if err != nil {
		s.logger.Error("Failed to query "+label, slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database query error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		s.logger.Error("Failed to encode "+label+" response", slog.String("error", err.Error()))
	}
}
