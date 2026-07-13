package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

const (
	defaultQueryLimit = 10
	maxQueryLimit     = 100
	maxQueryRange     = 7 * 24 * time.Hour
)

type queryWindow struct {
	Start time.Time
	End   time.Time
	Limit int
}

func parseQueryWindow(r *http.Request) (queryWindow, error) {
	q := r.URL.Query()

	limit, err := parseBoundedPositiveInt(q.Get("limit"), defaultQueryLimit, maxQueryLimit, "limit")
	if err != nil {
		return queryWindow{}, err
	}

	end := time.Now()
	if endStr := q.Get("end"); endStr != "" {
		val, err := time.Parse(time.RFC3339, endStr)
		if err != nil {
			return queryWindow{}, errors.New("invalid end timestamp; must be RFC3339 formatted")
		}
		end = val
	}

	start := end.Add(-1 * time.Hour)
	if startStr := q.Get("start"); startStr != "" {
		val, err := time.Parse(time.RFC3339, startStr)
		if err != nil {
			return queryWindow{}, errors.New("invalid start timestamp; must be RFC3339 formatted")
		}
		start = val
	}

	if start.After(end) {
		return queryWindow{}, errors.New("start timestamp cannot be after end timestamp")
	}
	if end.Sub(start) > maxQueryRange {
		return queryWindow{}, errors.New("query range exceeds maximum limit of 7 days")
	}

	return queryWindow{Start: start, End: end, Limit: limit}, nil
}

func parseLimit(r *http.Request, defaultValue, maxValue int) (int, error) {
	return parseBoundedPositiveInt(r.URL.Query().Get("limit"), defaultValue, maxValue, "limit")
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

func parseBoundedPositiveInt(raw string, defaultValue, maxValue int, name string) (int, error) {
	if raw == "" {
		return defaultValue, nil
	}

	val, err := strconv.Atoi(raw)
	if err != nil || val <= 0 {
		return 0, errors.New("invalid " + name + " parameter; must be a positive integer")
	}
	if val > maxValue {
		return maxValue, nil
	}
	return val, nil
}

func requireMethod(w http.ResponseWriter, r *http.Request, logger *slog.Logger, method string) bool {
	if r.Method == method {
		return true
	}
	writeError(w, logger, http.StatusMethodNotAllowed, "method not allowed")
	return false
}

// writeError outputs standardized JSON error payloads.
func writeError(w http.ResponseWriter, logger *slog.Logger, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	errPayload := map[string]string{"error": msg}
	if err := json.NewEncoder(w).Encode(errPayload); err != nil {
		logger.Error("Failed encoding JSON error response", slog.String("error", err.Error()))
	}
}

func writeJSON(w http.ResponseWriter, logger *slog.Logger, status int, payload any, label string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logger.Error("Failed to encode "+label+" response", slog.String("error", err.Error()))
	}
}
