package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseQueryWindowValidAndCapsLimit(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/top/sources?start=2026-07-10T10:00:00Z&end=2026-07-10T11:00:00Z&limit=999",
		nil,
	)

	got, err := parseQueryWindow(req)
	if err != nil {
		t.Fatalf("parseQueryWindow returned error: %v", err)
	}

	if got.Limit != maxQueryLimit {
		t.Fatalf("expected capped limit %d, got %d", maxQueryLimit, got.Limit)
	}
	if got.Start.Format(time.RFC3339) != "2026-07-10T10:00:00Z" {
		t.Fatalf("unexpected start: %s", got.Start.Format(time.RFC3339))
	}
	if got.End.Format(time.RFC3339) != "2026-07-10T11:00:00Z" {
		t.Fatalf("unexpected end: %s", got.End.Format(time.RFC3339))
	}
}

func TestParseQueryWindowRejectsUnboundedRanges(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/top/sources?start=2026-07-01T00:00:00Z&end=2026-07-10T00:00:00Z",
		nil,
	)

	if _, err := parseQueryWindow(req); err == nil || !strings.Contains(err.Error(), "maximum limit of 7 days") {
		t.Fatalf("expected bounded range error, got %v", err)
	}
}

func TestParseBucketSeconds(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/security/timeline?bucket_seconds=900", nil)
	got, err := parseBucketSeconds(req)
	if err != nil {
		t.Fatalf("parseBucketSeconds returned error: %v", err)
	}
	if got != 900 {
		t.Fatalf("expected bucket 900, got %d", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/security/timeline?bucket_seconds=42", nil)
	if _, err := parseBucketSeconds(req); err == nil {
		t.Fatal("expected invalid bucket error")
	}
}

func TestWriteErrorPayload(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, slog.New(slog.NewTextHandler(io.Discard, nil)), http.StatusBadRequest, "bad input")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected JSON content type, got %q", got)
	}
	var payload map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode error payload: %v", err)
	}
	if payload["error"] != "bad input" {
		t.Fatalf("unexpected error payload: %+v", payload)
	}
}

func TestWriteJSONPayload(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, slog.New(slog.NewTextHandler(io.Discard, nil)), http.StatusCreated, map[string]string{"status": "ok"}, "test")

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected JSON content type, got %q", got)
	}
	var payload map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode JSON payload: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected JSON payload: %+v", payload)
	}
}

func TestRequireMethodWritesJSONError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/example", nil)
	w := httptest.NewRecorder()

	ok := requireMethod(w, req, slog.New(slog.NewTextHandler(io.Discard, nil)), http.MethodGet)
	if ok {
		t.Fatal("expected method to be rejected")
	}
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "method not allowed") {
		t.Fatalf("expected JSON method error, got %s", w.Body.String())
	}
}
