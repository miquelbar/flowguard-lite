package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miquelbar/flowguard-lite/internal/config"
)

func TestAuthSetupLoginAndProtectedAPI(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "api_auth_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	cfg := config.DefaultConfig()
	cfg.FirstRunCompleted = true
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockColl := &MockCollector{}
	server := NewAPIServer(cfg, logger, mockColl, nil, nil, nil, nil, nil, nil, nil, configPath)

	req := httptest.NewRequest(http.MethodGet, "/api/exporters", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected protected API to require auth, got %d", w.Code)
	}

	setupBody := `{"password":"correct horse battery"}`
	req = httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(setupBody))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected setup 200, got %d: %s", w.Code, w.Body.String())
	}
	if server.cfg.AdminPasswordHash == "" || strings.Contains(server.cfg.AdminPasswordHash, "correct horse battery") {
		t.Fatalf("expected stored password hash, got %q", server.cfg.AdminPasswordHash)
	}
	setupCookie := w.Result().Cookies()[0]

	req = httptest.NewRequest(http.MethodGet, "/api/exporters", nil)
	req.AddCookie(setupCookie)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected authenticated API request to succeed, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(setupCookie)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected logout 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/exporters", nil)
	req.AddCookie(setupCookie)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected logged-out cookie to be rejected, got %d", w.Code)
	}

	loginBody := `{"password":"correct horse battery"}`
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(loginBody))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuthRejectsShortPasswordAndInvalidLogin(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.FirstRunCompleted = true
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewAPIServer(cfg, logger, nil, nil, nil, nil, nil, nil, nil, nil, "")

	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", strings.NewReader(`{"password":"short"}`))
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected short password 400, got %d", w.Code)
	}

	hash, err := hashPassword("correct horse battery")
	if err != nil {
		t.Fatalf("failed hashing password: %v", err)
	}
	server.cfg.AdminPasswordHash = hash

	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"password":"wrong password"}`))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected invalid login 401, got %d", w.Code)
	}
}
