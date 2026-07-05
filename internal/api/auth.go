package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/flowguard/flowguard/internal/config"
)

const (
	sessionCookieName = "flowguard_session"
	passwordMinLength = 10
	passwordHashIters = 210000
	sessionTTL        = 12 * time.Hour
)

type authSession struct {
	expiresAt time.Time
}

type loginAttempt struct {
	count       int
	windowFrom  time.Time
	lockedUntil time.Time
}

func randomToken(bytesLen int) (string, error) {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashPassword(password string) (string, error) {
	if len(password) < passwordMinLength {
		return "", fmt.Errorf("password must be at least %d characters", passwordMinLength)
	}
	salt, err := randomToken(16)
	if err != nil {
		return "", err
	}
	saltBytes, err := base64.RawURLEncoding.DecodeString(salt)
	if err != nil {
		return "", err
	}
	dk := pbkdf2SHA256([]byte(password), saltBytes, passwordHashIters, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", passwordHashIters, salt, base64.RawURLEncoding.EncodeToString(dk)), nil
}

func verifyPassword(storedHash, password string) bool {
	parts := strings.Split(storedHash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iters, err := strconv.Atoi(parts[1])
	if err != nil || iters <= 0 {
		return false
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	actual := pbkdf2SHA256([]byte(password), salt, iters, len(expected))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	hLen := 32
	numBlocks := (keyLen + hLen - 1) / hLen
	var dk []byte
	for block := 1; block <= numBlocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		var intBlock [4]byte
		binary.BigEndian.PutUint32(intBlock[:], uint32(block))
		mac.Write(intBlock[:])
		u := mac.Sum(nil)
		t := make([]byte, hLen)
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func (s *APIServer) authRequired() bool {
	return s.cfg.AdminPasswordHash != "" || s.cfg.FirstRunCompleted
}

func (s *APIServer) setupRequired() bool {
	return s.cfg.AdminPasswordHash == ""
}

func (s *APIServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.isPublicPath(r) || !s.authRequired() {
			next.ServeHTTP(w, r)
			return
		}
		if s.validSession(r) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeError(w, s.logger, http.StatusUnauthorized, "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *APIServer) isPublicPath(r *http.Request) bool {
	path := r.URL.Path
	if path == "/health" || path == "/api/health" || path == "/metrics" {
		return true
	}
	if path == "/api/auth/status" || path == "/api/auth/login" || path == "/api/auth/logout" || path == "/api/auth/setup" {
		return true
	}
	if !strings.HasPrefix(path, "/api/") {
		return true
	}
	return false
}

func (s *APIServer) validSession(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	s.authMu.Lock()
	defer s.authMu.Unlock()
	session, ok := s.sessions[cookie.Value]
	if !ok {
		return false
	}
	if time.Now().After(session.expiresAt) {
		delete(s.sessions, cookie.Value)
		return false
	}
	return true
}

func (s *APIServer) createSession(w http.ResponseWriter, r *http.Request) error {
	token, err := randomToken(32)
	if err != nil {
		return err
	}
	s.authMu.Lock()
	s.sessions[token] = authSession{expiresAt: time.Now().Add(sessionTTL)}
	s.authMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecureRequest(r),
	})
	return nil
}

func (s *APIServer) clearSession(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.authMu.Lock()
		delete(s.sessions, cookie.Value)
		s.authMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecureRequest(r),
	})
}

func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *APIServer) checkLoginRateLimit(r *http.Request) error {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	now := time.Now()
	s.authMu.Lock()
	defer s.authMu.Unlock()
	attempt := s.loginAttempts[host]
	if now.Before(attempt.lockedUntil) {
		return errors.New("too many failed login attempts; try again later")
	}
	if now.Sub(attempt.windowFrom) > 5*time.Minute {
		attempt = loginAttempt{windowFrom: now}
	}
	attempt.count++
	if attempt.count > 5 {
		attempt.lockedUntil = now.Add(5 * time.Minute)
	}
	s.loginAttempts[host] = attempt
	if now.Before(attempt.lockedUntil) {
		return errors.New("too many failed login attempts; try again later")
	}
	return nil
}

func (s *APIServer) resetLoginRateLimit(r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	s.authMu.Lock()
	delete(s.loginAttempts, host)
	s.authMu.Unlock()
}

type authStatusPayload struct {
	Authenticated bool `json:"authenticated"`
	SetupRequired bool `json:"setup_required"`
}

func (s *APIServer) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	payload := authStatusPayload{
		Authenticated: s.validSession(r) || !s.authRequired(),
		SetupRequired: s.setupRequired(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *APIServer) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.setupRequired() {
		writeError(w, s.logger, http.StatusConflict, "admin password is already configured")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, s.logger, http.StatusBadRequest, "invalid request JSON body")
		return
	}
	hash, err := hashPassword(req.Password)
	if err != nil {
		writeError(w, s.logger, http.StatusBadRequest, err.Error())
		return
	}
	s.cfg.AdminPasswordHash = hash
	if s.cfg.SessionSecret == "" {
		secret, err := randomToken(32)
		if err != nil {
			writeError(w, s.logger, http.StatusInternalServerError, "failed generating session secret")
			return
		}
		s.cfg.SessionSecret = secret
	}
	if s.configPath != "" {
		if err := config.SaveConfig(s.configPath, s.cfg); err != nil {
			writeError(w, s.logger, http.StatusInternalServerError, "failed to persist auth settings")
			return
		}
	}
	if s.deviceRepo != nil {
		_ = s.deviceRepo.SaveAuditLog(r.Context(), "auth_setup", "Configured initial admin password")
	}
	if err := s.createSession(w, r); err != nil {
		writeError(w, s.logger, http.StatusInternalServerError, "failed creating session")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(authStatusPayload{Authenticated: true, SetupRequired: false})
}

func (s *APIServer) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.setupRequired() {
		writeError(w, s.logger, http.StatusPreconditionRequired, "admin password setup required")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, s.logger, http.StatusBadRequest, "invalid request JSON body")
		return
	}
	if err := s.checkLoginRateLimit(r); err != nil {
		writeError(w, s.logger, http.StatusTooManyRequests, err.Error())
		return
	}
	if !verifyPassword(s.cfg.AdminPasswordHash, req.Password) {
		writeError(w, s.logger, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.resetLoginRateLimit(r)
	if err := s.createSession(w, r); err != nil {
		writeError(w, s.logger, http.StatusInternalServerError, "failed creating session")
		return
	}
	if s.deviceRepo != nil {
		_ = s.deviceRepo.SaveAuditLog(r.Context(), "auth_login", "Admin login succeeded")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(authStatusPayload{Authenticated: true, SetupRequired: false})
}

func (s *APIServer) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, s.logger, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.clearSession(w, r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(authStatusPayload{Authenticated: false, SetupRequired: s.setupRequired()})
}
