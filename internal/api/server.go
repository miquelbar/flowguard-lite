package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/flowguard/flowguard/internal/config"
)

// APIServer manages the lifecycle of the HTTP REST API server.
type APIServer struct {
	server *http.Server
	cfg    *config.Config
	logger *slog.Logger
}

// HealthResponse represents the structure of health check outputs.
type HealthResponse struct {
	Status      string `json:"status"`
	Environment string `json:"environment"`
	Timestamp   string `json:"timestamp"`
	Version     string `json:"version"`
}

// NewAPIServer creates and configures a new APIServer instance.
func NewAPIServer(cfg *config.Config, logger *slog.Logger) *APIServer {
	mux := http.NewServeMux()
	s := &APIServer{
		cfg:    cfg,
		logger: logger,
		server: &http.Server{
			Addr:         ":" + cfg.Port,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
	}

	mux.HandleFunc("/health", s.handleHealth)

	return s
}

// Start launches the HTTP server and blocks until it is stopped or encounters an error.
func (s *APIServer) Start() error {
	s.logger.Info("Starting HTTP API Server", slog.String("port", s.cfg.Port))
	if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server failure: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the HTTP server within the provided context deadline.
func (s *APIServer) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down HTTP API Server gracefully...")
	return s.server.Shutdown(ctx)
}

// handleHealth returns basic service availability status in JSON format.
func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	res := HealthResponse{
		Status:      "OK",
		Environment: s.cfg.Environment,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Version:     "0.1.0",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		s.logger.Error("Failed to encode health response", slog.String("error", err.Error()))
	}
}
