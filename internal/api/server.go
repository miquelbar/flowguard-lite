package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/baseline"
	"github.com/miquelbar/flowguard-lite/internal/collector"
	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/ddos"
	"github.com/miquelbar/flowguard-lite/internal/device"
	"github.com/miquelbar/flowguard-lite/internal/risk"
	"github.com/miquelbar/flowguard-lite/internal/storage"
	"github.com/miquelbar/flowguard-lite/internal/ui"
	"github.com/miquelbar/flowguard-lite/internal/webhook"
)

// CollectorProvider defines the contract for fetching collector stats and exporters.
type CollectorProvider interface {
	GetStats() collector.Stats
	GetExporters() []collector.ExporterMetadata
}

// APIServer manages the lifecycle of the HTTP REST API server.
type APIServer struct {
	server         *http.Server
	cfg            *config.Config
	logger         *slog.Logger
	collector      CollectorProvider
	repo           storage.FlowRepository
	deviceRepo     storage.DeviceRepository
	baselineEngine *baseline.BaselineEngine
	riskEngine     *risk.RiskEngine
	profiler       *device.DeviceProfiler
	ddosDetector   *ddos.DDoSDetector
	webhookEngine  *webhook.WebhookEngine
	channelTester  *NotificationChannelTester
	configPath     string
	authMu         sync.Mutex
	sessions       map[string]authSession
	loginAttempts  map[string]loginAttempt
	statsMu        sync.RWMutex
	statsSamples   []CollectorHealthSample
	statsCancel    context.CancelFunc
}

const maxCollectorHealthSamples = 240

// HealthResponse represents the structure of health check outputs.
type HealthResponse struct {
	Status       string           `json:"status"`
	Healthy      bool             `json:"healthy"`
	ErrorMessage string           `json:"error_message,omitempty"`
	Environment  string           `json:"environment"`
	Timestamp    string           `json:"timestamp"`
	Version      string           `json:"version"`
	Collector    *collector.Stats `json:"collector,omitempty"`
	LocalIPs     []string         `json:"local_ips,omitempty"`
}

// CollectorHealthSample is a bounded point-in-time snapshot used for Overview trends.
type CollectorHealthSample struct {
	Timestamp       time.Time `json:"timestamp"`
	PacketsReceived uint64    `json:"packets_received"`
	PacketsDropped  uint64    `json:"packets_dropped"`
	DecodeErrors    uint64    `json:"decode_errors"`
	QueueDepth      int       `json:"queue_depth"`
}

// NewAPIServer creates and configures a new APIServer instance.
func NewAPIServer(
	cfg *config.Config,
	logger *slog.Logger,
	coll CollectorProvider,
	repo storage.FlowRepository,
	deviceRepo storage.DeviceRepository,
	baselineEngine *baseline.BaselineEngine,
	riskEngine *risk.RiskEngine,
	profiler *device.DeviceProfiler,
	ddosDetector *ddos.DDoSDetector,
	webhookEngine *webhook.WebhookEngine,
	configPath string,
) *APIServer {
	mux := http.NewServeMux()
	s := &APIServer{
		cfg:            cfg,
		logger:         logger,
		collector:      coll,
		repo:           repo,
		deviceRepo:     deviceRepo,
		baselineEngine: baselineEngine,
		riskEngine:     riskEngine,
		profiler:       profiler,
		ddosDetector:   ddosDetector,
		webhookEngine:  webhookEngine,
		channelTester:  NewNotificationChannelTester(nil),
		configPath:     configPath,
		sessions:       make(map[string]authSession),
		loginAttempts:  make(map[string]loginAttempt),
		server: &http.Server{
			Addr:         ":" + cfg.Port,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
	}

	// Dynamic routing matching PLAN.md
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("/api/exporters", s.handleExporters)
	mux.HandleFunc("/api/top/sources", s.handleTopSources)
	mux.HandleFunc("/api/top/destinations", s.handleTopDestinations)
	mux.HandleFunc("/api/top/ports", s.handleTopPorts)
	mux.HandleFunc("/api/top/protocols", s.handleTopProtocols)
	mux.HandleFunc("GET /api/traffic/timeseries", s.handleTrafficTimeSeries)
	mux.HandleFunc("GET /api/traffic/records", s.handleTrafficRecords)

	mux.HandleFunc("GET /api/devices", s.handleListDevices)
	mux.HandleFunc("GET /api/devices/{ip}", s.handleGetDeviceProfile)
	mux.HandleFunc("PUT /api/devices/{ip}/label", s.handleUpdateDeviceLabel)
	mux.HandleFunc("GET /api/devices/{ip}/baseline", s.handleGetDeviceBaseline)
	mux.HandleFunc("GET /api/devices/{ip}/flows", s.handleGetDeviceFlows)
	mux.HandleFunc("GET /api/devices/{ip}/unifi-events", s.handleGetDeviceUniFiEvents)

	// Anomaly detection endpoints (Go 1.22+ wildcard patterns)
	mux.HandleFunc("GET /api/anomalies", s.handleListAnomalies)
	mux.HandleFunc("PUT /api/anomalies/{id}/status", s.handleUpdateAnomalyStatus)

	// Threat risk scoring endpoints (Go 1.22+ wildcard patterns)
	mux.HandleFunc("GET /api/risk/devices", s.handleListRiskDevices)
	mux.HandleFunc("GET /api/security/summary", s.handleSecuritySummary)
	mux.HandleFunc("GET /api/security/timeline", s.handleSecurityTimeline)
	mux.HandleFunc("GET /api/security/unifi-events", s.handleListUniFiEvents)
	mux.HandleFunc("GET /api/stats/protocols", s.handleStatsProtocols)
	mux.HandleFunc("GET /api/stats/top-devices", s.handleStatsTopDevices)
	mux.HandleFunc("GET /api/stats/heatmap", s.handleStatsHeatmap)
	mux.HandleFunc("GET /api/stats/collector-health", s.handleStatsCollectorHealth)

	// Security audit log endpoints (Go 1.22+ wildcard patterns)
	mux.HandleFunc("GET /api/audit-logs", s.handleListAuditLogs)

	// Firewall rules templates export (Go 1.22+ wildcard patterns)
	mux.HandleFunc("GET /api/firewall/rules", s.handleGetFirewallRules)

	// Settings configuration endpoints (Go 1.22+ wildcard patterns)
	mux.HandleFunc("GET /api/settings", s.handleGetSettings)
	mux.HandleFunc("POST /api/settings", s.handlePostSettings)
	mux.HandleFunc("POST /api/settings/test-alert", s.handleTestAlert)
	mux.HandleFunc("POST /api/settings/test-channel", s.handleTestChannel)
	mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)

	// Policy configuration endpoints (Go 1.22+ wildcard patterns)
	mux.HandleFunc("GET /api/policies", s.handleListPolicies)
	mux.HandleFunc("POST /api/policies", s.handleSavePolicy)
	mux.HandleFunc("PUT /api/policies/{id}", s.handleSavePolicy)
	mux.HandleFunc("DELETE /api/policies/{id}", s.handleDeletePolicy)

	// Notification routing rules and logs endpoints
	mux.HandleFunc("GET /api/notification-rules", s.handleListNotificationRules)
	mux.HandleFunc("POST /api/notification-rules", s.handleSaveNotificationRule)
	mux.HandleFunc("PUT /api/notification-rules/{id}", s.handleSaveNotificationRule)
	mux.HandleFunc("DELETE /api/notification-rules/{id}", s.handleDeleteNotificationRule)
	mux.HandleFunc("GET /api/notification-logs", s.handleListNotificationLogs)
	mux.HandleFunc("POST /api/notification-rules/{id}/test", s.handleTestNotificationRule)
	mux.HandleFunc("POST /api/auth/setup", s.handleAuthSetup)
	mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleAuthLogout)

	mux.Handle("/", ui.Handler())
	s.server.Handler = s.accessLogMiddleware(s.authMiddleware(mux))

	return s
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status != 0 {
		return
	}
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	r.bytes += n
	return n, err
}

func (s *APIServer) accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		s.logger.Info("HTTP request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("query", sanitizedQuery(r)),
			slog.Int("status", status),
			slog.Int("bytes", rec.bytes),
			slog.Duration("duration", time.Since(start)),
			slog.String("remote_addr", r.RemoteAddr),
		)
	})
}

func sanitizedQuery(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return ""
	}
	values := r.URL.Query()
	for key := range values {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "password") ||
			strings.Contains(lower, "token") ||
			strings.Contains(lower, "secret") ||
			strings.Contains(lower, "key") ||
			strings.Contains(lower, "webhook") {
			values.Set(key, "REDACTED")
		}
	}
	return values.Encode()
}

// Start launches the HTTP server and blocks until it is stopped or encounters an error.
func (s *APIServer) Start() error {
	s.logger.Info("Starting HTTP API Server", slog.String("port", s.cfg.Port))
	s.startCollectorStatsSampler()
	if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.stopCollectorStatsSampler()
		return fmt.Errorf("http server failure: %w", err)
	}
	s.stopCollectorStatsSampler()
	return nil
}

// Shutdown gracefully stops the HTTP server within the provided context deadline.
func (s *APIServer) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down HTTP API Server gracefully...")
	s.stopCollectorStatsSampler()
	return s.server.Shutdown(ctx)
}

func (s *APIServer) startCollectorStatsSampler() {
	if s.collector == nil {
		return
	}
	s.statsMu.Lock()
	if s.statsCancel != nil {
		s.statsMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.statsCancel = cancel
	s.statsMu.Unlock()

	s.recordCollectorStats(time.Now().UTC())
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case ts := <-ticker.C:
				s.recordCollectorStats(ts.UTC())
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *APIServer) stopCollectorStatsSampler() {
	s.statsMu.Lock()
	cancel := s.statsCancel
	s.statsCancel = nil
	s.statsMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *APIServer) recordCollectorStats(ts time.Time) {
	if s.collector == nil {
		return
	}
	stats := s.collector.GetStats()
	sample := CollectorHealthSample{
		Timestamp:       ts,
		PacketsReceived: stats.PacketsReceived,
		PacketsDropped:  stats.PacketsDropped,
		DecodeErrors:    stats.DecodeErrors,
		QueueDepth:      stats.QueueDepth,
	}

	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	s.statsSamples = append(s.statsSamples, sample)
	if len(s.statsSamples) > maxCollectorHealthSamples {
		s.statsSamples = s.statsSamples[len(s.statsSamples)-maxCollectorHealthSamples:]
	}
}

func (s *APIServer) collectorHealthSamples(limit int) []CollectorHealthSample {
	if limit <= 0 || limit > maxCollectorHealthSamples {
		limit = maxCollectorHealthSamples
	}

	s.statsMu.RLock()
	defer s.statsMu.RUnlock()
	if len(s.statsSamples) == 0 {
		return []CollectorHealthSample{}
	}
	start := len(s.statsSamples) - limit
	if start < 0 {
		start = 0
	}
	out := make([]CollectorHealthSample, len(s.statsSamples[start:]))
	copy(out, s.statsSamples[start:])
	return out
}

// handleHealth returns availability status and optionally collector performance counters.
func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	localIPs := []string{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					localIPs = append(localIPs, ipnet.IP.String())
				}
			}
		}
	}

	res := HealthResponse{
		Status:      "OK",
		Healthy:     true,
		Environment: s.cfg.Environment,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Version:     "0.1.0",
		LocalIPs:    localIPs,
	}

	if s.collector != nil {
		stats := s.collector.GetStats()
		res.Collector = &stats
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		s.logger.Error("Failed to encode health response", slog.String("error", err.Error()))
	}
}

// handleExporters returns a JSON list of all active flow exporters.
func (s *APIServer) handleExporters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var exporters []collector.ExporterMetadata
	if s.collector != nil {
		exporters = s.collector.GetExporters()
	} else {
		exporters = []collector.ExporterMetadata{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(exporters); err != nil {
		s.logger.Error("Failed to encode exporters response", slog.String("error", err.Error()))
	}
}

// ServeHTTP implements http.Handler, delegating request routing to the internal server multiplexer.
func (s *APIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.server != nil && s.server.Handler != nil {
		s.server.Handler.ServeHTTP(w, r)
	}
}
