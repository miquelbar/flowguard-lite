package benchmark

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/api"
	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/risk"
	sqlitestore "github.com/miquelbar/flowguard-lite/internal/storage/sqlite"
)

func BenchmarkAPI_Endpoints(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "bench_api")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sqliteRepo, err := sqlitestore.NewRepository(tmpDir, logger)
	if err != nil {
		b.Fatalf("failed to create sqlite repo: %v", err)
	}
	defer sqliteRepo.Close()

	// Seed 5,000 aggregates into the database
	gen := NewFlowEventGenerator(42)
	now := time.Now()
	populateRepository(sqliteRepo, gen, 5000, now)

	// Pre-seed some device and anomaly records for summary API
	ip := "192.168.1.100"
	_ = sqliteRepo.UpsertDevice(context.Background(), ip, "test-device", now)
	riskEngine := risk.NewRiskEngine(sqliteRepo)
	
	cfg := config.DefaultConfig()
	// Disable auth checking for benchmarks by keeping AdminPasswordHash empty
	cfg.AdminPasswordHash = ""
	cfg.FirstRunCompleted = false

	server := api.NewAPIServer(cfg, logger, nil, sqliteRepo, sqliteRepo, nil, riskEngine, nil, nil, nil, "")

	// 1. Benchmark GET /api/security/summary
	b.Run("SecuritySummary", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/api/security/summary", nil)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			server.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("expected status OK, got %d. Body: %s", w.Code, w.Body.String())
			}
		}
	})

	// 2. Benchmark GET /api/security/timeline
	b.Run("SecurityTimeline", func(b *testing.B) {
		startParam := url.QueryEscape(now.Add(-6 * time.Hour).Format(time.RFC3339))
		endParam := url.QueryEscape(now.Add(6 * time.Hour).Format(time.RFC3339))
		req := httptest.NewRequest(http.MethodGet, "/api/security/timeline?start="+startParam+"&end="+endParam, nil)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			server.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("expected status OK, got %d. Body: %s", w.Code, w.Body.String())
			}
		}
	})

	// 3. Benchmark GET /api/traffic/records
	b.Run("TrafficRecords", func(b *testing.B) {
		startParam := url.QueryEscape(now.Add(-6 * time.Hour).Format(time.RFC3339))
		endParam := url.QueryEscape(now.Add(6 * time.Hour).Format(time.RFC3339))
		req := httptest.NewRequest(http.MethodGet, "/api/traffic/records?limit=100&start="+startParam+"&end="+endParam, nil)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			server.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("expected status OK, got %d. Body: %s", w.Code, w.Body.String())
			}
		}
	})
}
