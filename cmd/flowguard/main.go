package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/anomaly"
	"github.com/miquelbar/flowguard-lite/internal/api"
	"github.com/miquelbar/flowguard-lite/internal/baseline"
	"github.com/miquelbar/flowguard-lite/internal/collector"
	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/ddos"
	"github.com/miquelbar/flowguard-lite/internal/device"
	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/logger"
	"github.com/miquelbar/flowguard-lite/internal/risk"
	"github.com/miquelbar/flowguard-lite/internal/storage"
	duckdbstore "github.com/miquelbar/flowguard-lite/internal/storage/duckdb"
	sqlitestore "github.com/miquelbar/flowguard-lite/internal/storage/sqlite"
	"github.com/miquelbar/flowguard-lite/internal/suricata"
	"github.com/miquelbar/flowguard-lite/internal/webhook"
)

func main() {
	// 1. Define and parse command line flags
	configPath := flag.String("config", "config.yaml", "Path to YAML configuration file")
	flag.Parse()

	// 2. Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		slog.Error("Failed to load application configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// 3. Initialize structured logger
	log := logger.InitLogger(cfg.LogLevel, cfg.Environment)
	log.Info("Starting FlowGuard Lite daemon...", slog.String("env", cfg.Environment), slog.String("log_level", cfg.LogLevel))

	// 4. Initialize storage repository based on choice
	var repo storage.StorageRepository
	if cfg.StorageBackend == "duckdb" {
		repo, err = duckdbstore.NewRepository(cfg.StorageDir, log)
		if err != nil {
			log.Error("Failed to initialize DuckDB repository", slog.String("error", err.Error()))
			os.Exit(1)
		}
		log.Info("Initialized DuckDB storage backend")
	} else {
		repo, err = sqlitestore.NewRepository(cfg.StorageDir, log)
		if err != nil {
			log.Error("Failed to initialize SQLite repository", slog.String("error", err.Error()))
			os.Exit(1)
		}
		log.Info("Initialized SQLite storage backend (daily shards)")
	}

	// Traps conditional developer database seeding flag
	handleSeed(repo, log, cfg, *configPath)

	// Run storage retention cleanup once on startup
	if err := repo.CleanupRetention(cfg.RetentionDays); err != nil {
		log.Warn("Failed to execute initial retention cleanup", slog.String("error", err.Error()))
	}

	// Start periodic background retention pruner (every 24 hours)
	prunerCtx, prunerCancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				log.Info("Running daily storage retention cleanup...", slog.Int("retention_days", cfg.RetentionDays))
				if err := repo.CleanupRetention(cfg.RetentionDays); err != nil {
					log.Warn("Failed to execute periodic retention cleanup", slog.String("error", err.Error()))
				}
			case <-prunerCtx.Done():
				return
			}
		}
	}()

	// 5. Initialize Flow Aggregator with transactional SQLite repository
	agg := storage.NewFlowAggregator(repo, log, 15*time.Second)
	agg.Start()

	// 6. Initialize Device Profiler with local subnets and downstream aggregator
	profiler := device.NewDeviceProfiler(repo, log, cfg.LocalSubnets, agg)
	profiler.Start()

	// 7. Initialize DDoS Detector with local subnets and downstream DeviceProfiler
	ddosDetector := ddos.NewDDoSDetector(repo, log, cfg, profiler)
	ddosDetector.Start()

	// 8. Initialize Flow Collector, using the DDoS Detector as the flow entrypoint processor
	coll := collector.NewFlowCollector(cfg, log, ddosDetector, repo)

	if cfg.Environment != "production" {
		coll.AddExporter("192.168.1.1", time.Now().Add(-12*time.Second), 45892)
		coll.AddExporter("192.168.1.5", time.Now().Add(-5*time.Minute), 2341)
	}

	// 9. Start Flow Collector daemon
	if err := coll.Start(); err != nil {
		log.Error("Failed to start Flow Collector daemon", slog.String("error", err.Error()))
		coll.Shutdown()
		ddosDetector.Shutdown()
		profiler.Shutdown()
		agg.Shutdown()
		repo.Close()
		os.Exit(1)
	}

	// Passive capture is opt-in because it requires raw-packet privileges.
	var pcapColl *collector.PcapCollector
	if cfg.CaptureInterface != "" {
		pcapColl = collector.NewPcapCollector(
			cfg.CaptureInterface,
			cfg.CaptureBPFFilter,
			cfg.CapturePromiscuous,
			log,
			ddosDetector,
		)
		if err := pcapColl.Start(); err != nil {
			log.Error("Failed to start passive packet capture", slog.String("error", err.Error()))
			coll.Shutdown()
			ddosDetector.Shutdown()
			profiler.Shutdown()
			agg.Shutdown()
			repo.Close()
			os.Exit(1)
		}
	}

	// 10. Initialize Baseline Engine
	baselineEngine := baseline.NewBaselineEngine(repo, log)
	if err := baselineEngine.LoadBaselines(context.Background()); err != nil {
		log.Warn("Failed to load device baselines on startup", slog.String("error", err.Error()))
	}

	// 11. Start background baseline recalculator loop
	baselineCtx, baselineCancel := context.WithCancel(context.Background())
	go func() {
		// Run initial calculation after a short startup delay (e.g. 5 seconds) to allow initial flows to accumulate
		select {
		case <-time.After(5 * time.Second):
			log.Info("Executing initial baseline calculation...")
			if err := baselineEngine.CalculateBaselines(baselineCtx, repo); err != nil {
				log.Error("Failed to calculate initial device baselines", slog.String("error", err.Error()))
			}
		case <-baselineCtx.Done():
			return
		}

		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				log.Info("Executing periodic baseline recalculation...")
				if err := baselineEngine.CalculateBaselines(baselineCtx, repo); err != nil {
					log.Error("Failed to recalculate device baselines", slog.String("error", err.Error()))
				}
			case <-baselineCtx.Done():
				return
			}
		}
	}()

	// 12. Initialize Anomaly Engine & Register post-flush hooks on FlowAggregator
	anomalyEngine := anomaly.NewAnomalyEngine(repo, log, baselineEngine, cfg.LocalSubnets)
	agg.RegisterFlushCallback(func(ctx context.Context, batch []flow.FlowEvent) {
		anomalyEngine.AnalyzeBatch(ctx, repo, batch)
	})

	// 13. Initialize Suricata tailer worker
	var suricataTailer *suricata.Tailer
	if cfg.SuricataEvePath != "" {
		suricataTailer = suricata.NewTailer(repo, log, cfg.SuricataEvePath, cfg.LocalSubnets)
		suricataTailer.Start()
	}

	// 14. Initialize Threat Risk Scoring Engine
	riskEngine := risk.NewRiskEngine(repo)

	// 14b. Initialize Webhook Engine (always registered to support dynamic configuration reloads)
	webhookEngine := webhook.NewWebhookEngine(repo, cfg.SlackWebhookURL, cfg.WebhookURL, cfg.WebhookFormat, cfg.WebhookHeaders, cfg.TelegramEnabled, cfg.TelegramToken, cfg.TelegramChatID, log)
	repo.RegisterAnomalyCallback(func(a *storage.Anomaly) {
		webhookEngine.SendAnomalyAlert(context.Background(), a)
	})
	log.Info("Webhook Engine started and registered post-anomaly trigger callbacks")

	// 15. Initialize API HTTP server
	server := api.NewAPIServer(cfg, log, coll, repo, repo, baselineEngine, riskEngine, profiler, ddosDetector, webhookEngine, *configPath)

	// 16. Run HTTP server in a separate goroutine so we can trap signals concurrently
	serverErrChan := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil {
			serverErrChan <- err
		}
	}()

	// 17. Setup signal trapping for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// 18. Wait for termination signal or server start failure
	select {
	case err := <-serverErrChan:
		log.Error("HTTP server stopped unexpectedly", slog.String("error", err.Error()))
		baselineCancel()
		prunerCancel()
		if suricataTailer != nil {
			suricataTailer.Shutdown()
		}
		if pcapColl != nil {
			pcapColl.Shutdown()
		}
		coll.Shutdown()
		ddosDetector.Shutdown()
		profiler.Shutdown()
		agg.Shutdown()
		repo.Close()
		os.Exit(1)

	case sig := <-signalChan:
		log.Info("Termination signal received. Initiating graceful shutdown...", slog.String("signal", sig.String()))

		// Stop baseline calculations
		baselineCancel()
		prunerCancel()

		// Create a timeout context for shutdown operations (e.g., 5 seconds)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var shutdownFailed bool

		// Shutdown the HTTP API server
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Error("Failed to shut down HTTP API server cleanly", slog.String("error", err.Error()))
			shutdownFailed = true
		}

		// Shutdown the Suricata Tailer
		if suricataTailer != nil {
			suricataTailer.Shutdown()
		}

		if pcapColl != nil {
			pcapColl.Shutdown()
		}

		// Shutdown the Flow Collector
		coll.Shutdown()

		// Shutdown the DDoS Detector
		ddosDetector.Shutdown()

		// Shutdown the Device Profiler (stops background reverse DNS lookups)
		profiler.Shutdown()

		// Shutdown the Flow Aggregator (flushes remaining in-memory states to database)
		agg.Shutdown()

		// Shutdown the webhook dispatcher after final anomaly callbacks have had a chance to enqueue notifications.
		if err := webhookEngine.Shutdown(shutdownCtx); err != nil {
			log.Error("Failed to shut down webhook dispatcher cleanly", slog.String("error", err.Error()))
			shutdownFailed = true
		}

		// Close SQLite repository connections
		if err := repo.Close(); err != nil {
			log.Error("Failed to close SQLite repository connections cleanly", slog.String("error", err.Error()))
			shutdownFailed = true
		}

		if shutdownFailed {
			log.Warn("Graceful shutdown finished with errors.")
			os.Exit(1)
		}

		log.Info("FlowGuard Lite shut down successfully.")
		os.Exit(0)
	}
}
