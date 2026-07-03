package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/flowguard/flowguard/internal/api"
	"github.com/flowguard/flowguard/internal/collector"
	"github.com/flowguard/flowguard/internal/config"
	"github.com/flowguard/flowguard/internal/device"
	"github.com/flowguard/flowguard/internal/logger"
	"github.com/flowguard/flowguard/internal/storage"
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

	// 4. Initialize storage repository
	repo, err := storage.NewSQLiteRepository(cfg.StorageDir, log)
	if err != nil {
		log.Error("Failed to initialize SQLite repository", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Run storage retention cleanup once on startup (7-day default limit)
	if err := repo.CleanupRetention(7); err != nil {
		log.Warn("Failed to execute initial retention cleanup", slog.String("error", err.Error()))
	}

	// 5. Initialize Flow Aggregator with transactional SQLite repository
	agg := storage.NewFlowAggregator(repo, log, 15*time.Second)
	agg.Start()

	// 6. Initialize Device Profiler with local subnets and downstream aggregator
	profiler := device.NewDeviceProfiler(repo, log, cfg.LocalSubnets, agg)
	profiler.Start()

	// 7. Initialize Flow Collector, using the Profiler as the flow processor
	coll := collector.NewFlowCollector(cfg, log, profiler)

	// 8. Start Flow Collector daemon
	if err := coll.Start(); err != nil {
		log.Error("Failed to start Flow Collector daemon", slog.String("error", err.Error()))
		coll.Shutdown()
		profiler.Shutdown()
		agg.Shutdown()
		repo.Close()
		os.Exit(1)
	}

	// 9. Initialize API HTTP server
	server := api.NewAPIServer(cfg, log, coll, repo, repo)

	// 10. Run HTTP server in a separate goroutine so we can trap signals concurrently
	serverErrChan := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil {
			serverErrChan <- err
		}
	}()

	// 11. Setup signal trapping for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// 12. Wait for termination signal or server start failure
	select {
	case err := <-serverErrChan:
		log.Error("HTTP server stopped unexpectedly", slog.String("error", err.Error()))
		coll.Shutdown()
		profiler.Shutdown()
		agg.Shutdown()
		repo.Close()
		os.Exit(1)

	case sig := <-signalChan:
		log.Info("Termination signal received. Initiating graceful shutdown...", slog.String("signal", sig.String()))

		// Create a timeout context for shutdown operations (e.g., 5 seconds)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var shutdownFailed bool

		// Shutdown the HTTP API server
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Error("Failed to shut down HTTP API server cleanly", slog.String("error", err.Error()))
			shutdownFailed = true
		}

		// Shutdown the Flow Collector
		coll.Shutdown()

		// Shutdown the Device Profiler (stops background reverse DNS lookups)
		profiler.Shutdown()

		// Shutdown the Flow Aggregator (flushes remaining in-memory states to database)
		agg.Shutdown()

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
