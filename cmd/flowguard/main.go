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
	"github.com/flowguard/flowguard/internal/flow"
	"github.com/flowguard/flowguard/internal/logger"
)

// LogProcessor is a temporary FlowProcessor that logs normalized flows at debug level.
type LogProcessor struct {
	logger *slog.Logger
}

func (p *LogProcessor) Process(event *flow.FlowEvent) {
	p.logger.Debug("Processed flow event",
		slog.String("src", event.SrcIP),
		slog.String("dst", event.DstIP),
		slog.Int("port", event.DstPort),
		slog.Uint64("bytes", event.Bytes))
}

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

	// 4. Initialize Flow Collector with temporary log processor
	proc := &LogProcessor{logger: log}
	coll := collector.NewFlowCollector(cfg, log, proc)

	// 5. Start Flow Collector
	if err := coll.Start(); err != nil {
		log.Error("Failed to start Flow Collector daemon", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// 6. Initialize API HTTP server
	server := api.NewAPIServer(cfg, log, coll)

	// 7. Run HTTP server in a separate goroutine so we can trap signals concurrently
	serverErrChan := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil {
			serverErrChan <- err
		}
	}()

	// 8. Setup signal trapping for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// 9. Wait for termination signal or server start failure
	select {
	case err := <-serverErrChan:
		log.Error("HTTP server stopped unexpectedly", slog.String("error", err.Error()))
		coll.Shutdown()
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

		if shutdownFailed {
			log.Warn("Graceful shutdown finished with errors.")
			os.Exit(1)
		}

		log.Info("FlowGuard Lite shut down successfully.")
		os.Exit(0)
	}
}
