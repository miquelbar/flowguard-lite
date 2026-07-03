package logger

import (
	"log/slog"
	"os"
	"strings"
)

// InitLogger configures the default slog logger using JSON format for production and text format for development.
func InitLogger(levelStr string, environment string) *slog.Logger {
	var level slog.Level

	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if strings.ToLower(environment) == "development" {
		// Clean text representation for development console
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		// Production JSON logging for Docker logging drivers & log management ingestion
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger
}
