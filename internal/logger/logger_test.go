package logger

import (
	"log/slog"
	"testing"
)

func TestInitLogger(t *testing.T) {
	log := InitLogger("debug", "development")
	if log == nil {
		t.Fatal("expected logger to not be nil")
	}

	log.Debug("test debug log message")
	log.Info("test info log message")

	// Ensure the default logger is also set
	slog.Info("test default slog logger info message")
}
