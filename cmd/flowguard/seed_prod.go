//go:build production

package main

import (
	"log/slog"

	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

// handleSeed is a no-op in production builds. The -seed flag is not registered.
func handleSeed(repo storage.StorageRepository, log *slog.Logger, cfg *config.Config, configPath string) {
	// No-op
}
