//go:build !production

package main

import (
	"flag"
	"log/slog"

	"github.com/flowguard/flowguard/internal/config"
	"github.com/flowguard/flowguard/internal/storage"
)

var seedFlag = flag.Bool("seed", false, "Seed database with 30 days of mock development telemetry and bypass wizard")

func handleSeed(repo storage.StorageRepository, log *slog.Logger, cfg *config.Config, configPath string) {
	if !*seedFlag {
		return
	}
	log.Info("Developer seed flag enabled. Initializing data seeding...")
	if err := storage.SeedMockData(repo, log, cfg, configPath); err != nil {
		log.Error("Data seeding failed", slog.String("error", err.Error()))
	} else {
		log.Info("Data seeding finished successfully!")
	}
}
