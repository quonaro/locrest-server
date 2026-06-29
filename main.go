package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"locrest-server/internal/auth"
	"locrest-server/internal/chiselwrapper"
	"locrest-server/internal/config"
	"locrest-server/internal/db"
	"locrest-server/internal/server"
)

func main() {
	cfg, err := config.Load("locrest.yaml")
	if err != nil {
		slog.Error("config load failed", "error", err)
		os.Exit(1)
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		slog.Error("db open failed", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	store := auth.NewStore(database)
	chisel, err := chiselwrapper.New()
	if err != nil {
		slog.Error("chisel init failed", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	database.StartCleaner(ctx, 30*time.Second)

	frontend := server.NewFrontend(cfg, store, chisel, database)
	frontend.ReloadChiselUsers()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		slog.Info("shutting down")
		cancel()
	}()

	slog.Info("locrest-server starting", "http_port", cfg.HTTPPort, "https_port", cfg.HTTPSPort)
	if err := frontend.Run(ctx); err != nil {
		slog.Error("frontend run failed", "error", err)
		os.Exit(1)
	}
}
