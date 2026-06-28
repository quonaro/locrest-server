package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"locrest-server/internal/auth"
	"locrest-server/internal/chiselwrapper"
	"locrest-server/internal/config"
	"locrest-server/internal/server"
)

func main() {
	cfg, err := config.Load("locrest.yaml")
	if err != nil {
		slog.Error("config load failed", "error", err)
		os.Exit(1)
	}

	store := auth.NewStore()
	chisel, err := chiselwrapper.New()
	if err != nil {
		slog.Error("chisel init failed", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	frontend := server.NewFrontend(cfg, store, chisel)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		slog.Info("shutting down")
		cancel()
	}()

	slog.Info("locrest-server starting", "frontend", cfg.Port)
	if err := frontend.Run(ctx); err != nil {
		slog.Error("frontend run failed", "error", err)
		os.Exit(1)
	}
}
