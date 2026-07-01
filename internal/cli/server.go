package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"locrest-server/internal/auth"
	"locrest-server/internal/chiselwrapper"
	"locrest-server/internal/logger"
	"locrest-server/internal/server"

	"github.com/quonaro/lota/engine"
)

// StartServer loads config, opens DB, and runs the frontend.
// It blocks until interrupted.
func StartServer(ctx context.Context, nctx engine.NativeContext) error {
	cfg, err := loadConfig(configPath())
	if err != nil {
		return err
	}

	logger.Setup(cfg.LogLevel)

	database, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = database.Close() }()

	store := auth.NewStore(database)
	chisel, err := chiselwrapper.New()
	if err != nil {
		return fmt.Errorf("chisel init: %w", err)
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	database.StartCleaner(ctx, 30*time.Second)

	frontend := server.NewFrontend(cfg, store, chisel, database, configPath(), adminSocketPath())
	frontend.ReloadChiselUsers()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		slog.Info("shutting down")
		stop()
	}()

	slog.Info("locrest-server starting", "http_port", cfg.HTTPPort, "https_port", cfg.HTTPSPort)
	if err := frontend.Run(ctx); err != nil {
		return fmt.Errorf("frontend run: %w", err)
	}
	return nil
}
