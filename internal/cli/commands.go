package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"locrest-server/internal/config"
	"locrest-server/internal/db"
)

const defaultConfigPath = "locrest.yaml"

func configPath() string {
	if p := os.Getenv("LOCREST_CONFIG"); p != "" {
		return p
	}
	return defaultConfigPath
}

func loadConfig(path string) (*config.ServerConfig, error) {
	cfg := config.DefaultConfig()
	if path == "" {
		path = defaultConfigPath
	}
	loaded, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	*cfg = *loaded
	return cfg, nil
}

func openDB(cfg *config.ServerConfig) (*db.DB, error) {
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	return database, nil
}

func adminClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}
}

func initLogLevel(level string) {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "info":
		lv = slog.LevelInfo
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv})))
}
