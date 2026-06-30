package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"locrest-server/internal/auth"
	"locrest-server/internal/chiselwrapper"
	"locrest-server/internal/config"
	"locrest-server/internal/db"
	"locrest-server/internal/server"

	"github.com/fatih/color"
	"github.com/quonaro/lota/engine"
	"gopkg.in/yaml.v3"
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

// InitConfig writes a default config file to disk.
func InitConfig(ctx context.Context, nctx engine.NativeContext) error {
	path := nctx.Args["path"]
	if path == "" {
		path = defaultConfigPath
	}

	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config file already exists: %s", path)
	}

	cfg := config.DefaultConfig()
	root := struct {
		Server config.ServerConfig `yaml:"server"`
	}{Server: *cfg}

	b, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, b, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	fmt.Fprintf(nctx.Stdout, "Created default config: %s\n", path)
	return nil
}

// RunServer starts the locrest-server.
func RunServer(ctx context.Context, nctx engine.NativeContext) error {
	if nctx.Args["daemon"] == "true" {
		if err := requireRoot(); err != nil {
			return err
		}
		if err := createSystemUser(); err != nil {
			return fmt.Errorf("create user: %w", err)
		}
		if err := createDirs(); err != nil {
			return fmt.Errorf("create dirs: %w", err)
		}
		if err := ensureConfig(); err != nil {
			return fmt.Errorf("ensure config: %w", err)
		}
		if err := installService(); err != nil {
			return fmt.Errorf("install service: %w", err)
		}
		if err := enableService(); err != nil {
			return fmt.Errorf("enable service: %w", err)
		}
		if err := startService(); err != nil {
			return fmt.Errorf("start service: %w", err)
		}
		color.New(color.FgGreen, color.Bold).Fprintln(nctx.Stdout, "locrest-server is running as a system service")
		return nil
	}

	cfg, err := loadConfig(configPath())
	if err != nil {
		return err
	}

	initLogLevel(cfg.LogLevel)

	database, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer database.Close()

	store := auth.NewStore(database)
	chisel, err := chiselwrapper.New()
	if err != nil {
		return fmt.Errorf("chisel init: %w", err)
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	database.StartCleaner(ctx, 30*time.Second)

	frontend := server.NewFrontend(cfg, store, chisel, database)
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
