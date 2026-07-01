package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"locrest-server/internal/config"
	"locrest-server/internal/db"

	"github.com/quonaro/lota/engine"
)

const defaultConfigPath = "/etc/locrest/locrest.yaml"

func configPath() string {
	if p := os.Getenv("LOCREST_CONFIG"); p != "" {
		return p
	}
	return defaultConfigPath
}

func adminSocketPath() string {
	if p := os.Getenv("LOCREST_ADMIN_SOCKET"); p != "" {
		return p
	}
	return "/var/lib/locrest/locrest-admin.sock"
}

func loadConfig(path string) (*config.ServerConfig, error) {
	cfg := config.DefaultConfig()
	if path == "" {
		path = defaultConfigPath
	}
	loaded, err := config.Load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("config file not found: %s", path)
		}
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

func checkAdminSocket(socketPath string) error {
	if _, err := os.Stat(socketPath); err != nil {
		return fmt.Errorf("server is not running (admin socket not found at %s)", socketPath)
	}
	return nil
}

// SoftReload triggers a config reload via the admin socket.
func SoftReload(ctx context.Context, nctx engine.NativeContext) error {
	if err := checkAdminSocket(adminSocketPath()); err != nil {
		return err
	}
	client := adminClient(adminSocketPath())
	resp, err := client.Post("http://admin/reload", "", nil)
	if err != nil {
		return fmt.Errorf("admin request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("reload failed: %s", resp.Status)
	}
	fmt.Println("Config reloaded successfully")
	return nil
}
