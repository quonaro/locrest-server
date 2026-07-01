package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/quonaro/lota/engine"
)

func TestInitConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "locrest.yaml")

	ctx := context.Background()
	nctx := engine.NativeContext{Args: map[string]string{"path": path}}
	if err := InitConfig(ctx, nctx); err != nil {
		t.Fatalf("InitConfig: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("config file is empty")
	}
}

func TestConfigPath(t *testing.T) {
	orig := os.Getenv("LOCREST_CONFIG")
	defer func() { _ = os.Setenv("LOCREST_CONFIG", orig) }()

	_ = os.Setenv("LOCREST_CONFIG", "/custom/locrest.yaml")
	if got := configPath(); got != "/custom/locrest.yaml" {
		t.Fatalf("configPath() = %q, want /custom/locrest.yaml", got)
	}

	_ = os.Unsetenv("LOCREST_CONFIG")
	if got := configPath(); got != defaultConfigPath {
		t.Fatalf("configPath() = %q, want %q", got, defaultConfigPath)
	}
}

func TestAdminSocketPath(t *testing.T) {
	orig := os.Getenv("LOCREST_ADMIN_SOCKET")
	defer func() { _ = os.Setenv("LOCREST_ADMIN_SOCKET", orig) }()

	_ = os.Setenv("LOCREST_ADMIN_SOCKET", "/tmp/admin.sock")
	if got := adminSocketPath(); got != "/tmp/admin.sock" {
		t.Fatalf("adminSocketPath() = %q, want /tmp/admin.sock", got)
	}

	_ = os.Unsetenv("LOCREST_ADMIN_SOCKET")
	if got := adminSocketPath(); got != "/var/lib/locrest/locrest-admin.sock" {
		t.Fatalf("adminSocketPath() = %q, want /var/lib/locrest/locrest-admin.sock", got)
	}
}
