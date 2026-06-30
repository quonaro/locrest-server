package cli

import (
	"os"
	"testing"
)

func TestConfigPath(t *testing.T) {
	orig := os.Getenv("LOCREST_CONFIG")
	defer os.Setenv("LOCREST_CONFIG", orig)

	os.Setenv("LOCREST_CONFIG", "/custom/locrest.yaml")
	if got := configPath(); got != "/custom/locrest.yaml" {
		t.Fatalf("configPath() = %q, want /custom/locrest.yaml", got)
	}

	os.Unsetenv("LOCREST_CONFIG")
	if got := configPath(); got != defaultConfigPath {
		t.Fatalf("configPath() = %q, want %q", got, defaultConfigPath)
	}
}

func TestAdminSocketPath(t *testing.T) {
	orig := os.Getenv("LOCREST_ADMIN_SOCKET")
	defer os.Setenv("LOCREST_ADMIN_SOCKET", orig)

	os.Setenv("LOCREST_ADMIN_SOCKET", "/tmp/admin.sock")
	if got := adminSocketPath(); got != "/tmp/admin.sock" {
		t.Fatalf("adminSocketPath() = %q, want /tmp/admin.sock", got)
	}

	os.Unsetenv("LOCREST_ADMIN_SOCKET")
	if got := adminSocketPath(); got != "locrest-admin.sock" {
		t.Fatalf("adminSocketPath() = %q, want locrest-admin.sock", got)
	}
}
