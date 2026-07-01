package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Network.HTTPPort != 80 {
		t.Fatalf("HTTPPort = %d, want 80", cfg.Network.HTTPPort)
	}
	if cfg.Network.HTTPSPort != 443 {
		t.Fatalf("HTTPSPort = %d, want 443", cfg.Network.HTTPSPort)
	}
	if cfg.Network.Domain != "localtest.me" {
		t.Fatalf("Domain = %q, want localtest.me", cfg.Network.Domain)
	}
	if cfg.Tunnel.TTL != time.Hour {
		t.Fatalf("TTL = %v, want 1h", cfg.Tunnel.TTL)
	}
	if cfg.Tunnel.TTLLimit != 7*24*time.Hour {
		t.Fatalf("TTLLimit = %v, want 7d", cfg.Tunnel.TTLLimit)
	}
	if cfg.Runtime.DBPath != "locrest.db" {
		t.Fatalf("DBPath = %q, want locrest.db", cfg.Runtime.DBPath)
	}
	if cfg.Tunnel.MaxSessions != 10000 {
		t.Fatalf("MaxSessions = %d, want 10000", cfg.Tunnel.MaxSessions)
	}
	if cfg.Tunnel.SubdomainLength != 16 {
		t.Fatalf("SubdomainLength = %d, want 16", cfg.Tunnel.SubdomainLength)
	}
	if cfg.Runtime.LogLevel != "info" {
		t.Fatalf("LogLevel = %q, want info", cfg.Runtime.LogLevel)
	}
	if !cfg.Runtime.StatusEndpoint {
		t.Fatal("StatusEndpoint should be true")
	}
	if !cfg.Permissions.Public.CreateTunnel {
		t.Fatal("public CreateTunnel should be true")
	}
	if cfg.Permissions.Public.RawTCP {
		t.Fatal("public RawTCP should be false")
	}
	if !cfg.Permissions.Auth.RawTCP {
		t.Fatal("auth RawTCP should be true")
	}
}

func TestLoadFromYAML(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"test"}

	dir := t.TempDir()
	path := filepath.Join(dir, "locrest.yaml")
	content := `server:
  network:
    http_port: 8080
    domain: "example.com"
  tunnel:
    ttl: 30m
  permissions:
    public:
      raw_tcp: true
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Network.HTTPPort != 8080 {
		t.Fatalf("HTTPPort = %d, want 8080", cfg.Network.HTTPPort)
	}
	if cfg.Network.Domain != "example.com" {
		t.Fatalf("Domain = %q, want example.com", cfg.Network.Domain)
	}
	if cfg.Tunnel.TTL != 30*time.Minute {
		t.Fatalf("TTL = %v, want 30m", cfg.Tunnel.TTL)
	}
	if !cfg.Permissions.Public.RawTCP {
		t.Fatal("public RawTCP should be true")
	}
}

func TestLoadMissingFile(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"test"}

	_, err := Load("/nonexistent/locrest.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestEffectiveBinaryCacheDir(t *testing.T) {
	cfg := DefaultConfig()
	want := filepath.Join(filepath.Dir(cfg.Runtime.DBPath), "bin")
	if got := cfg.EffectiveBinaryCacheDir(); got != want {
		t.Fatalf("EffectiveBinaryCacheDir = %q, want %q", got, want)
	}
	cfg.Binary.CacheDir = "/custom/bin"
	if got := cfg.EffectiveBinaryCacheDir(); got != "/custom/bin" {
		t.Fatalf("EffectiveBinaryCacheDir = %q, want /custom/bin", got)
	}
}

func TestBinaryRefreshIntervalDefault(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Binary.RefreshInterval != 24*time.Hour {
		t.Fatalf("BinaryRefreshInterval = %v, want 24h", cfg.Binary.RefreshInterval)
	}
}

func TestLoadIgnoresCLIArgs(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"test", "-http-port", "9090", "-domain", "cli.example.com", "-log-level", "debug"}

	dir := t.TempDir()
	path := filepath.Join(dir, "locrest.yaml")
	content := `server:
  network:
    http_port: 8080
    domain: "yaml.example.com"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Network.HTTPPort != 8080 {
		t.Fatalf("HTTPPort = %d, want 8080", cfg.Network.HTTPPort)
	}
	if cfg.Network.Domain != "yaml.example.com" {
		t.Fatalf("Domain = %q, want yaml.example.com", cfg.Network.Domain)
	}
	if cfg.Runtime.LogLevel != "info" {
		t.Fatalf("LogLevel = %q, want info", cfg.Runtime.LogLevel)
	}
}
