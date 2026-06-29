package config

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func resetFlags() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.HTTPPort != 80 {
		t.Fatalf("HTTPPort = %d, want 80", cfg.HTTPPort)
	}
	if cfg.HTTPSPort != 443 {
		t.Fatalf("HTTPSPort = %d, want 443", cfg.HTTPSPort)
	}
	if cfg.Domain != "localtest.me" {
		t.Fatalf("Domain = %q, want localtest.me", cfg.Domain)
	}
	if cfg.TTL != time.Hour {
		t.Fatalf("TTL = %v, want 1h", cfg.TTL)
	}
	if cfg.TTLLimit != 7*24*time.Hour {
		t.Fatalf("TTLLimit = %v, want 7d", cfg.TTLLimit)
	}
	if cfg.DBPath != "locrest.db" {
		t.Fatalf("DBPath = %q, want locrest.db", cfg.DBPath)
	}
	if cfg.MaxSessions != 10000 {
		t.Fatalf("MaxSessions = %d, want 10000", cfg.MaxSessions)
	}
	if cfg.SubdomainLength != 16 {
		t.Fatalf("SubdomainLength = %d, want 16", cfg.SubdomainLength)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if !cfg.StatusEndpoint {
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
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"test"}

	dir := t.TempDir()
	path := filepath.Join(dir, "locrest.yaml")
	content := `server:
  http_port: 8080
  domain: "example.com"
  ttl: 30m
  dev: true
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
	if cfg.HTTPPort != 8080 {
		t.Fatalf("HTTPPort = %d, want 8080", cfg.HTTPPort)
	}
	if cfg.Domain != "example.com" {
		t.Fatalf("Domain = %q, want example.com", cfg.Domain)
	}
	if cfg.TTL != 30*time.Minute {
		t.Fatalf("TTL = %v, want 30m", cfg.TTL)
	}
	if !cfg.Dev {
		t.Fatal("Dev should be true")
	}
	if !cfg.Permissions.Public.RawTCP {
		t.Fatal("public RawTCP should be true")
	}
}

func TestLoadMissingFile(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"test"}

	_, err := Load("/nonexistent/locrest.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadCLIOverrides(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"test", "-http-port", "9090", "-domain", "cli.example.com", "-dev", "-log-level", "debug"}

	dir := t.TempDir()
	path := filepath.Join(dir, "locrest.yaml")
	content := `server:
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
	if cfg.HTTPPort != 9090 {
		t.Fatalf("HTTPPort = %d, want 9090", cfg.HTTPPort)
	}
	if cfg.Domain != "cli.example.com" {
		t.Fatalf("Domain = %q, want cli.example.com", cfg.Domain)
	}
	if !cfg.Dev {
		t.Fatal("Dev should be true")
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("LogLevel = %q, want debug", cfg.LogLevel)
	}
}
