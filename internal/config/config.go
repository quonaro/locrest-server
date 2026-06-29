package config

import (
	"flag"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// TLSConfig holds certificate and ACME settings.
type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	// AutoTLS enables autocert when Domains is non-empty.
	AutoTLS bool     `yaml:"auto_tls"`
	Domains []string `yaml:"domains"`
	Email   string   `yaml:"email"`
}

// Permissions defines capabilities for a role (public or auth).
type Permissions struct {
	CreateTunnel bool          `yaml:"create_tunnel"`
	RawTCP       bool          `yaml:"raw_tcp"`
	SetTTL       bool          `yaml:"set_ttl"`
	MaxTTL       time.Duration `yaml:"max_ttl"`
	HTTPAuth     bool          `yaml:"http_auth"`
	SetSubdomain bool          `yaml:"set_subdomain"`
}

// PermissionsConfig holds permissions for public and authenticated users.
type PermissionsConfig struct {
	Public Permissions `yaml:"public"`
	Auth   Permissions `yaml:"auth"`
}

// ServerConfig is the runtime configuration.
type ServerConfig struct {
	HTTPPort        int               `yaml:"http_port"`
	HTTPSPort       int               `yaml:"https_port"`
	Domain          string            `yaml:"domain"`
	TLS             TLSConfig         `yaml:"tls"`
	TTL             time.Duration     `yaml:"ttl"`
	TTLLimit        time.Duration     `yaml:"ttl_limit"`
	Insecure        bool              `yaml:"insecure"`
	Dev             bool              `yaml:"dev"`
	BinaryURL       string            `yaml:"binary_url"`
	StripErrorParam bool              `yaml:"strip_error_param"`
	BehindProxy     bool              `yaml:"behind_proxy"`
	DBPath          string            `yaml:"db_path"`
	RootPage        bool              `yaml:"root_page"`
	Permissions     PermissionsConfig `yaml:"permissions"`
}

type yamlRoot struct {
	Server ServerConfig `yaml:"server"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *ServerConfig {
	return &ServerConfig{
		HTTPPort:  80,
		HTTPSPort: 443,
		Domain:    "localtest.me",
		TTL:       1 * time.Hour,
		TTLLimit:  7 * 24 * time.Hour,
		BinaryURL: "https://github.com/locrest/locrest/releases/latest/download",
		DBPath:    "locrest.db",
		RootPage:  true,
		Permissions: PermissionsConfig{
			Public: Permissions{
				CreateTunnel: true,
				RawTCP:       false,
				SetTTL:       false,
				MaxTTL:       30 * time.Minute,
				HTTPAuth:     true,
				SetSubdomain: false,
			},
			Auth: Permissions{
				CreateTunnel: true,
				RawTCP:       true,
				SetTTL:       true,
				MaxTTL:       7 * 24 * time.Hour,
				HTTPAuth:     true,
				SetSubdomain: true,
			},
		},
	}
}

// Load reads a YAML file (nested under `server:`) and overrides with CLI flags.
func Load(path string) (*ServerConfig, error) {
	cfg := DefaultConfig()

	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		var root yamlRoot
		root.Server = *cfg
		if err := yaml.Unmarshal(b, &root); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		*cfg = root.Server
	}

	// CLI overrides
	flag.StringVar(&cfg.Domain, "domain", cfg.Domain, "public domain")
	flag.IntVar(&cfg.HTTPPort, "http-port", cfg.HTTPPort, "HTTP frontend port")
	flag.IntVar(&cfg.HTTPSPort, "https-port", cfg.HTTPSPort, "HTTPS frontend port")
	flag.StringVar(&cfg.TLS.Cert, "tls-cert", cfg.TLS.Cert, "TLS certificate path")
	flag.StringVar(&cfg.TLS.Key, "tls-key", cfg.TLS.Key, "TLS private key path")
	flag.BoolVar(&cfg.TLS.AutoTLS, "auto-tls", cfg.TLS.AutoTLS, "enable autocert (Let's Encrypt)")
	flag.StringVar(&cfg.TLS.Email, "tls-email", cfg.TLS.Email, "autocert contact email")
	flag.DurationVar(&cfg.TTL, "ttl", cfg.TTL, "default session lifetime")
	flag.DurationVar(&cfg.TTLLimit, "ttl-limit", cfg.TTLLimit, "maximum allowed session lifetime")
	flag.BoolVar(&cfg.Insecure, "insecure", cfg.Insecure, "also listen on :80 without TLS when TLS is configured")
	flag.BoolVar(&cfg.Dev, "dev", cfg.Dev, "serve embedded client binaries from embedbin/bin")
	flag.StringVar(&cfg.BinaryURL, "binary-url", cfg.BinaryURL, "base URL for client binaries (used when dev=false)")
	flag.BoolVar(&cfg.StripErrorParam, "strip-error-param", cfg.StripErrorParam, "strip the 'error' query parameter before forwarding to backend")
	flag.BoolVar(&cfg.BehindProxy, "behind-proxy", cfg.BehindProxy, "trust X-Forwarded-For and X-Real-Ip headers for client IP")
	flag.StringVar(&cfg.DBPath, "db-path", cfg.DBPath, "path to BoltDB file")
	flag.BoolVar(&cfg.RootPage, "root-page", cfg.RootPage, "serve landing page on root host")
	flag.Parse()

	return cfg, nil
}
