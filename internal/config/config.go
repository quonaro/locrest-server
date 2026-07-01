package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultBinaryURL is the client release URL used when no binary_url is configured.
const DefaultBinaryURL = "https://github.com/quonaro/locrest-client/releases/latest/download"

// RateLimit configures a sliding-window rate limiter.
type RateLimit struct {
	Requests int           `yaml:"requests"`
	Window   time.Duration `yaml:"window"`
}

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
	CreateTunnel  bool          `yaml:"create_tunnel"`
	RawTCP        bool          `yaml:"raw_tcp"`
	SetTTL        bool          `yaml:"set_ttl"`
	MaxTTL        time.Duration `yaml:"max_ttl"`
	HTTPAuth      bool          `yaml:"http_auth"`
	SetSubdomain  bool          `yaml:"set_subdomain"`
	SetAllowedIPs bool          `yaml:"set_allowed_ips"`
	SetHost       bool          `yaml:"set_host"`
	SetTCPPort    bool          `yaml:"set_tcp_port"`
	SetMode       bool          `yaml:"set_mode"`
	Infinity      bool          `yaml:"infinity"`
}

// PermissionsConfig holds permissions for public and authenticated users.
type PermissionsConfig struct {
	Public Permissions `yaml:"public"`
	Auth   Permissions `yaml:"auth"`
}

// NetworkConfig holds network settings.
type NetworkConfig struct {
	Domain              string `yaml:"domain"`
	HTTPPort            int    `yaml:"http_port"`
	HTTPSPort           int    `yaml:"https_port"`
	BehindProxy         bool   `yaml:"behind_proxy"`
	HTTPToHTTPSRedirect bool   `yaml:"http_to_https_redirect"`
	Insecure            bool   `yaml:"insecure"`
}

// TunnelConfig holds tunnel parameters.
type TunnelConfig struct {
	TTL                time.Duration `yaml:"ttl"`
	TTLLimit           time.Duration `yaml:"ttl_limit"`
	MaxSessions        int           `yaml:"max_sessions"`
	SubdomainLength    int           `yaml:"subdomain_length"`
	ReservedSubdomains []string      `yaml:"reserved_subdomains"`
	AllowedTunnelHosts []string      `yaml:"allowed_tunnel_hosts"`
	BlockedTunnelHosts []string      `yaml:"blocked_tunnel_hosts"`
	StripErrorParam    bool          `yaml:"strip_error_param"`
}

// SecurityConfig holds security and rate limiting.
type SecurityConfig struct {
	AllowedIPs          []string  `yaml:"allowed_ips"`
	BlockedIPs          []string  `yaml:"blocked_ips"`
	RateLimit           RateLimit `yaml:"rate_limit"`
	RegenerateRateLimit RateLimit `yaml:"regenerate_rate_limit"`
}

// BinaryConfig holds client binary settings.
type BinaryConfig struct {
	URL             string        `yaml:"url"`
	CacheDir        string        `yaml:"cache_dir"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
}

// RuntimeConfig holds server runtime settings.
type RuntimeConfig struct {
	DBPath          string            `yaml:"db_path"`
	AdminSocketPath string            `yaml:"admin_socket_path"`
	LogLevel        string            `yaml:"log_level"`
	RootPage        bool              `yaml:"root_page"`
	StatusEndpoint  bool              `yaml:"status_endpoint"`
	CustomHeaders   map[string]string `yaml:"custom_response_headers"`
}

// ServerConfig is the runtime configuration.
type ServerConfig struct {
	Network     NetworkConfig     `yaml:"network"`
	TLS         TLSConfig         `yaml:"tls"`
	Tunnel      TunnelConfig      `yaml:"tunnel"`
	Security    SecurityConfig    `yaml:"security"`
	Permissions PermissionsConfig `yaml:"permissions"`
	Binary      BinaryConfig      `yaml:"binaries"`
	Runtime     RuntimeConfig     `yaml:"runtime"`
}

type yamlRoot struct {
	Server ServerConfig `yaml:"server"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *ServerConfig {
	return &ServerConfig{
		Network: NetworkConfig{
			Domain:    "localtest.me",
			HTTPPort:  80,
			HTTPSPort: 443,
		},
		Tunnel: TunnelConfig{
			TTL:                1 * time.Hour,
			TTLLimit:           7 * 24 * time.Hour,
			MaxSessions:        10000,
			AllowedTunnelHosts: []string{"localhost", "127.0.0.1"},
			SubdomainLength:    16,
		},
		Security: SecurityConfig{
			RateLimit:           RateLimit{Requests: 10, Window: time.Minute},
			RegenerateRateLimit: RateLimit{Requests: 3, Window: time.Minute},
		},
		Runtime: RuntimeConfig{
			DBPath:         "locrest.db",
			RootPage:       true,
			LogLevel:       "info",
			StatusEndpoint: true,
		},
		Binary: BinaryConfig{
			URL:             DefaultBinaryURL,
			RefreshInterval: 24 * time.Hour,
		},
		Permissions: PermissionsConfig{
			Public: Permissions{
				CreateTunnel: true,
				RawTCP:       false,
				SetTTL:       false,
				MaxTTL:       30 * time.Minute,
				HTTPAuth:     true,
				SetSubdomain: false,
				Infinity:     false,
			},
			Auth: Permissions{
				CreateTunnel:  true,
				RawTCP:        true,
				SetTTL:        true,
				MaxTTL:        7 * 24 * time.Hour,
				HTTPAuth:      true,
				SetSubdomain:  true,
				SetAllowedIPs: true,
				SetHost:       true,
				SetTCPPort:    true,
				SetMode:       true,
				Infinity:      true,
			},
		},
	}
}

// EffectiveBinaryCacheDir returns the binary cache directory.
// When Binary.CacheDir is empty, it defaults to a "bin" subdirectory next to Runtime.DBPath.
func (c *ServerConfig) EffectiveBinaryCacheDir() string {
	if c.Binary.CacheDir != "" {
		return c.Binary.CacheDir
	}
	return filepath.Join(filepath.Dir(c.Runtime.DBPath), "bin")
}

// Validate checks the configuration for logical errors.
func (c *ServerConfig) Validate() error {
	if c.Network.HTTPPort <= 0 || c.Network.HTTPPort > 65535 {
		return fmt.Errorf("invalid network.http_port: %d", c.Network.HTTPPort)
	}
	if c.Network.HTTPSPort <= 0 || c.Network.HTTPSPort > 65535 {
		return fmt.Errorf("invalid network.https_port: %d", c.Network.HTTPSPort)
	}
	if c.Network.Domain == "" {
		return fmt.Errorf("network.domain is required")
	}
	if c.Tunnel.TTL <= 0 {
		return fmt.Errorf("tunnel.ttl must be positive")
	}
	if c.Tunnel.TTLLimit < c.Tunnel.TTL {
		return fmt.Errorf("tunnel.ttl_limit must be >= tunnel.ttl")
	}
	if c.Tunnel.SubdomainLength <= 0 {
		return fmt.Errorf("tunnel.subdomain_length must be positive")
	}
	if c.Tunnel.MaxSessions < 0 {
		return fmt.Errorf("tunnel.max_sessions must be >= 0")
	}
	if c.Runtime.DBPath == "" {
		return fmt.Errorf("runtime.db_path is required")
	}
	if c.Runtime.AdminSocketPath == "" {
		return fmt.Errorf("runtime.admin_socket_path is required")
	}
	if c.Security.RateLimit.Requests < 0 {
		return fmt.Errorf("security.rate_limit.requests must be >= 0")
	}
	if c.Security.RateLimit.Window <= 0 {
		return fmt.Errorf("security.rate_limit.window must be positive")
	}
	if c.Security.RegenerateRateLimit.Requests < 0 {
		return fmt.Errorf("security.regenerate_rate_limit.requests must be >= 0")
	}
	if c.Security.RegenerateRateLimit.Window <= 0 {
		return fmt.Errorf("security.regenerate_rate_limit.window must be positive")
	}
	if c.Permissions.Public.MaxTTL < 0 {
		return fmt.Errorf("permissions.public.max_ttl must be >= 0")
	}
	if c.Permissions.Auth.MaxTTL < 0 {
		return fmt.Errorf("permissions.auth.max_ttl must be >= 0")
	}
	if c.Binary.RefreshInterval < 0 {
		return fmt.Errorf("binaries.refresh_interval must be >= 0")
	}
	return nil
}

// Load reads a YAML file (nested under `server:`).
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

	return cfg, nil
}
