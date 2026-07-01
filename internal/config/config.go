package config

import (
	"fmt"
	"os"
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

// ServerConfig is the runtime configuration.
type ServerConfig struct {
	HTTPPort            int               `yaml:"http_port"`
	HTTPSPort           int               `yaml:"https_port"`
	Domain              string            `yaml:"domain"`
	TLS                 TLSConfig         `yaml:"tls"`
	TTL                 time.Duration     `yaml:"ttl"`
	TTLLimit            time.Duration     `yaml:"ttl_limit"`
	Insecure            bool              `yaml:"insecure"`
	BinaryURL           string            `yaml:"binary_url"`
	StripErrorParam     bool              `yaml:"strip_error_param"`
	BehindProxy         bool              `yaml:"behind_proxy"`
	DBPath              string            `yaml:"db_path"`
	RootPage            bool              `yaml:"root_page"`
	MaxSessions         int               `yaml:"max_sessions"`
	RateLimit           RateLimit         `yaml:"rate_limit"`
	RegenerateRateLimit RateLimit         `yaml:"regenerate_rate_limit"`
	AllowedTunnelHosts  []string          `yaml:"allowed_tunnel_hosts"`
	BlockedTunnelHosts  []string          `yaml:"blocked_tunnel_hosts"`
	AllowedIPs          []string          `yaml:"allowed_ips"`
	BlockedIPs          []string          `yaml:"blocked_ips"`
	ReservedSubdomains  []string          `yaml:"reserved_subdomains"`
	SubdomainLength     int               `yaml:"subdomain_length"`
	HTTPToHTTPSRedirect bool              `yaml:"http_to_https_redirect"`
	LogLevel            string            `yaml:"log_level"`
	StatusEndpoint      bool              `yaml:"status_endpoint_enabled"`
	CustomHeaders       map[string]string `yaml:"custom_response_headers"`
	Permissions         PermissionsConfig `yaml:"permissions"`
	AdminSocketPath     string            `yaml:"admin_socket_path"`
}

type yamlRoot struct {
	Server ServerConfig `yaml:"server"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *ServerConfig {
	return &ServerConfig{
		HTTPPort:            80,
		HTTPSPort:           443,
		Domain:              "localtest.me",
		TTL:                 1 * time.Hour,
		TTLLimit:            7 * 24 * time.Hour,
		BinaryURL:           DefaultBinaryURL,
		DBPath:              "locrest.db",
		RootPage:            true,
		MaxSessions:         10000,
		RateLimit:           RateLimit{Requests: 10, Window: time.Minute},
		RegenerateRateLimit: RateLimit{Requests: 3, Window: time.Minute},
		AllowedTunnelHosts:  []string{"localhost", "127.0.0.1"},
		SubdomainLength:     16,
		LogLevel:            "info",
		StatusEndpoint:      true,
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

// Validate checks the configuration for logical errors.
func (c *ServerConfig) Validate() error {
	if c.HTTPPort <= 0 || c.HTTPPort > 65535 {
		return fmt.Errorf("invalid http_port: %d", c.HTTPPort)
	}
	if c.HTTPSPort <= 0 || c.HTTPSPort > 65535 {
		return fmt.Errorf("invalid https_port: %d", c.HTTPSPort)
	}
	if c.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if c.TTL <= 0 {
		return fmt.Errorf("ttl must be positive")
	}
	if c.TTLLimit < c.TTL {
		return fmt.Errorf("ttl_limit must be >= ttl")
	}
	if c.SubdomainLength <= 0 {
		return fmt.Errorf("subdomain_length must be positive")
	}
	if c.MaxSessions < 0 {
		return fmt.Errorf("max_sessions must be >= 0")
	}
	if c.DBPath == "" {
		return fmt.Errorf("db_path is required")
	}
	if c.AdminSocketPath == "" {
		return fmt.Errorf("admin_socket_path is required")
	}
	if c.RateLimit.Requests < 0 {
		return fmt.Errorf("rate_limit.requests must be >= 0")
	}
	if c.RateLimit.Window <= 0 {
		return fmt.Errorf("rate_limit.window must be positive")
	}
	if c.RegenerateRateLimit.Requests < 0 {
		return fmt.Errorf("regenerate_rate_limit.requests must be >= 0")
	}
	if c.RegenerateRateLimit.Window <= 0 {
		return fmt.Errorf("regenerate_rate_limit.window must be positive")
	}
	if c.Permissions.Public.MaxTTL < 0 {
		return fmt.Errorf("permissions.public.max_ttl must be >= 0")
	}
	if c.Permissions.Auth.MaxTTL < 0 {
		return fmt.Errorf("permissions.auth.max_ttl must be >= 0")
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
