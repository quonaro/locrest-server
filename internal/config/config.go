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

// ServerConfig is the runtime configuration.
type ServerConfig struct {
	Port      int           `yaml:"port"`
	Domain    string        `yaml:"domain"`
	TLS       TLSConfig     `yaml:"tls"`
	ScriptTTL time.Duration `yaml:"script_ttl"`
}

type yamlRoot struct {
	Server ServerConfig `yaml:"server"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *ServerConfig {
	return &ServerConfig{
		Port:      80,
		Domain:    "localtest.me",
		ScriptTTL: 5 * time.Minute,
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
	flag.IntVar(&cfg.Port, "port", cfg.Port, "HTTP frontend port")
	flag.StringVar(&cfg.TLS.Cert, "tls-cert", cfg.TLS.Cert, "TLS certificate path")
	flag.StringVar(&cfg.TLS.Key, "tls-key", cfg.TLS.Key, "TLS private key path")
	flag.BoolVar(&cfg.TLS.AutoTLS, "auto-tls", cfg.TLS.AutoTLS, "enable autocert (Let's Encrypt)")
	flag.StringVar(&cfg.TLS.Email, "tls-email", cfg.TLS.Email, "autocert contact email")
	flag.DurationVar(&cfg.ScriptTTL, "script-ttl", cfg.ScriptTTL, "script/keypair TTL")
	flag.Parse()

	return cfg, nil
}
