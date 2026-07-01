package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"locrest-server/internal/config"
	"log/slog"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/libdns/digitalocean"
	"github.com/libdns/route53"
	"golang.org/x/crypto/acme/autocert"
)

func (f *Frontend) buildTLSConfig() (*tls.Config, error) {
	cfg := f.cfg.Load()
	if cfg.TLS.Cert != "" && cfg.TLS.Key != "" {
		slog.Info("using BYO TLS certificate")
		cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
		}, nil
	}

	if cfg.TLS.CertMagic.Enabled {
		return f.buildCertMagicTLSConfig()
	}

	if cfg.TLS.AutoTLS && len(cfg.TLS.Domains) > 0 {
		slog.Info("using autocert", "domains", cfg.TLS.Domains)
		m := &autocert.Manager{
			Cache:      autocert.DirCache("locrest-certs"),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.TLS.Domains...),
			Email:      cfg.TLS.Email,
		}
		return m.TLSConfig(), nil
	}

	return nil, nil
}

func (f *Frontend) buildCertMagicTLSConfig() (*tls.Config, error) {
	cfg := f.cfg.Load()
	cm := cfg.TLS.CertMagic

	dnsProvider, err := f.newDNSProvider(cm)
	if err != nil {
		return nil, fmt.Errorf("dns provider: %w", err)
	}

	ca := certmagic.LetsEncryptProductionCA
	if cm.Staging {
		ca = certmagic.LetsEncryptStagingCA
	}

	magicCfg := certmagic.NewDefault()
	cacheDir := cfg.EffectiveCertMagicCacheDir()
	magicCfg.Storage = &certmagic.FileStorage{Path: cacheDir}
	slog.Info("certmagic cache dir", "path", cacheDir)

	issuer := certmagic.NewACMEIssuer(magicCfg, certmagic.ACMEIssuer{
		CA:     ca,
		Email:  cfg.TLS.Email,
		Agreed: true,
		DNS01Solver: &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider:        dnsProvider,
				Resolvers:          []string{"1.1.1.1:53", "8.8.8.8:53"},
				PropagationTimeout: 5 * time.Minute,
			},
		},
	})
	magicCfg.Issuers = []certmagic.Issuer{issuer}

	domains := []string{"*." + cfg.Network.Domain, cfg.Network.Domain}
	slog.Info("using certmagic", "domains", domains, "provider", cm.DNSProvider, "staging", cm.Staging)

	if err := magicCfg.ManageAsync(context.Background(), domains); err != nil {
		return nil, fmt.Errorf("certmagic manage: %w", err)
	}

	return magicCfg.TLSConfig(), nil
}

func (f *Frontend) newDNSProvider(cm config.CertMagicConfig) (certmagic.DNSProvider, error) {
	switch cm.DNSProvider {
	case "cloudflare":
		if cm.APIToken == "" {
			return nil, fmt.Errorf("cloudflare api_token is required")
		}
		return &cloudflare.Provider{APIToken: cm.APIToken}, nil
	case "route53":
		return &route53.Provider{
			AccessKeyId:     cm.AccessKeyID,
			SecretAccessKey: cm.SecretAccessKey,
			Region:          cm.Region,
		}, nil
	case "digitalocean":
		if cm.APIToken == "" {
			return nil, fmt.Errorf("digitalocean api_token is required")
		}
		return &digitalocean.Provider{APIToken: cm.APIToken}, nil
	default:
		return nil, fmt.Errorf("unsupported dns_provider: %q", cm.DNSProvider)
	}
}
