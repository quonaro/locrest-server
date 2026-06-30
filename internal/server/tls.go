package server

import (
	"crypto/tls"
	"log/slog"

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
