package server

import (
	"crypto/tls"
	"log/slog"

	"golang.org/x/crypto/acme/autocert"
)

func (f *Frontend) buildTLSConfig() (*tls.Config, error) {
	if f.cfg.TLS.Cert != "" && f.cfg.TLS.Key != "" {
		slog.Info("using BYO TLS certificate")
		cert, err := tls.LoadX509KeyPair(f.cfg.TLS.Cert, f.cfg.TLS.Key)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
		}, nil
	}

	if f.cfg.TLS.AutoTLS && len(f.cfg.TLS.Domains) > 0 {
		slog.Info("using autocert", "domains", f.cfg.TLS.Domains)
		m := &autocert.Manager{
			Cache:      autocert.DirCache("locrest-certs"),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(f.cfg.TLS.Domains...),
			Email:      f.cfg.TLS.Email,
		}
		return m.TLSConfig(), nil
	}

	return nil, nil
}
