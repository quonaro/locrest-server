package server

import (
	"context"
	"log/slog"
	"time"

	tunnel "locrest-server/internal/chiselvendor/tunnel"
)

func (f *Frontend) startCleaner(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.cleanStaleRoutesAndSessions()
			f.rateLimiter.cleanup()
			f.regenerateRateLimiter.cleanup()
		}
	}
}

func (f *Frontend) startDisconnectWatcher(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.cleanStaleRoutesAndSessions()
		}
	}
}

func (f *Frontend) cleanStaleRoutesAndSessions() {
	var staleRoutes []string
	var expiredSessions []string
	f.mu.Lock()
	for subdomain, port := range f.routes {
		if tunnel.GetProxyPipe(port) == nil {
			staleRoutes = append(staleRoutes, subdomain)
			delete(f.routes, subdomain)
		}
	}
	cfg := f.cfg.Load()
	if cfg.Tunnel.TTL > 0 {
		now := time.Now()
		for _, sess := range f.store.All() {
			if !sess.Infinity && now.After(sess.ExpiresAt) {
				expiredSessions = append(expiredSessions, sess.SetupToken)
				delete(f.routes, sess.Subdomain)
			}
		}
	}
	f.mu.Unlock()

	for _, subdomain := range staleRoutes {
		slog.Debug("cleaner: removing stale route", "subdomain", subdomain)
		f.chisel.DeleteUser(subdomain)
		if sess, ok := f.store.GetBySubdomain(subdomain); ok {
			slog.Info("cleaner: deleting stale session", "subdomain", sess.Subdomain, "setup_token_prefix", sess.SetupToken[:8])
			f.store.Delete(sess.SetupToken)
		}
	}
	for _, setupToken := range expiredSessions {
		sess, ok := f.store.Get(setupToken)
		if ok {
			slog.Info("cleaner: deleting expired session", "subdomain", sess.Subdomain, "setup_token_prefix", sess.SetupToken[:8], "ttl", cfg.Tunnel.TTL)
			if sess.Mode == "tcp" {
				f.closeTCPListener(sess.ServerPort)
				f.chisel.DeleteUser(sess.Subdomain)
			}
		}
		f.store.Delete(setupToken)
	}
	if len(staleRoutes) > 0 || len(expiredSessions) > 0 {
		slog.Info("cleaner finished", "stale_routes", len(staleRoutes), "expired_sessions", len(expiredSessions))
	}
}
