package server

import (
	"context"
	"log/slog"
	"time"
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
	var expiredSessions []string
	f.mu.Lock()
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

	for _, setupToken := range expiredSessions {
		sess, ok := f.store.Get(setupToken)
		if ok {
			slog.Info("cleaner: deleting expired session", "subdomain", sess.Subdomain, "setup_token_prefix", sess.SetupToken[:8], "ttl", cfg.Tunnel.TTL)
			if sess.Mode == "tcp" || sess.Mode == "tcp/udp" {
				f.closeTCPListener(sess.ServerPort)
			}
			if sess.Mode == "tcp/udp" {
				f.closeUDPListener(sess.ServerPort)
			}
			f.chisel.DeleteUser(sess.Subdomain)
		}
		f.store.Delete(setupToken)
	}
	if len(expiredSessions) > 0 {
		slog.Info("cleaner finished", "expired_sessions", len(expiredSessions))
	}
}
