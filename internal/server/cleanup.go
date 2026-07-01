package server

import (
	"context"
	tunnel "locrest-server/internal/chiselvendor/tunnel"
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
	var disconnectedSessions []string
	var httpRoutesToDelete []string

	cfg := f.cfg.Load()
	now := time.Now()
	for _, sess := range f.store.All() {
		if !sess.IsActivated() {
			continue
		}
		if sess.Mode == "tcp" || sess.Mode == "tcp/udp" {
			tcpGone := tunnel.GetProxyPipe(sess.ServerPort, "tcp") == nil
			udpGone := true
			if sess.Mode == "tcp/udp" {
				udpGone = tunnel.GetProxyPipe(sess.ServerPort, "udp") == nil
			}
			if tcpGone && udpGone {
				disconnectedSessions = append(disconnectedSessions, sess.SetupToken)
				continue
			}
		}
		if cfg.Tunnel.TTL > 0 && !sess.Infinity && now.After(sess.ExpiresAt) {
			expiredSessions = append(expiredSessions, sess.SetupToken)
			if sess.Mode == "http" {
				httpRoutesToDelete = append(httpRoutesToDelete, sess.Subdomain)
			}
		}
	}

	f.mu.Lock()
	for _, sub := range httpRoutesToDelete {
		delete(f.routes, sub)
	}
	f.mu.Unlock()

	for _, setupToken := range expiredSessions {
		sess, ok := f.store.Get(setupToken)
		if !ok {
			continue
		}
		slog.Info("cleaner: deleting expired session", "subdomain", sess.Subdomain, "setup_token_prefix", sess.SetupToken[:8], "ttl", cfg.Tunnel.TTL)
		if sess.Mode == "tcp" || sess.Mode == "tcp/udp" {
			f.closeTCPListener(sess.ServerPort)
		}
		if sess.Mode == "tcp/udp" {
			f.closeUDPListener(sess.ServerPort)
		}
		f.chisel.DeleteUser(sess.Subdomain)
		f.store.Delete(setupToken)
	}
	for _, setupToken := range disconnectedSessions {
		sess, ok := f.store.Get(setupToken)
		if !ok {
			continue
		}
		slog.Info("cleaner: deleting disconnected session", "subdomain", sess.Subdomain, "setup_token_prefix", sess.SetupToken[:8], "server_port", sess.ServerPort)
		if sess.Mode == "tcp" || sess.Mode == "tcp/udp" {
			f.closeTCPListener(sess.ServerPort)
		}
		if sess.Mode == "tcp/udp" {
			f.closeUDPListener(sess.ServerPort)
		}
		f.chisel.DeleteUser(sess.Subdomain)
		f.store.Delete(setupToken)
	}
	total := len(expiredSessions) + len(disconnectedSessions)
	if total > 0 {
		slog.Info("cleaner finished", "expired_sessions", len(expiredSessions), "disconnected_sessions", len(disconnectedSessions))
	}
}
