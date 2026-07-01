package server

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// rateLimiter is an in-memory sliding-window rate limiter per IP.
type rateLimiter struct {
	mu      sync.Mutex
	windows map[string][]time.Time // IP -> request timestamps
	limit   int
	window  time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		windows: make(map[string][]time.Time),
		limit:   limit,
		window:  window,
	}
}

func (rl *rateLimiter) reconfigure(limit int, window time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.limit = limit
	rl.window = window
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)
	// drop old entries
	recent := make([]time.Time, 0, len(rl.windows[ip]))
	for _, t := range rl.windows[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= rl.limit {
		rl.windows[ip] = recent
		return false
	}
	rl.windows[ip] = append(recent, now)
	return true
}

func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-rl.window)
	for ip, times := range rl.windows {
		recent := make([]time.Time, 0, len(times))
		for _, t := range times {
			if t.After(cutoff) {
				recent = append(recent, t)
			}
		}
		if len(recent) == 0 {
			delete(rl.windows, ip)
		} else {
			rl.windows[ip] = recent
		}
	}
}

func (f *Frontend) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if cfg := f.cfg.Load(); cfg != nil {
			for k, v := range cfg.CustomHeaders {
				w.Header().Set(k, v)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (f *Frontend) ipFilterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := f.cfg.Load()
		if cfg == nil {
			next.ServeHTTP(w, r)
			return
		}
		ip := clientIP(r, cfg.BehindProxy)
		if len(cfg.AllowedIPs) > 0 && !ipAllowed(ip, cfg.AllowedIPs) {
			slog.Warn("request from IP not in allowed list", "ip", ip, "path", r.URL.Path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if len(cfg.BlockedIPs) > 0 && ipAllowed(ip, cfg.BlockedIPs) {
			slog.Warn("request from blocked IP", "ip", ip, "path", r.URL.Path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func redirectToHTTPS(httpsPort int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := fmt.Sprintf("https://%s%s", r.Host, r.URL.RequestURI())
		if httpsPort != 443 {
			host := r.Host
			if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
				host = host[:colonIdx]
			}
			target = fmt.Sprintf("https://%s:%d%s", host, httpsPort, r.URL.RequestURI())
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

func clientIP(r *http.Request, behindProxy bool) string {
	if behindProxy {
		ip := r.Header.Get("X-Forwarded-For")
		if ip != "" {
			parts := strings.Split(ip, ",")
			if len(parts) > 0 {
				return strings.TrimSpace(parts[0])
			}
		}
		ip = r.Header.Get("X-Real-Ip")
		if ip != "" {
			return strings.TrimSpace(ip)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
