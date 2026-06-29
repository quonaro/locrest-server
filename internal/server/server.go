package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"locrest-server/internal/auth"
	tunnel "locrest-server/internal/chiselvendor/tunnel"
	"locrest-server/internal/chiselwrapper"
	"locrest-server/internal/config"
	"locrest-server/internal/embedbin"
)

var (
	portPathRegex  = regexp.MustCompile(`^/(\d+)$`)
	portsPathRegex = regexp.MustCompile(`^/(\d+)/(\d+)$`)
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

// Frontend is the public HTTP/HTTPS server that dispenses scripts,
// handles challenge-response, and reverse-proxies traffic into active tunnels.
type Frontend struct {
	cfg    *config.ServerConfig
	store  *auth.Store
	chisel *chiselwrapper.Chisel
	mu     sync.RWMutex
	// subdomain -> backend port
	routes      map[string]int
	nextPort    atomic.Uint32
	rateLimiter *rateLimiter
}

// NewFrontend creates the HTTP frontend.
func NewFrontend(cfg *config.ServerConfig, store *auth.Store, chisel *chiselwrapper.Chisel) *Frontend {
	return &Frontend{
		cfg:         cfg,
		store:       store,
		chisel:      chisel,
		routes:      make(map[string]int),
		rateLimiter: newRateLimiter(10, time.Minute),
	}
}

// NextServerPort returns a unique internal port number for reverse-tunnel allocation.
func (f *Frontend) NextServerPort() int {
	return int(f.nextPort.Add(1)%40000 + 20000)
}

func securityHeaders(next http.Handler, tls bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if tls {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// Run starts the HTTP/HTTPS frontend and blocks.
func (f *Frontend) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/tunnel", f.chisel.Handler())
	mux.Handle("/tunnel/", f.chisel.Handler())
	mux.HandleFunc("/bin/", embedbin.NewHandler(f.cfg.Dev, f.cfg.BinaryURL))
	mux.HandleFunc("/register", f.handleRegister)
	mux.HandleFunc("/", f.handler)

	tlsConfig, err := f.buildTLSConfig()
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}
	tlsEnabled := tlsConfig != nil

	handler := securityHeaders(mux, tlsEnabled)

	primary := &http.Server{
		Addr:      fmt.Sprintf(":%d", f.cfg.Port),
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	var insecureSrv *http.Server
	if tlsEnabled && f.cfg.Insecure {
		insecureSrv = &http.Server{Addr: ":80", Handler: handler}
	}

	go f.startCleaner(ctx)

	slog.Info("frontend listening", "addr", primary.Addr, "tls", tlsEnabled, "insecure", insecureSrv != nil)

	errCh := make(chan error, 2)
	go func() {
		if tlsEnabled {
			errCh <- primary.ListenAndServeTLS("", "")
		} else {
			errCh <- primary.ListenAndServe()
		}
	}()
	if insecureSrv != nil {
		go func() {
			if err := insecureSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("insecure server failed", "error", err)
			}
		}()
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if insecureSrv != nil {
			if err := insecureSrv.Shutdown(shutdownCtx); err != nil {
				slog.Error("insecure server shutdown failed", "error", err)
			}
		}
		if err := primary.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// RegisterRoute maps a subdomain to a local backend port.
func (f *Frontend) RegisterRoute(subdomain string, backendPort int) {
	f.mu.Lock()
	f.routes[subdomain] = backendPort
	f.mu.Unlock()
}

// UnregisterRoute removes a subdomain mapping.
func (f *Frontend) UnregisterRoute(subdomain string) {
	f.mu.Lock()
	delete(f.routes, subdomain)
	f.mu.Unlock()
}

func (f *Frontend) startCleaner(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Collect stale routes and expired sessions while holding the lock.
			var staleRoutes []string
			var expiredSessions []string
			f.mu.Lock()
			for subdomain, port := range f.routes {
				if tunnel.GetProxyPipe(port) == nil {
					staleRoutes = append(staleRoutes, subdomain)
					delete(f.routes, subdomain)
				}
			}
			if f.cfg.TTL > 0 {
				now := time.Now()
				for _, sess := range f.store.All() {
					if now.After(sess.ExpiresAt) {
						expiredSessions = append(expiredSessions, sess.SetupToken)
						delete(f.routes, sess.Subdomain)
					}
				}
			}
			f.mu.Unlock()

			// Perform I/O outside the lock.
			for _, subdomain := range staleRoutes {
				slog.Debug("cleaner: removing stale route", "subdomain", subdomain)
				f.chisel.DeleteUser(subdomain)
			}
			for _, setupToken := range expiredSessions {
				sess, ok := f.store.Get(setupToken)
				if ok {
					slog.Info("cleaner: deleting expired session", "subdomain", sess.Subdomain, "setup_token_prefix", sess.SetupToken[:8], "ttl", f.cfg.TTL)
				}
				f.store.Delete(setupToken)
			}

			f.rateLimiter.cleanup()
		}
	}
}

func (f *Frontend) handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	targetHost := r.URL.Query().Get("host")

	if m := portPathRegex.FindStringSubmatch(path); m != nil && r.Method == http.MethodGet {
		localPort, _ := strconv.Atoi(m[1])
		f.handleScript(w, r, localPort, localPort, targetHost)
		return
	}
	if m := portsPathRegex.FindStringSubmatch(path); m != nil && r.Method == http.MethodGet {
		localPort, _ := strconv.Atoi(m[1])
		remotePort, _ := strconv.Atoi(m[2])
		f.handleScript(w, r, localPort, remotePort, targetHost)
		return
	}

	if path == "/challenge" {
		f.handleChallenge(w, r)
		return
	}
	if path == "/status" {
		f.handleStatus(w, r)
		return
	}
	if path == "/verify" {
		f.handleVerify(w, r)
		return
	}

	if lowerUpgrade(r.Header.Get("Upgrade")) == "websocket" {
		f.proxyWebSocket(w, r)
		return
	}

	f.proxyTunnel(w, r)
}

func lowerUpgrade(v string) string {
	return strings.ToLower(v)
}
