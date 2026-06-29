package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	"locrest-server/internal/db"
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
	db     *db.DB
	mu     sync.RWMutex
	// subdomain -> backend port
	routes                map[string]int
	nextPort              atomic.Uint32
	rateLimiter           *rateLimiter
	regenerateRateLimiter *rateLimiter
	// serverPort -> raw TCP listener
	tcpListeners map[int]net.Listener
}

// NewFrontend creates the HTTP frontend.
func NewFrontend(cfg *config.ServerConfig, store *auth.Store, chisel *chiselwrapper.Chisel, database *db.DB) *Frontend {
	return &Frontend{
		cfg:                   cfg,
		store:                 store,
		chisel:                chisel,
		db:                    database,
		routes:                make(map[string]int),
		rateLimiter:           newRateLimiter(10, time.Minute),
		regenerateRateLimiter: newRateLimiter(3, time.Minute),
		tcpListeners:          make(map[int]net.Listener),
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
	mux.HandleFunc("/regenerate", f.handleRegenerate)
	mux.HandleFunc("/", f.handler)

	tlsConfig, err := f.buildTLSConfig()
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}
	tlsEnabled := tlsConfig != nil

	handler := securityHeaders(mux, tlsEnabled)

	var primary *http.Server
	var insecureSrv *http.Server
	if tlsEnabled {
		primary = &http.Server{
			Addr:      fmt.Sprintf(":%d", f.cfg.HTTPSPort),
			Handler:   handler,
			TLSConfig: tlsConfig,
		}
		if f.cfg.Insecure {
			insecureSrv = &http.Server{Addr: fmt.Sprintf(":%d", f.cfg.HTTPPort), Handler: handler}
		}
	} else {
		primary = &http.Server{
			Addr:    fmt.Sprintf(":%d", f.cfg.HTTPPort),
			Handler: handler,
		}
	}

	go f.startCleaner(ctx)
	go f.startDisconnectWatcher(ctx)

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

// isPortInUse reports whether any active route or TCP listener already uses the given port.
func (f *Frontend) isPortInUse(port int) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, p := range f.routes {
		if p == port {
			return true
		}
	}
	_, ok := f.tcpListeners[port]
	return ok
}

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
			slog.Info("cleaner: deleting expired session", "subdomain", sess.Subdomain, "setup_token_prefix", sess.SetupToken[:8], "ttl", f.cfg.TTL)
			if sess.Mode == "tcp" {
				f.closeTCPListener(sess.ServerPort)
				f.chisel.DeleteUser(sess.Subdomain)
			}
		}
		f.store.Delete(setupToken)
	}
}

func (f *Frontend) startTCPListener(port int, setupToken string) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("tcp raw listen failed", "port", port, "error", err)
		return
	}
	f.mu.Lock()
	f.tcpListeners[port] = ln
	f.mu.Unlock()

	defer func() {
		ln.Close()
		f.mu.Lock()
		delete(f.tcpListeners, port)
		f.mu.Unlock()
	}()

	slog.Info("tcp raw listening", "port", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			slog.Debug("tcp raw accept error", "port", port, "error", err)
			return
		}
		pipeCh := tunnel.GetProxyPipe(port)
		if pipeCh == nil {
			conn.Close()
			continue
		}
		clientPipe, serverPipe := net.Pipe()
		select {
		case pipeCh <- serverPipe:
		default:
			clientPipe.Close()
			conn.Close()
			continue
		}
		go func(c net.Conn) {
			defer clientPipe.Close()
			defer c.Close()
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { io.Copy(clientPipe, c); wg.Done() }()
			go func() { io.Copy(c, clientPipe); wg.Done() }()
			wg.Wait()
		}(conn)
	}
}

func (f *Frontend) closeTCPListener(port int) {
	f.mu.Lock()
	ln := f.tcpListeners[port]
	delete(f.tcpListeners, port)
	f.mu.Unlock()
	if ln != nil {
		ln.Close()
		slog.Debug("tcp raw listener closed", "port", port)
	}
}

// resolveRoute looks up the backend port for a given host (or subdomain).
func (f *Frontend) resolveRoute(host string) (port int, subdomain string, ok bool) {
	if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	port, ok = f.routes[host]
	if ok {
		return port, host, true
	}
	parts := strings.SplitN(host, ".", 2)
	if len(parts) == 2 {
		port, ok = f.routes[parts[0]]
		if ok {
			return port, parts[0], true
		}
	}
	return 0, "", false
}

func (f *Frontend) handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	targetHost := r.URL.Query().Get("host")
	httpAuth := r.URL.Query().Get("http_auth")
	if httpAuth == "true" {
		user, err := auth.RandString(8)
		if err != nil {
			http.Error(w, "Failed to generate credentials", http.StatusInternalServerError)
			return
		}
		pass, err := auth.RandString(16)
		if err != nil {
			http.Error(w, "Failed to generate credentials", http.StatusInternalServerError)
			return
		}
		httpAuth = user + ":" + pass
	} else if httpAuth != "" && !strings.Contains(httpAuth, ":") {
		http.Error(w, "http_auth must be 'true' or 'user:pass'", http.StatusBadRequest)
		return
	}

	if m := portPathRegex.FindStringSubmatch(path); m != nil && r.Method == http.MethodGet {
		localPort, _ := strconv.Atoi(m[1])
		tcpPortStr := r.URL.Query().Get("tcp")
		if tcpPortStr != "" {
			remotePort, _ := strconv.Atoi(tcpPortStr)
			f.handleScript(w, r, localPort, remotePort, targetHost, "tcp", httpAuth)
		} else {
			f.handleScript(w, r, localPort, 0, targetHost, "http", httpAuth)
		}
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
