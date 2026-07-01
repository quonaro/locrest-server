package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
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
	"locrest-server/internal/logger"
)

var portPathRegex = regexp.MustCompile(`^/(\d+)$`)

// Frontend is the public HTTP/HTTPS server that dispenses scripts,
// handles challenge-response, and reverse-proxies traffic into active tunnels.
type Frontend struct {
	cfg             atomic.Pointer[config.ServerConfig]
	configPath      string
	adminSocketPath string
	store           *auth.Store
	chisel          *chiselwrapper.Chisel
	db              *db.DB
	mu              sync.RWMutex
	// subdomain -> backend port
	routes                map[string]int
	nextPort              atomic.Uint32
	rateLimiter           *rateLimiter
	regenerateRateLimiter *rateLimiter
	// serverPort -> raw TCP listener
	tcpListeners map[int]net.Listener
}

// NewFrontend creates the HTTP frontend.
func NewFrontend(cfg *config.ServerConfig, store *auth.Store, chisel *chiselwrapper.Chisel, database *db.DB, configPath string, adminSocketPath string) *Frontend {
	f := &Frontend{
		configPath:            configPath,
		adminSocketPath:       adminSocketPath,
		store:                 store,
		chisel:                chisel,
		db:                    database,
		routes:                make(map[string]int),
		rateLimiter:           newRateLimiter(cfg.RateLimit.Requests, cfg.RateLimit.Window),
		regenerateRateLimiter: newRateLimiter(cfg.RegenerateRateLimit.Requests, cfg.RegenerateRateLimit.Window),
		tcpListeners:          make(map[int]net.Listener),
	}
	f.cfg.Store(cfg)
	return f
}

// effectiveBinaryURL returns the URL used for client binaries.
// It returns the configured binary_url, falling back to the default
// client release URL when none is set.
func (f *Frontend) effectiveBinaryURL() string {
	cfg := f.cfg.Load()
	if cfg == nil {
		return config.DefaultBinaryURL
	}
	if cfg.BinaryURL != "" {
		return cfg.BinaryURL
	}
	return config.DefaultBinaryURL
}

// Run starts the HTTP/HTTPS frontend and blocks.
func (f *Frontend) Run(ctx context.Context) error {
	cfg := f.cfg.Load()
	logger.ReloadLevel(cfg.LogLevel)

	mux := http.NewServeMux()
	mux.Handle("/tunnel", f.chisel.Handler())
	mux.Handle("/tunnel/", f.chisel.Handler())
	mux.HandleFunc("/bin/", embedbin.NewHandler(f.effectiveBinaryURL()))
	mux.HandleFunc("/register", f.handleRegister)
	mux.HandleFunc("/regenerate", f.handleRegenerate)
	mux.HandleFunc("/{path...}", f.handler)

	tlsConfig, err := f.buildTLSConfig()
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}
	tlsEnabled := tlsConfig != nil

	handler := f.securityHeaders(mux)
	handler = f.ipFilterMiddleware(handler)

	var primary *http.Server
	var insecureSrv *http.Server
	if tlsEnabled {
		primary = &http.Server{
			Addr:      fmt.Sprintf(":%d", cfg.HTTPSPort),
			Handler:   handler,
			TLSConfig: tlsConfig,
		}
		if cfg.Insecure {
			if cfg.HTTPToHTTPSRedirect {
				insecureSrv = &http.Server{Addr: fmt.Sprintf(":%d", cfg.HTTPPort), Handler: redirectToHTTPS(cfg.HTTPSPort)}
			} else {
				insecureSrv = &http.Server{Addr: fmt.Sprintf(":%d", cfg.HTTPPort), Handler: handler}
			}
		}
	} else {
		primary = &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.HTTPPort),
			Handler: handler,
		}
	}

	adminMux := f.adminMux()
	adminSrv := &http.Server{Handler: adminMux}
	_ = os.Remove(f.adminSocketPath)
	adminLn, err := net.Listen("unix", f.adminSocketPath)
	if err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	defer func() { _ = adminLn.Close() }()
	if err := os.Chmod(f.adminSocketPath, 0600); err != nil {
		return fmt.Errorf("admin socket chmod: %w", err)
	}
	go func() {
		if err := adminSrv.Serve(adminLn); err != nil && err != http.ErrServerClosed {
			slog.Error("admin server failed", "error", err)
		}
	}()

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
		if err := adminSrv.Shutdown(shutdownCtx); err != nil {
			slog.Error("admin server shutdown failed", "error", err)
		}
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

func (f *Frontend) reloadConfig() error {
	if f.configPath == "" {
		return fmt.Errorf("no config path set")
	}
	newCfg, err := config.Load(f.configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := newCfg.Validate(); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}
	oldCfg := f.cfg.Swap(newCfg)
	logger.ReloadLevel(newCfg.LogLevel)
	f.rateLimiter.reconfigure(newCfg.RateLimit.Requests, newCfg.RateLimit.Window)
	f.regenerateRateLimiter.reconfigure(newCfg.RegenerateRateLimit.Requests, newCfg.RegenerateRateLimit.Window)
	slog.Info("config reloaded", "path", f.configPath)
	_ = oldCfg
	return nil
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

	role := "auth"
	if !isAuthenticated(r, f.db) {
		role = "public"
	}
	cfg := f.cfg.Load()
	var perms config.Permissions
	if role == "public" {
		perms = cfg.Permissions.Public
	} else {
		perms = cfg.Permissions.Auth
	}

	if m := portPathRegex.FindStringSubmatch(path); m != nil && r.Method == http.MethodGet {
		localPort, _ := strconv.Atoi(m[1])
		tcpPortStr := r.URL.Query().Get("tcp")
		if tcpPortStr != "" {
			if !perms.SetTCPPort {
				http.Error(w, "Permission DENIED", http.StatusForbidden)
				return
			}
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
	if path == "/status" && cfg.StatusEndpoint {
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

// ReloadChiselUsers restores all activated sessions from persistent storage into the
// in-memory chisel server and route table. Call this once after creating the frontend.
func (f *Frontend) ReloadChiselUsers() {
	for _, sess := range f.store.All() {
		if !sess.IsActivated() {
			continue
		}
		if err := f.chisel.AddUser(sess.Subdomain, sess.Token); err != nil {
			slog.Warn("reload chisel user failed", "subdomain", sess.Subdomain, "error", err)
			continue
		}
		switch sess.Mode {
		case "http":
			f.RegisterRoute(sess.Subdomain, sess.ServerPort)
		case "tcp":
			go func(port int) {
				for i := 0; i < 50; i++ {
					if tunnel.GetProxyPipe(port) != nil {
						f.startTCPListener(port)
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
				slog.Warn("reload tcp: chisel pipe never created", "port", port)
			}(sess.ServerPort)
		}
		slog.Debug("reloaded chisel user", "subdomain", sess.Subdomain, "mode", sess.Mode)
	}
}
