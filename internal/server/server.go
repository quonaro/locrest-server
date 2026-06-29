package server

import (
	"context"
	"fmt"
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

func initLogLevel(level string) {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	slog.SetLogLoggerLevel(lv)
}

var (
	portPathRegex  = regexp.MustCompile(`^/(\d+)$`)
	portsPathRegex = regexp.MustCompile(`^/(\d+)/(\d+)$`)
)

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
		rateLimiter:           newRateLimiter(cfg.RateLimit.Requests, cfg.RateLimit.Window),
		regenerateRateLimiter: newRateLimiter(cfg.RegenerateRateLimit.Requests, cfg.RegenerateRateLimit.Window),
		tcpListeners:          make(map[int]net.Listener),
	}
}

// Run starts the HTTP/HTTPS frontend and blocks.
func (f *Frontend) Run(ctx context.Context) error {
	initLogLevel(f.cfg.LogLevel)

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

	handler := securityHeaders(mux, tlsEnabled, f.cfg.CustomHeaders)
	handler = ipFilterMiddleware(handler, f.cfg.AllowedIPs, f.cfg.BlockedIPs, f.cfg.BehindProxy)

	var primary *http.Server
	var insecureSrv *http.Server
	if tlsEnabled {
		primary = &http.Server{
			Addr:      fmt.Sprintf(":%d", f.cfg.HTTPSPort),
			Handler:   handler,
			TLSConfig: tlsConfig,
		}
		if f.cfg.Insecure {
			if f.cfg.HTTPToHTTPSRedirect {
				insecureSrv = &http.Server{Addr: fmt.Sprintf(":%d", f.cfg.HTTPPort), Handler: redirectToHTTPS(handler, f.cfg.HTTPSPort)}
			} else {
				insecureSrv = &http.Server{Addr: fmt.Sprintf(":%d", f.cfg.HTTPPort), Handler: handler}
			}
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
	var perms config.Permissions
	if role == "public" {
		perms = f.cfg.Permissions.Public
	} else {
		perms = f.cfg.Permissions.Auth
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
	if path == "/status" && f.cfg.StatusEndpoint {
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
		if sess.Mode == "http" {
			f.RegisterRoute(sess.Subdomain, sess.ServerPort)
		} else if sess.Mode == "tcp" {
			go func(port int, setupToken string) {
				for i := 0; i < 50; i++ {
					if tunnel.GetProxyPipe(port) != nil {
						f.startTCPListener(port, setupToken)
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
				slog.Warn("reload tcp: chisel pipe never created", "port", port)
			}(sess.ServerPort, sess.SetupToken)
		}
		slog.Debug("reloaded chisel user", "subdomain", sess.Subdomain, "mode", sess.Mode)
	}
}
