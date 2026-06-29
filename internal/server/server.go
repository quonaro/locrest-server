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

// Frontend is the public HTTP/HTTPS server that dispenses scripts,
// handles challenge-response, and reverse-proxies traffic into active tunnels.
type Frontend struct {
	cfg    *config.ServerConfig
	store  *auth.Store
	chisel *chiselwrapper.Chisel
	mu     sync.RWMutex
	// subdomain -> backend port
	routes   map[string]int
	nextPort atomic.Uint32
}

// NewFrontend creates the HTTP frontend.
func NewFrontend(cfg *config.ServerConfig, store *auth.Store, chisel *chiselwrapper.Chisel) *Frontend {
	return &Frontend{
		cfg:    cfg,
		store:  store,
		chisel: chisel,
		routes: make(map[string]int),
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
			f.mu.Lock()
			for subdomain, port := range f.routes {
				if tunnel.GetProxyPipe(port) == nil {
					f.chisel.DeleteUser(subdomain)
					delete(f.routes, subdomain)
				}
			}

			if f.cfg.ScriptTTL > 0 {
				cutoff := time.Now().Add(-f.cfg.ScriptTTL)
				for _, sess := range f.store.Expired(cutoff) {
					if tunnel.GetProxyPipe(sess.ServerPort) != nil {
						sess.Touch()
						continue
					}
					f.chisel.DeleteUser(sess.Subdomain)
					delete(f.routes, sess.Subdomain)
					f.store.Delete(sess.SetupToken)
				}
			}
			f.mu.Unlock()
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
