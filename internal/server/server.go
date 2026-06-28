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
	routes map[string]int
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

// Run starts the HTTPS frontend and blocks.
func (f *Frontend) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/tunnel", f.chisel.Handler())
	mux.Handle("/tunnel/", f.chisel.Handler())
	mux.HandleFunc("/bin/", embedbin.ServeBinary)
	mux.HandleFunc("/", f.handler)

	tlsConfig, err := f.buildTLSConfig()
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", f.cfg.Port),
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	go f.startCleaner(ctx)

	slog.Info("frontend listening", "addr", server.Addr, "tls", tlsConfig != nil)

	var redirectSrv *http.Server
	if tlsConfig != nil && f.cfg.Port != 80 {
		redirectSrv = &http.Server{Addr: ":80", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + r.Host + r.URL.RequestURI()
			if colonIdx := strings.LastIndex(r.Host, ":"); colonIdx != -1 {
				target = "https://" + r.Host[:colonIdx] + r.URL.RequestURI()
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})}
		go func() {
			if err := redirectSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("http redirect server failed", "error", err)
			}
		}()
	}

	errCh := make(chan error, 1)
	go func() {
		if tlsConfig != nil {
			errCh <- server.ListenAndServeTLS("", "")
		} else {
			errCh <- server.ListenAndServe()
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if redirectSrv != nil {
			redirectSrv.Shutdown(shutdownCtx)
		}
		if err := server.Shutdown(shutdownCtx); err != nil {
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
					delete(f.routes, subdomain)
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
