package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	tunnel "locrest-server/internal/chiselvendor/tunnel"
)

func (f *Frontend) proxyWebSocket(w http.ResponseWriter, r *http.Request) {
	backendPort, subdomain, ok := f.resolveRoute(r.Host)
	cfg := f.cfg.Load()
	ip := clientIP(r, cfg.Network.BehindProxy)
	if !ok {
		if cfg.Runtime.RootPage && f.isRootHost(r.Host) {
			f.handleRoot(w, r)
			return
		}
		slog.Warn("websocket tunnel not found", "ip", ip, "host", r.Host)
		f.sendHTMLError(w, r, http.StatusNotFound, "Tunnel Not Found", "No active tunnel for this host. The tunnel may have expired or the subdomain is incorrect.")
		return
	}
	if !f.checkBasicAuth(w, r, subdomain) {
		slog.Warn("websocket basic auth failed", "ip", ip, "subdomain", subdomain)
		return
	}
	if !f.checkAllowedIPs(w, r, subdomain) {
		slog.Warn("websocket IP not allowed", "ip", ip, "subdomain", subdomain)
		return
	}

	pipeCh := tunnel.GetProxyPipe(backendPort)
	if pipeCh == nil {
		slog.Warn("websocket tunnel pipe missing", "ip", ip, "subdomain", subdomain, "backend_port", backendPort)
		f.sendHTMLError(w, r, http.StatusNotFound, "Tunnel Not Found", "No active tunnel for this host. The tunnel may have expired or the subdomain is incorrect.")
		return
	}
	slog.Debug("websocket proxy", "ip", ip, "subdomain", subdomain, "backend_port", backendPort)

	dialer := websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			select {
			case pipeCh <- serverConn:
			default:
				return nil, fmt.Errorf("tunnel pipe full")
			}
			return clientConn, nil
		},
	}

	header := http.Header{}
	for k, v := range r.Header {
		if !strings.EqualFold(k, "Upgrade") && !strings.EqualFold(k, "Connection") &&
			!strings.EqualFold(k, "Sec-Websocket-Key") &&
			!strings.EqualFold(k, "Sec-Websocket-Version") &&
			!strings.EqualFold(k, "Sec-Websocket-Extensions") {
			header[k] = v
		}
	}
	proto := r.Header.Get("Sec-Websocket-Protocol")
	if proto != "" {
		header.Set("Sec-Websocket-Protocol", proto)
	}

	// Preserve the original Host so the backend sees the public domain, not "localhost".
	header.Set("Host", r.Host)

	uri := r.URL.RequestURI()
	if cfg.Tunnel.StripErrorParam {
		u := *r.URL
		u.RawQuery = stripErrorParam(u.RawQuery)
		uri = u.RequestURI()
	}
	backendURL := fmt.Sprintf("ws://localhost%s", uri)
	backendConn, resp, err := dialer.Dial(backendURL, header)
	if err != nil {
		if strings.Contains(err.Error(), "tunnel pipe full") {
			f.sendHTMLError(w, r, http.StatusServiceUnavailable, "Tunnel Overloaded", "The tunnel is currently overloaded. Please try again in a moment.")
			return
		}
		if resp != nil {
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
			_ = resp.Body.Close()
		} else {
			f.sendHTMLError(w, r, http.StatusServiceUnavailable, "Service Offline", "Your local service is offline. Start it to enable this tunnel.")
		}
		return
	}
	defer func() { _ = backendConn.Close() }()

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}
			host := u.Host
			if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
				host = host[:colonIdx]
			}
			return host == cfg.Network.Domain || strings.HasSuffix(host, "."+cfg.Network.Domain)
		},
	}

	// Forward the subprotocol selected by the backend to the client.
	respHeader := http.Header{}
	if resp != nil && resp.Header.Get("Sec-Websocket-Protocol") != "" {
		respHeader.Set("Sec-Websocket-Protocol", resp.Header.Get("Sec-Websocket-Protocol"))
	}
	clientConn, err := upgrader.Upgrade(w, r, respHeader)
	if err != nil {
		return
	}
	defer func() { _ = clientConn.Close() }()

	var wg sync.WaitGroup
	wg.Add(2)
	const pipeTimeout = 60 * time.Second
	go func() {
		defer wg.Done()
		for {
			_ = backendConn.SetReadDeadline(time.Now().Add(pipeTimeout))
			mt, msg, err := backendConn.ReadMessage()
			if err != nil {
				_ = clientConn.Close()
				return
			}
			_ = clientConn.SetWriteDeadline(time.Now().Add(pipeTimeout))
			if err := clientConn.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			_ = clientConn.SetReadDeadline(time.Now().Add(pipeTimeout))
			mt, msg, err := clientConn.ReadMessage()
			if err != nil {
				_ = backendConn.Close()
				return
			}
			_ = backendConn.SetWriteDeadline(time.Now().Add(pipeTimeout))
			if err := backendConn.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	}()
	wg.Wait()
}

func (f *Frontend) proxyTunnel(w http.ResponseWriter, r *http.Request) {
	backendPort, subdomain, ok := f.resolveRoute(r.Host)
	cfg := f.cfg.Load()
	ip := clientIP(r, cfg.Network.BehindProxy)
	if !ok {
		if cfg.Runtime.RootPage && f.isRootHost(r.Host) {
			f.handleRoot(w, r)
			return
		}
		slog.Warn("http tunnel not found", "ip", ip, "host", r.Host)
		f.sendHTMLError(w, r, http.StatusNotFound, "Tunnel Not Found", "No active tunnel for this host. The tunnel may have expired or the subdomain is incorrect.")
		return
	}
	if !f.checkBasicAuth(w, r, subdomain) {
		slog.Warn("http basic auth failed", "ip", ip, "subdomain", subdomain)
		return
	}
	if !f.checkAllowedIPs(w, r, subdomain) {
		slog.Warn("http IP not allowed", "ip", ip, "subdomain", subdomain)
		return
	}

	pipeCh := tunnel.GetProxyPipe(backendPort)
	if pipeCh == nil {
		slog.Warn("http tunnel pipe missing", "ip", ip, "subdomain", subdomain, "backend_port", backendPort)
		f.sendHTMLError(w, r, http.StatusNotFound, "Tunnel Not Found", "No active tunnel for this host. The tunnel may have expired or the subdomain is incorrect.")
		return
	}
	slog.Debug("http proxy", "ip", ip, "subdomain", subdomain, "backend_port", backendPort, "path", r.URL.Path)

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			select {
			case pipeCh <- serverConn:
			default:
				return nil, fmt.Errorf("tunnel pipe full")
			}
			return clientConn, nil
		},
		DisableKeepAlives: true,
	}
	proxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = r.Host
			if cfg.Tunnel.StripErrorParam {
				req.URL.RawQuery = stripErrorParam(req.URL.RawQuery)
			}
		},
		Transport: tr,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if strings.Contains(err.Error(), "tunnel pipe full") {
				f.sendHTMLError(w, r, http.StatusServiceUnavailable, "Tunnel Overloaded", "The tunnel is currently overloaded. Please try again in a moment.")
				return
			}
			f.sendHTMLError(w, r, http.StatusServiceUnavailable, "Service Offline", "Your local service is offline. Start it to enable this tunnel.")
		},
	}
	proxy.ServeHTTP(w, r)
}
