package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/gorilla/websocket"

	tunnel "locrest-server/internal/chiselvendor/tunnel"
)

func (f *Frontend) proxyWebSocket(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}

	f.mu.RLock()
	backendPort, ok := f.routes[host]
	if !ok {
		parts := strings.SplitN(host, ".", 2)
		if len(parts) == 2 {
			backendPort, ok = f.routes[parts[0]]
		}
	}
	f.mu.RUnlock()
	if !ok {
		http.Error(w, "No active tunnel for this host", http.StatusNotFound)
		return
	}

	pipeCh := tunnel.GetProxyPipe(backendPort)
	if pipeCh == nil {
		http.Error(w, "No active tunnel for this host", http.StatusNotFound)
		return
	}

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

	backendURL := fmt.Sprintf("ws://localhost%s", r.URL.RequestURI())
	backendConn, resp, err := dialer.Dial(backendURL, header)
	if err != nil {
		if strings.Contains(err.Error(), "tunnel pipe full") {
			http.Error(w, "Tunnel overloaded", http.StatusServiceUnavailable)
			return
		}
		if resp != nil {
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
			resp.Body.Close()
		} else {
			http.Error(w, "backend unavailable", http.StatusBadGateway)
		}
		return
	}
	defer backendConn.Close()

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
			return host == f.cfg.Domain || strings.HasSuffix(host, "."+f.cfg.Domain)
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
	defer clientConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			mt, msg, err := backendConn.ReadMessage()
			if err != nil {
				clientConn.Close()
				return
			}
			if err := clientConn.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			mt, msg, err := clientConn.ReadMessage()
			if err != nil {
				backendConn.Close()
				return
			}
			if err := backendConn.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	}()
	wg.Wait()
}

func (f *Frontend) proxyTunnel(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}

	f.mu.RLock()
	backendPort, ok := f.routes[host]
	if !ok {
		parts := strings.SplitN(host, ".", 2)
		if len(parts) == 2 {
			backendPort, ok = f.routes[parts[0]]
		}
	}
	f.mu.RUnlock()
	if !ok {
		http.Error(w, "No active tunnel for this host", http.StatusNotFound)
		return
	}

	pipeCh := tunnel.GetProxyPipe(backendPort)
	if pipeCh == nil {
		http.Error(w, "No active tunnel for this host", http.StatusNotFound)
		return
	}

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
		},
		Transport: tr,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if strings.Contains(err.Error(), "tunnel pipe full") {
				http.Error(w, "Tunnel overloaded", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, "backend unavailable", http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}
