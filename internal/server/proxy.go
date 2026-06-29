package server

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
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

//go:embed assets/error.html
var errorPageBytes []byte

var errorPageTmpl = template.Must(template.New("error").Parse(string(errorPageBytes)))

func (f *Frontend) sendHTMLError(w http.ResponseWriter, r *http.Request, code int, title, message string) {
	if r.URL.Query().Get("error") == "json" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  code,
			"error":   title,
			"message": message,
		})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = errorPageTmpl.Execute(w, map[string]any{
		"Code":    code,
		"Title":   title,
		"Message": message,
		"Domain":  f.cfg.Domain,
	})
}

func stripErrorParam(rawQuery string) string {
	q, _ := url.ParseQuery(rawQuery)
	q.Del("error")
	return q.Encode()
}

func (f *Frontend) proxyWebSocket(w http.ResponseWriter, r *http.Request) {
	backendPort, _, ok := f.resolveRoute(r.Host)
	if !ok {
		f.sendHTMLError(w, r, http.StatusNotFound, "Tunnel Not Found", "No active tunnel for this host. The tunnel may have expired or the subdomain is incorrect.")
		return
	}

	pipeCh := tunnel.GetProxyPipe(backendPort)
	if pipeCh == nil {
		f.sendHTMLError(w, r, http.StatusNotFound, "Tunnel Not Found", "No active tunnel for this host. The tunnel may have expired or the subdomain is incorrect.")
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

	uri := r.URL.RequestURI()
	if f.cfg.StripErrorParam {
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
			io.Copy(w, resp.Body)
			resp.Body.Close()
		} else {
			f.sendHTMLError(w, r, http.StatusBadGateway, "Backend Unavailable", "The backend service is temporarily unavailable.")
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
	const pipeTimeout = 60 * time.Second
	go func() {
		defer wg.Done()
		for {
			backendConn.SetReadDeadline(time.Now().Add(pipeTimeout))
			mt, msg, err := backendConn.ReadMessage()
			if err != nil {
				clientConn.Close()
				return
			}
			clientConn.SetWriteDeadline(time.Now().Add(pipeTimeout))
			if err := clientConn.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			clientConn.SetReadDeadline(time.Now().Add(pipeTimeout))
			mt, msg, err := clientConn.ReadMessage()
			if err != nil {
				backendConn.Close()
				return
			}
			backendConn.SetWriteDeadline(time.Now().Add(pipeTimeout))
			if err := backendConn.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	}()
	wg.Wait()
}

func (f *Frontend) proxyTunnel(w http.ResponseWriter, r *http.Request) {
	backendPort, _, ok := f.resolveRoute(r.Host)
	if !ok {
		f.sendHTMLError(w, r, http.StatusNotFound, "Tunnel Not Found", "No active tunnel for this host. The tunnel may have expired or the subdomain is incorrect.")
		return
	}

	pipeCh := tunnel.GetProxyPipe(backendPort)
	if pipeCh == nil {
		f.sendHTMLError(w, r, http.StatusNotFound, "Tunnel Not Found", "No active tunnel for this host. The tunnel may have expired or the subdomain is incorrect.")
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
			if f.cfg.StripErrorParam {
				req.URL.RawQuery = stripErrorParam(req.URL.RawQuery)
			}
		},
		Transport: tr,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if strings.Contains(err.Error(), "tunnel pipe full") {
				f.sendHTMLError(w, r, http.StatusServiceUnavailable, "Tunnel Overloaded", "The tunnel is currently overloaded. Please try again in a moment.")
				return
			}
			f.sendHTMLError(w, r, http.StatusBadGateway, "Backend Unavailable", "The backend service is temporarily unavailable.")
		},
	}
	proxy.ServeHTTP(w, r)
}
