package server

import (
	"fmt"
	"io"
	tunnel "locrest-server/internal/chiselvendor/tunnel"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
)

// isCurlLikeRequest returns true for curl/wget user-agents.
func isCurlLikeRequest(r *http.Request) bool {
	ua := strings.ToLower(r.UserAgent())
	return strings.Contains(ua, "curl") || strings.Contains(ua, "wget")
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
