package server

import (
	"fmt"
	"io"
	tunnel "locrest-server/internal/chiselvendor/tunnel"
	"log/slog"
	"net"
	"sync"
)

func (f *Frontend) startTCPListener(port int) {
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
		_ = ln.Close()
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
		pipeCh := tunnel.GetProxyPipe(port, "tcp")
		if pipeCh == nil {
			_ = conn.Close()
			continue
		}
		clientPipe, serverPipe := net.Pipe()
		select {
		case pipeCh <- serverPipe:
		default:
			_ = clientPipe.Close()
			_ = conn.Close()
			continue
		}
		go func(c net.Conn) {
			defer func() { _ = clientPipe.Close() }()
			defer func() { _ = c.Close() }()
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { _, _ = io.Copy(clientPipe, c); wg.Done() }()
			go func() { _, _ = io.Copy(c, clientPipe); wg.Done() }()
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
		_ = ln.Close()
		slog.Debug("tcp raw listener closed", "port", port)
	}
}
