package server

import (
	"encoding/gob"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	tunnel "locrest-server/internal/chiselvendor/tunnel"
)

func (f *Frontend) startUDPListener(port int) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		slog.Error("udp raw resolve failed", "port", port, "error", err)
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		slog.Error("udp raw listen failed", "port", port, "error", err)
		return
	}
	f.mu.Lock()
	f.udpListeners[port] = conn
	f.mu.Unlock()

	defer func() {
		_ = conn.Close()
		f.mu.Lock()
		delete(f.udpListeners, port)
		f.mu.Unlock()
	}()

	slog.Info("udp raw listening", "port", port)

	pipeCh := tunnel.GetProxyPipe(port)
	if pipeCh == nil {
		slog.Warn("udp raw: no proxy pipe", "port", port)
		return
	}

	// Obtain the single pipe connection for this UDP listener.
	clientPipe, serverPipe := net.Pipe()
	select {
	case pipeCh <- serverPipe:
	default:
		_ = clientPipe.Close()
		return
	}
	defer func() { _ = clientPipe.Close() }()

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine: read from chisel (clientPipe) and write UDP responses.
	go func() {
		defer wg.Done()
		dec := gob.NewDecoder(clientPipe)
		for {
			var p tunnel.UDPPacket
			if err := dec.Decode(&p); err != nil {
				if err != io.EOF {
					slog.Debug("udp raw decode error", "port", port, "error", err)
				}
				return
			}
			dst, err := net.ResolveUDPAddr("udp", p.Src)
			if err != nil {
				continue
			}
			_, _ = conn.WriteToUDP(p.Payload, dst)
		}
	}()

	// Main loop: read UDP packets and write gob-encoded frames to chisel.
	go func() {
		defer wg.Done()
		enc := gob.NewEncoder(clientPipe)
		buff := make([]byte, 9012)
		for {
			n, src, err := conn.ReadFromUDP(buff)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				slog.Debug("udp raw read error", "port", port, "error", err)
				return
			}
			p := tunnel.UDPPacket{Src: src.String(), Payload: buff[:n]}
			if err := enc.Encode(p); err != nil {
				slog.Debug("udp raw encode error", "port", port, "error", err)
				return
			}
		}
	}()

	wg.Wait()
}

func (f *Frontend) closeUDPListener(port int) {
	f.mu.Lock()
	c := f.udpListeners[port]
	delete(f.udpListeners, port)
	f.mu.Unlock()
	if c != nil {
		_ = c.Close()
		slog.Debug("udp raw listener closed", "port", port)
	}
}
