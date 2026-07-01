package server

import (
	"encoding/gob"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	tunnel "locrest-server/internal/chiselvendor/tunnel"
)

func (f *Frontend) startUDPListener(port int) {
	slog.Info("startUDPListener called", "port", port)
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic in startUDPListener", "port", port, "recover", r)
		}
	}()

	for {
		// If cleanup removed the listener, exit.
		f.mu.RLock()
		_, managed := f.udpListeners[port]
		f.mu.RUnlock()
		if !managed {
			return
		}

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

		pipeCh := tunnel.GetProxyPipe(port, "udp")
		if pipeCh == nil {
			_ = conn.Close()
			f.mu.Lock()
			delete(f.udpListeners, port)
			f.mu.Unlock()
			slog.Warn("udp raw: no proxy pipe, retrying", "port", port)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Obtain the single pipe connection for this UDP listener.
		clientPipe, serverPipe := net.Pipe()
		select {
		case pipeCh <- serverPipe:
		default:
			_ = clientPipe.Close()
			_ = conn.Close()
			f.mu.Lock()
			delete(f.udpListeners, port)
			f.mu.Unlock()
			time.Sleep(100 * time.Millisecond)
			continue
		}

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
						slog.Info("udp raw decode error", "port", port, "error", err)
					}
					return
				}
				dst, err := net.ResolveUDPAddr("udp", p.Src)
				if err != nil {
					slog.Info("udp raw resolve dst failed", "port", port, "src", p.Src, "error", err)
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
					slog.Info("udp raw read error", "port", port, "error", err)
					return
				}
				slog.Debug("udp raw received packet", "port", port, "src", src, "n", n)
				p := tunnel.UDPPacket{Src: src.String(), Payload: buff[:n]}
				if err := enc.Encode(p); err != nil {
					slog.Info("udp raw encode error", "port", port, "error", err)
					return
				}
				slog.Debug("udp raw encoded packet", "port", port, "src", p.Src, "len", len(p.Payload))
			}
		}()

		wg.Wait()
		_ = clientPipe.Close()
		_ = conn.Close()
		f.mu.Lock()
		delete(f.udpListeners, port)
		f.mu.Unlock()

		// Loop back to wait for a new chisel pipe after disconnect.
		time.Sleep(100 * time.Millisecond)
	}
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
