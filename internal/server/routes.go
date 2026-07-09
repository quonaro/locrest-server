package server

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
)

// NextServerPort returns a unique internal port number for reverse-tunnel allocation.
func (f *Frontend) NextServerPort() int {
	for {
		port := int(f.nextPort.Add(1)%40000 + 20000)
		if f.isPortInUse(port) {
			continue
		}
		addr := fmt.Sprintf(":%d", port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		_ = ln.Close()
		return port
	}
}

// RegisterRoute maps a subdomain to a local backend port.
func (f *Frontend) RegisterRoute(subdomain string, backendPort int) {
	f.mu.Lock()
	f.routes[subdomain] = backendPort
	f.mu.Unlock()
	slog.Debug("route registered", "subdomain", subdomain, "backend_port", backendPort)
}

// UnregisterRoute removes a subdomain mapping.
func (f *Frontend) UnregisterRoute(subdomain string) {
	f.mu.Lock()
	delete(f.routes, subdomain)
	f.mu.Unlock()
	slog.Debug("route unregistered", "subdomain", subdomain)
}

// isPortInUse reports whether any active route or listener already uses the given port.
func (f *Frontend) isPortInUse(port int) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, p := range f.routes {
		if p == port {
			return true
		}
	}
	_, ok := f.tcpListeners[port]
	if ok {
		return true
	}
	_, ok = f.udpListeners[port]
	return ok
}

func (f *Frontend) isReservedSubdomain(subdomain string) bool {
	cfg := f.cfg.Load()
	for _, r := range cfg.Tunnel.ReservedSubdomains {
		if r == subdomain {
			return true
		}
	}
	return false
}

func (f *Frontend) isAllowedTunnelHost(host string) bool {
	cfg := f.cfg.Load()
	if len(cfg.Tunnel.BlockedTunnelHosts) > 0 {
		for _, b := range cfg.Tunnel.BlockedTunnelHosts {
			if b == host {
				return false
			}
		}
	}
	if len(cfg.Tunnel.AllowedTunnelHosts) > 0 {
		for _, a := range cfg.Tunnel.AllowedTunnelHosts {
			if a == host {
				return true
			}
		}
		return false
	}
	return true
}

// resolveRoute looks up the backend port for a given host (or subdomain).
func (f *Frontend) resolveRoute(host string) (port int, subdomain string, ok bool) {
	if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	port, ok = f.routes[host]
	if ok {
		return port, host, true
	}
	parts := strings.SplitN(host, ".", 2)
	if len(parts) == 2 {
		port, ok = f.routes[parts[0]]
		if ok {
			return port, parts[0], true
		}
	}
	return 0, "", false
}
