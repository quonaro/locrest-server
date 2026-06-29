package server

import (
	"io"
	"net"
	"net/http"
	"sync"

	tunnel "locrest-server/internal/chiselvendor/tunnel"
)

// handleRawTCP hijacks the HTTP connection and pipes raw bytes into the chisel tunnel.
// This endpoint ALWAYS requires Bearer authentication.
func (f *Frontend) handleRawTCP(w http.ResponseWriter, r *http.Request, localPort, remotePort int, targetHost string) {
	if _, ok := requireBearer(w, r, f.db); !ok {
		return
	}
	if !f.cfg.Permissions.Auth.RawTCP {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if !f.rateLimiter.allow(clientIP(r, f.cfg.BehindProxy)) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if f.store.Len() >= 10000 {
		http.Error(w, "Server busy", http.StatusServiceUnavailable)
		return
	}

	ttl, err := effectiveTTL(r, f.cfg, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create a session for this raw TCP tunnel.
	sess, err := f.store.Create(localPort, remotePort, targetHost, ttl, 16)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	if err := f.chisel.AddUser(sess.Subdomain, sess.Token); err != nil {
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}
	f.RegisterRoute(sess.Subdomain, sess.ServerPort)

	// Hijack the HTTP connection.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Connect to the chisel tunnel backend via net.Pipe.
	pipeCh := tunnel.GetProxyPipe(sess.ServerPort)
	if pipeCh == nil {
		clientConn.Close()
		return
	}
	clientPipe, serverPipe := net.Pipe()
	select {
	case pipeCh <- serverPipe:
	default:
		clientPipe.Close()
		return
	}
	defer clientPipe.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(clientPipe, clientConn)
		clientPipe.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientConn, clientPipe)
		clientConn.Close()
	}()
	wg.Wait()

	// Cleanup after raw TCP session ends.
	f.UnregisterRoute(sess.Subdomain)
	f.chisel.DeleteUser(sess.Subdomain)
	f.store.Delete(sess.SetupToken)
}
