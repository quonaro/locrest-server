package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"locrest-server/internal/auth"
	"locrest-server/internal/config"
	"locrest-server/internal/script"
)

const maxSessions = 10000

func clientIP(r *http.Request, behindProxy bool) string {
	if behindProxy {
		ip := r.Header.Get("X-Forwarded-For")
		if ip != "" {
			parts := strings.Split(ip, ",")
			if len(parts) > 0 {
				return strings.TrimSpace(parts[len(parts)-1])
			}
		}
		ip = r.Header.Get("X-Real-Ip")
		if ip != "" {
			return strings.TrimSpace(ip)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (f *Frontend) handleScript(w http.ResponseWriter, r *http.Request, localPort, remotePort int, targetHost string) {
	rolePublic := !isAuthenticated(r, f.db)
	var perms config.Permissions
	if rolePublic {
		perms = f.cfg.Permissions.Public
	} else {
		perms = f.cfg.Permissions.Auth
	}
	if !perms.CreateTunnel {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if !f.rateLimiter.allow(clientIP(r, f.cfg.BehindProxy)) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if f.store.Len() >= maxSessions {
		http.Error(w, "Server busy", http.StatusServiceUnavailable)
		return
	}

	ttl, err := effectiveTTL(r, f.cfg, rolePublic)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	serverPort := f.NextServerPort()

	sess, err := f.store.Create(localPort, serverPort, targetHost, ttl, 16)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	hostOnly := r.Host
	if colonIdx := strings.LastIndex(hostOnly, ":"); colonIdx != -1 {
		hostOnly = hostOnly[:colonIdx]
	}
	serverURL := fmt.Sprintf("https://%s", hostOnly)
	if f.cfg.HTTPSPort != 443 {
		serverURL = fmt.Sprintf("https://%s:%d", hostOnly, f.cfg.HTTPSPort)
	}
	if f.cfg.TLS.Cert == "" && !f.cfg.TLS.AutoTLS {
		serverURL = fmt.Sprintf("http://%s", hostOnly)
		if f.cfg.HTTPPort != 80 {
			serverURL = fmt.Sprintf("http://%s:%d", hostOnly, f.cfg.HTTPPort)
		}
	}

	flags := map[string]string{
		"debug": r.URL.Query().Get("debug"),
	}
	scr, err := script.Generate(serverURL, sess, r.UserAgent(), flags, ttl)
	if err != nil {
		http.Error(w, "Script generation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Header().Set("Content-Disposition", "attachment; filename=install.sh")
	w.Write([]byte(scr))
}

func (f *Frontend) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pubHex := r.URL.Query().Get("pubkey")
	if pubHex == "" {
		http.Error(w, "Missing pubkey", http.StatusBadRequest)
		return
	}
	sess, ok := f.store.GetByPubkey(pubHex)
	if !ok {
		http.Error(w, "Unknown pubkey", http.StatusUnauthorized)
		return
	}

	nonce, err := auth.Nonce()
	if err != nil {
		http.Error(w, "Nonce generation failed", http.StatusInternalServerError)
		return
	}
	sess.SetNonce(nonce)
	if err := f.store.UpdateNonce(sess.SetupToken, sess.Nonce, sess.NonceAt); err != nil {
		http.Error(w, "Failed to update nonce", http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"nonce":       nonce,
		"subdomain":   sess.Subdomain,
		"server_port": sess.ServerPort,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (f *Frontend) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		PubKey    string `json:"pubkey"`
		Signature string `json:"signature"`
		Nonce     string `json:"nonce"`
		Subdomain string `json:"subdomain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	sess, ok := f.store.GetByPubkey(req.PubKey)
	if !ok {
		http.Error(w, "Unknown pubkey", http.StatusUnauthorized)
		return
	}
	if sess.IsActivated() {
		http.Error(w, "Session already activated", http.StatusConflict)
		return
	}

	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "Bad signature encoding", http.StatusBadRequest)
		return
	}

	if !sess.ConsumeNonce(req.Nonce, 5*time.Minute) {
		http.Error(w, "Invalid or expired nonce", http.StatusUnauthorized)
		return
	}

	pubBytes, err := hex.DecodeString(req.PubKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		http.Error(w, "Bad pubkey", http.StatusBadRequest)
		return
	}

	if !auth.VerifySignature(ed25519.PublicKey(pubBytes), []byte(req.Nonce), sig) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	if err := f.chisel.AddUser(sess.Subdomain, sess.Token); err != nil {
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	f.RegisterRoute(sess.Subdomain, sess.ServerPort)
	sess.Activate()
	if err := f.store.Activate(sess.SetupToken); err != nil {
		http.Error(w, "Failed to activate session", http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"token":       sess.Token,
		"server_port": sess.ServerPort,
		"remote":      fmt.Sprintf("R:%d:%s:%d", sess.ServerPort, sess.TargetHost, sess.LocalPort),
		"fingerprint": f.chisel.Fingerprint(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
