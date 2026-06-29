package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"locrest-server/internal/auth"
	tunnel "locrest-server/internal/chiselvendor/tunnel"
	"locrest-server/internal/config"
	"locrest-server/internal/script"
)

const maxSessions = 10000

func parseAllowedIPs(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "/") {
			_, _, err := net.ParseCIDR(p)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q", p)
			}
		} else {
			ip := net.ParseIP(p)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP %q", p)
			}
			p = p + "/32"
		}
		out = append(out, p)
	}
	return out, nil
}

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

func (f *Frontend) handleScript(w http.ResponseWriter, r *http.Request, localPort, remotePort int, targetHost, mode, httpAuth string) {
	role := "auth"
	if !isAuthenticated(r, f.db) {
		role = "public"
	}
	if !f.rateLimiter.allow(clientIP(r, f.cfg.BehindProxy)) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if f.store.Len() >= maxSessions {
		http.Error(w, "Server busy", http.StatusServiceUnavailable)
		return
	}

	var perms config.Permissions
	if role == "public" {
		perms = f.cfg.Permissions.Public
	} else {
		perms = f.cfg.Permissions.Auth
	}

	if httpAuth != "" && !perms.HTTPAuth {
		http.Error(w, "Permission DENIED", http.StatusForbidden)
		return
	}

	requestedSubdomain := r.URL.Query().Get("subdomain")
	if requestedSubdomain != "" && !perms.SetSubdomain {
		http.Error(w, "Permission DENIED", http.StatusForbidden)
		return
	}

	allowedIPsRaw := r.URL.Query().Get("allowed_ips")
	var allowedIPs []string
	if allowedIPsRaw != "" {
		if !perms.SetAllowedIPs {
			http.Error(w, "Permission DENIED", http.StatusForbidden)
			return
		}
		var err error
		allowedIPs, err = parseAllowedIPs(allowedIPsRaw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	rolePublic := role == "public"
	ttl, err := effectiveTTL(r, f.cfg, rolePublic)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	serverPort := remotePort
	if serverPort <= 0 {
		serverPort = f.NextServerPort()
	} else if f.isPortInUse(serverPort) {
		http.Error(w, "Port already in use", http.StatusConflict)
		return
	}

	sess, err := f.store.Create(localPort, serverPort, targetHost, ttl, 16, mode, role, httpAuth, requestedSubdomain, allowedIPs)
	if err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		if msg == "subdomain already in use" {
			status = http.StatusConflict
		} else if strings.Contains(msg, "subdomain must") || strings.Contains(msg, "subdomain must not") {
			status = http.StatusBadRequest
		}
		http.Error(w, msg, status)
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
	binaryURL := f.cfg.BinaryURL
	if f.cfg.Dev {
		binaryURL = ""
	}
	scr, err := script.Generate(serverURL, binaryURL, sess, r.UserAgent(), flags, ttl)
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

	var perms config.Permissions
	if sess.Role == "public" {
		perms = f.cfg.Permissions.Public
	} else {
		perms = f.cfg.Permissions.Auth
	}
	if sess.Mode == "tcp" && !perms.RawTCP {
		f.store.Delete(sess.SetupToken)
		http.Error(w, "Permission DENIED", http.StatusForbidden)
		return
	}
	if sess.Mode == "http" && !perms.CreateTunnel {
		f.store.Delete(sess.SetupToken)
		http.Error(w, "Permission DENIED", http.StatusForbidden)
		return
	}

	if err := f.chisel.AddUser(sess.Subdomain, sess.Token); err != nil {
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	if sess.Mode == "http" {
		f.RegisterRoute(sess.Subdomain, sess.ServerPort)
	}
	sess.Activate()
	if err := f.store.Activate(sess.SetupToken); err != nil {
		http.Error(w, "Failed to activate session", http.StatusInternalServerError)
		return
	}
	if sess.Mode == "tcp" {
		go func(port int, setupToken string) {
			for i := 0; i < 50; i++ {
				if tunnel.GetProxyPipe(port) != nil {
					f.startTCPListener(port, setupToken)
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			slog.Warn("tcp raw: chisel pipe never created", "port", port)
		}(sess.ServerPort, sess.SetupToken)
	}

	resp := map[string]interface{}{
		"token":       sess.Token,
		"server_port": sess.ServerPort,
		"remote":      fmt.Sprintf("R:%d:%s:%d", sess.ServerPort, sess.TargetHost, sess.LocalPort),
		"fingerprint": f.chisel.Fingerprint(),
		"mode":        sess.Mode,
		"http_auth":   sess.HTTPAuth,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
