package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"locrest-server/internal/auth"
	tunnel "locrest-server/internal/chiselvendor/tunnel"
	"locrest-server/internal/config"
	"locrest-server/internal/db"
)

func (f *Frontend) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pubHex := r.URL.Query().Get("pubkey")
	if pubHex == "" {
		http.Error(w, "Missing pubkey", http.StatusBadRequest)
		return
	}
	_, ok := f.store.GetByPubkey(pubHex)
	if !ok {
		http.Error(w, "Unknown pubkey", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"alive":true}`))
}

func (f *Frontend) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		SetupToken string `json:"setup_token"`
		PubKey     string `json:"pubkey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if req.SetupToken == "" || req.PubKey == "" {
		http.Error(w, "Missing setup_token or pubkey", http.StatusBadRequest)
		return
	}

	if !f.store.RegisterPubkey(req.SetupToken, req.PubKey) {
		http.Error(w, "Invalid or already used setup token", http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func (f *Frontend) handleRegenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !f.regenerateRateLimiter.allow(clientIP(r, f.cfg.BehindProxy)) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		SeedPhrase string `json:"seed_phrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.SeedPhrase == "" {
		http.Error(w, "Missing seed_phrase", http.StatusBadRequest)
		return
	}

	hash := db.HashSeedPhrase(req.SeedPhrase)
	user, err := f.db.GetUserBySeedHash(hash)
	if err != nil {
		http.Error(w, "Invalid seed phrase", http.StatusUnauthorized)
		return
	}

	newToken, err := auth.RandString(32)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}
	if err := f.db.UpdateUserToken(user.Username, newToken); err != nil {
		http.Error(w, "Token update failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": newToken})
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
	if sess.IsActivated() {
		http.Error(w, "Session already activated", http.StatusConflict)
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
	if sess.Infinity && !perms.Infinity {
		f.store.Delete(sess.SetupToken)
		http.Error(w, "infinity tunnel not permitted for your role", http.StatusForbidden)
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
		go func(port int) {
			for i := 0; i < 50; i++ {
				if tunnel.GetProxyPipe(port) != nil {
					f.startTCPListener(port)
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			slog.Warn("tcp raw: chisel pipe never created", "port", port)
		}(sess.ServerPort)
	}

	resp := map[string]interface{}{
		"token":       sess.Token,
		"server_port": sess.ServerPort,
		"remote":      fmt.Sprintf("R:%d:%s:%d", sess.ServerPort, sess.TargetHost, sess.LocalPort),
		"fingerprint": f.chisel.Fingerprint(),
		"mode":        sess.Mode,
		"http_auth":   sess.HTTPAuth,
		"authorized":  sess.Role != "public",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
