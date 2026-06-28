package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"locrest-server/internal/auth"
	"locrest-server/internal/script"
)

func (f *Frontend) handleScript(w http.ResponseWriter, r *http.Request, localPort, remotePort int, targetHost string) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		http.Error(w, "No free port", http.StatusServiceUnavailable)
		return
	}
	serverPort := l.Addr().(*net.TCPAddr).Port
	l.Close()

	subdomain := auth.RandString(16)

	sess, err := f.store.Create(subdomain, localPort, serverPort, targetHost)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	hostOnly := r.Host
	if colonIdx := strings.LastIndex(hostOnly, ":"); colonIdx != -1 {
		hostOnly = hostOnly[:colonIdx]
	}
	serverURL := fmt.Sprintf("https://%s", hostOnly)
	if f.cfg.Port != 443 {
		serverURL = fmt.Sprintf("https://%s:%d", hostOnly, f.cfg.Port)
	}
	if f.cfg.TLS.Cert == "" && !f.cfg.TLS.AutoTLS {
		serverURL = fmt.Sprintf("http://%s", hostOnly)
		if f.cfg.Port != 80 {
			serverURL = fmt.Sprintf("http://%s:%d", hostOnly, f.cfg.Port)
		}
	}

	flags := map[string]string{
		"debug": r.URL.Query().Get("debug"),
	}
	scr, err := script.Generate(serverURL, sess, r.UserAgent(), flags)
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
	sess, ok := f.store.Get(pubHex)
	if !ok {
		http.Error(w, "Unknown pubkey", http.StatusUnauthorized)
		return
	}

	nonce, err := auth.Nonce()
	if err != nil {
		http.Error(w, "Nonce generation failed", http.StatusInternalServerError)
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

	sess, ok := f.store.Get(req.PubKey)
	if !ok {
		http.Error(w, "Unknown pubkey", http.StatusUnauthorized)
		return
	}

	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "Bad signature encoding", http.StatusBadRequest)
		return
	}

	if !auth.VerifySignature(sess.PublicKey, []byte(req.Nonce), sig) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	user, pass, _ := strings.Cut(sess.SSHToken(), ":")
	if err := f.chisel.AddUser(user, pass); err != nil {
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	f.RegisterRoute(sess.Subdomain, sess.ServerPort)

	resp := map[string]interface{}{
		"token":       sess.Token,
		"server_port": sess.ServerPort,
		"remote":      fmt.Sprintf("R:%d:%s:%d", sess.ServerPort, sess.TargetHost, sess.LocalPort),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
