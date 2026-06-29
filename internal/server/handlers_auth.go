package server

import (
	"encoding/json"
	"net/http"

	"locrest-server/internal/auth"
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
