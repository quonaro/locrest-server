package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"locrest-server/internal/auth"
	"locrest-server/internal/db"
)

type adminUserResponse struct {
	Username       string    `json:"username"`
	APIToken       string    `json:"api_token,omitempty"`
	SeedPhrase     string    `json:"seed_phrase,omitempty"`
	SeedPhraseHash string    `json:"seed_phrase_hash,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	Expire         time.Time `json:"expire,omitempty"`
}

func (f *Frontend) adminUserPath(r *http.Request) string {
	return strings.TrimPrefix(r.URL.Path, "/users/")
}

func (f *Frontend) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		f.handleAdminCreateUser(w, r)
	case http.MethodGet:
		f.handleAdminListUsers(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (f *Frontend) handleAdminUser(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		f.handleAdminShowUser(w, r)
	case http.MethodDelete:
		f.handleAdminDeleteUser(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (f *Frontend) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "Missing username", http.StatusBadRequest)
		return
	}

	if _, err := f.db.GetUser(req.Username); err == nil {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	apiToken, err := auth.RandString(32)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}
	seedPhrase, err := auth.GenerateSeedPhrase()
	if err != nil {
		http.Error(w, "Seed phrase generation failed", http.StatusInternalServerError)
		return
	}

	user := &db.User{
		Username:       req.Username,
		APIToken:       apiToken,
		SeedPhraseHash: db.HashSeedPhrase(seedPhrase),
		CreatedAt:      time.Now().UTC(),
	}
	if err := f.db.CreateUser(user); err != nil {
		http.Error(w, "Create user failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(adminUserResponse{
		Username:   req.Username,
		APIToken:   apiToken,
		SeedPhrase: seedPhrase,
		CreatedAt:  user.CreatedAt,
	})
}

func (f *Frontend) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	username := f.adminUserPath(r)
	if username == "" {
		http.Error(w, "Missing username", http.StatusBadRequest)
		return
	}
	if err := f.db.DeleteUser(username); err != nil {
		http.Error(w, "Delete failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *Frontend) handleAdminRegenerate(w http.ResponseWriter, r *http.Request) {
	path := f.adminUserPath(r)
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[1] != "regenerate" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	username := parts[0]

	if _, err := f.db.GetUser(username); err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	newToken, err := auth.RandString(32)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}
	if err := f.db.UpdateUserToken(username, newToken); err != nil {
		http.Error(w, "Update failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"api_token": newToken})
}

func (f *Frontend) handleAdminShowUser(w http.ResponseWriter, r *http.Request) {
	username := f.adminUserPath(r)
	if username == "" {
		http.Error(w, "Missing username", http.StatusBadRequest)
		return
	}
	user, err := f.db.GetUser(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(adminUserResponse{
		Username:       user.Username,
		APIToken:       user.APIToken,
		SeedPhraseHash: user.SeedPhraseHash,
		CreatedAt:      user.CreatedAt,
		Expire:         user.Expire,
	})
}

func (f *Frontend) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := f.db.ListUsers()
	if err != nil {
		http.Error(w, "List failed", http.StatusInternalServerError)
		return
	}
	resp := make([]adminUserResponse, len(users))
	for i, u := range users {
		resp[i] = adminUserResponse{
			Username:       u.Username,
			APIToken:       u.APIToken,
			SeedPhraseHash: u.SeedPhraseHash,
			CreatedAt:      u.CreatedAt,
			Expire:         u.Expire,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *Frontend) handleAdminReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := f.reloadConfig(); err != nil {
		slog.Error("reload failed", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// adminMux returns the mux for the Unix socket admin API.
func (f *Frontend) adminMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/users/")
		if strings.Contains(path, "/") {
			// /users/{username}/regenerate
			f.handleAdminRegenerate(w, r)
			return
		}
		f.handleAdminUser(w, r)
	})
	mux.HandleFunc("/users", f.handleAdminUsers)
	mux.HandleFunc("/reload", f.handleAdminReload)
	mux.HandleFunc("/binaries/update", f.handleAdminBinariesUpdate)
	mux.HandleFunc("/binaries", f.handleAdminBinaries)
	return mux
}
