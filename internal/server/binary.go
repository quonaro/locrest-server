package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

func (f *Frontend) startBinaryUpdater(ctx context.Context) {
	cfg := f.cfg.Load()
	if cfg.Binary.RefreshInterval <= 0 {
		return
	}

	// Immediate first update.
	if err := f.binCache.Update(ctx); err != nil {
		slog.Error("binary cache initial update failed", "error", err)
	}

	ticker := time.NewTicker(cfg.Binary.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := f.binCache.Update(ctx); err != nil {
				slog.Error("binary cache update failed", "error", err)
			}
		}
	}
}

func (f *Frontend) handleAdminBinaries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	files, err := f.binCache.List()
	if err != nil {
		slog.Error("list binaries failed", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(files)
}

func (f *Frontend) handleAdminBinariesUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := f.binCache.Update(r.Context()); err != nil {
		slog.Error("binary cache manual update failed", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
