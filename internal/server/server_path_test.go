package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandlerTrailingSlash(t *testing.T) {
	f := newTestFrontend(t, nil)
	cacheDir := f.cfg.Load().EffectiveBinaryCacheDir()
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatalf("mkdir cache: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "lrc-linux-amd64"), []byte("dummy"), 0644); err != nil {
		t.Fatalf("write dummy binary: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/8080/", nil)
	req.Host = "localtest.me"
	rec := httptest.NewRecorder()
	f.handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "#!/bin/sh") {
		t.Fatal("handler with trailing slash should return install script")
	}
	if !strings.Contains(body, "8080") {
		t.Fatal("script should contain the requested port")
	}
}
