package binary

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewHandlerServeBinary(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lrc-darwin-arm64"), []byte("darwin-arm64\n"), 0644); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	handler := NewHandler(dir)
	req := httptest.NewRequest(http.MethodGet, "/bin/lrc-darwin-arm64", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "darwin-arm64\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type = %q, want application/octet-stream", ct)
	}
}

func TestNewHandlerServeChecksum(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lrc-darwin-arm64.sha256"), []byte("abc123\n"), 0644); err != nil {
		t.Fatalf("write checksum: %v", err)
	}

	handler := NewHandler(dir)
	req := httptest.NewRequest(http.MethodGet, "/bin/lrc-darwin-arm64.sha256", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "abc123") {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain" {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
}

func TestNewHandlerNotFound(t *testing.T) {
	dir := t.TempDir()
	handler := NewHandler(dir)

	req := httptest.NewRequest(http.MethodGet, "/bin/unknown", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestNewHandlerBadName(t *testing.T) {
	dir := t.TempDir()
	handler := NewHandler(dir)

	req := httptest.NewRequest(http.MethodGet, "/bin/malware", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestNewHandlerEmptyDir(t *testing.T) {
	handler := NewHandler("")
	req := httptest.NewRequest(http.MethodGet, "/bin/lrc-linux-amd64", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
