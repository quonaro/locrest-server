package embedbin

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func setupTestFS(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "locrest-client-linux-amd64"), []byte("linux-amd64\n"), 0644); err != nil {
		t.Fatalf("write linux: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "locrest-client-darwin-arm64"), []byte("darwin-arm64\n"), 0644); err != nil {
		t.Fatalf("write darwin: %v", err)
	}
	staticFS = os.DirFS(dir)
	initChecksums()
}

func TestServeBinary(t *testing.T) {
	setupTestFS(t)
	req := httptest.NewRequest(http.MethodGet, "/bin/locrest-client-linux-amd64", nil)
	rec := httptest.NewRecorder()
	ServeBinary(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if body != "linux-amd64\n" {
		t.Fatalf("body = %q, want linux-amd64 newline", body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type = %q, want application/octet-stream", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "locrest-client-linux-amd64") {
		t.Fatalf("Content-Disposition = %q", cd)
	}
}

func TestServeBinaryNotFound(t *testing.T) {
	setupTestFS(t)
	req := httptest.NewRequest(http.MethodGet, "/bin/unknown", nil)
	rec := httptest.NewRecorder()
	ServeBinary(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestServeChecksum(t *testing.T) {
	setupTestFS(t)
	req := httptest.NewRequest(http.MethodGet, "/bin/locrest-client-linux-amd64.sha256", nil)
	rec := httptest.NewRecorder()
	ServeChecksum(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	h := sha256.New()
	io.WriteString(h, "linux-amd64\n")
	expected := hex.EncodeToString(h.Sum(nil))
	if rec.Body.String() != expected {
		t.Fatalf("checksum = %q, want %q", rec.Body.String(), expected)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain" {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
}

func TestServeChecksumNotFound(t *testing.T) {
	setupTestFS(t)
	req := httptest.NewRequest(http.MethodGet, "/bin/unknown.sha256", nil)
	rec := httptest.NewRecorder()
	ServeChecksum(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestNewHandlerRedirect(t *testing.T) {
	setupTestFS(t)
	handler := NewHandler(false, "https://cdn.example.com/bin")
	req := httptest.NewRequest(http.MethodGet, "/bin/locrest-client-linux-amd64", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", rec.Code)
	}
	loc := rec.Header().Get("Location")
	want := "https://cdn.example.com/bin/locrest-client-linux-amd64"
	if loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
}

func TestNewHandlerServeBinary(t *testing.T) {
	setupTestFS(t)
	handler := NewHandler(true, "")
	req := httptest.NewRequest(http.MethodGet, "/bin/locrest-client-darwin-arm64", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "darwin-arm64\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestNewHandlerServeChecksum(t *testing.T) {
	setupTestFS(t)
	handler := NewHandler(true, "")
	req := httptest.NewRequest(http.MethodGet, "/bin/locrest-client-darwin-arm64.sha256", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if len(body) != 64 {
		t.Fatalf("checksum length = %d, want 64", len(body))
	}
}

func TestNewHandlerBadName(t *testing.T) {
	setupTestFS(t)
	handler := NewHandler(true, "")
	req := httptest.NewRequest(http.MethodGet, "/bin/unknown", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestEmptyFS(t *testing.T) {
	staticFS = fstest.MapFS{}
	initChecksums()
	if len(checksums) != 0 {
		t.Fatalf("checksums should be empty, got %d", len(checksums))
	}
}
