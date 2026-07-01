package binary

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCacheList(t *testing.T) {
	dir := t.TempDir()
	cache := NewCache(dir, "https://example.com/bin")

	// Empty cache.
	files, err := cache.List()
	if err != nil {
		t.Fatalf("List empty: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected 0 files, got %d", len(files))
	}

	// Create a fake binary and checksum.
	if err := os.WriteFile(filepath.Join(dir, "lrc-linux-amd64"), []byte("fake-binary"), 0644); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lrc-linux-amd64.sha256"), []byte("abc123"), 0644); err != nil {
		t.Fatalf("write checksum: %v", err)
	}

	files, err = cache.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].Name != "lrc-linux-amd64" {
		t.Fatalf("Name = %q, want lrc-linux-amd64", files[0].Name)
	}
	if files[0].Size != int64(len("fake-binary")) {
		t.Fatalf("Size = %d, want %d", files[0].Size, len("fake-binary"))
	}
}

func TestVerifyFile(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "test.bin")
	if err := os.WriteFile(binPath, []byte("hello"), 0644); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	// Correct checksum for "hello".
	shaPath := filepath.Join(dir, "test.bin.sha256")
	if err := os.WriteFile(shaPath, []byte("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"), 0644); err != nil {
		t.Fatalf("write checksum: %v", err)
	}

	if err := verifyFile(binPath, shaPath); err != nil {
		t.Fatalf("verifyFile: %v", err)
	}

	// Incorrect checksum.
	if err := os.WriteFile(shaPath, []byte("0000000000000000000000000000000000000000000000000000000000000000"), 0644); err != nil {
		t.Fatalf("write bad checksum: %v", err)
	}
	if err := verifyFile(binPath, shaPath); err == nil {
		t.Fatal("expected error for bad checksum")
	}
}
