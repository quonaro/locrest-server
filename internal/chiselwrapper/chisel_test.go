package chiselwrapper

import (
	"path/filepath"
	"testing"
)

func TestNewGeneratesPersistentHostKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "host_key")

	ch1, err := New(keyFile)
	if err != nil {
		t.Fatalf("first New() error: %v", err)
	}
	fp1 := ch1.Fingerprint()

	ch2, err := New(keyFile)
	if err != nil {
		t.Fatalf("second New() error: %v", err)
	}
	fp2 := ch2.Fingerprint()

	if fp1 == "" {
		t.Fatal("first fingerprint is empty")
	}
	if fp1 != fp2 {
		t.Fatalf("fingerprints differ across restarts: %q vs %q", fp1, fp2)
	}
}
