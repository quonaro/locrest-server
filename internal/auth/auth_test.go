package auth

import (
	"crypto/ed25519"
	"testing"
)

func TestNonce(t *testing.T) {
	n1, err := Nonce()
	if err != nil {
		t.Fatalf("Nonce: %v", err)
	}
	if n1 == "" {
		t.Fatal("nonce should not be empty")
	}
	n2, err := Nonce()
	if err != nil {
		t.Fatalf("Nonce: %v", err)
	}
	if n1 == n2 {
		t.Fatal("nonce values should be unique")
	}
	if len(n1) < 32 {
		t.Fatalf("nonce %q too short", n1)
	}
}

func TestVerifySignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	msg := []byte("challenge")
	sig := ed25519.Sign(priv, msg)

	if !VerifySignature(pub, msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if VerifySignature(pub, []byte("other"), sig) {
		t.Fatal("invalid message accepted")
	}
	if VerifySignature(pub, msg, []byte("bad")) {
		t.Fatal("invalid signature accepted")
	}
}

func TestRandString(t *testing.T) {
	for _, n := range []int{8, 16, 32} {
		s, err := RandString(n)
		if err != nil {
			t.Fatalf("RandString(%d): %v", n, err)
		}
		if len(s) != n {
			t.Fatalf("RandString(%d) length = %d", n, len(s))
		}
		for _, r := range s {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				t.Fatalf("RandString(%d) contains invalid rune %q", n, r)
			}
		}
	}
}

func TestRandStringDifferent(t *testing.T) {
	s1, err := RandString(16)
	if err != nil {
		t.Fatalf("RandString: %v", err)
	}
	s2, err := RandString(16)
	if err != nil {
		t.Fatalf("RandString: %v", err)
	}
	if s1 == s2 {
		t.Fatal("RandString should produce different values")
	}
}

func TestRandHex(t *testing.T) {
	s, err := randHex(32)
	if err != nil {
		t.Fatalf("randHex: %v", err)
	}
	if len(s) != 64 {
		t.Fatalf("randHex(32) length = %d, want 64", len(s))
	}
	// hex strings should not be valid base64 in general; we just check length
}
