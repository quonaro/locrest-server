package auth

import (
	"strings"
	"testing"

	"github.com/tyler-smith/go-bip39"
)

func TestGenerateSeedPhrase(t *testing.T) {
	phrase, err := GenerateSeedPhrase()
	if err != nil {
		t.Fatalf("GenerateSeedPhrase: %v", err)
	}
	words := strings.Fields(phrase)
	if len(words) != 12 {
		t.Fatalf("expected 12 words, got %d: %q", len(words), phrase)
	}
	if !bip39.IsMnemonicValid(phrase) {
		t.Fatalf("invalid mnemonic: %q", phrase)
	}
}
