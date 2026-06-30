package auth

import (
	"crypto/rand"

	"github.com/tyler-smith/go-bip39"
)

// GenerateSeedPhrase returns a 12-word BIP39 mnemonic phrase.
func GenerateSeedPhrase() (string, error) {
	// 128 bits of entropy produces a 12-word mnemonic.
	entropy := make([]byte, 16)
	if _, err := rand.Read(entropy); err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}
