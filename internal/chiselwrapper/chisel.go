package chiselwrapper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	chserver "locrest-server/internal/chiselvendor/server"
)

// Chisel wraps the embedded chisel server.
type Chisel struct {
	server *chserver.Server
	config *chserver.Config
}

// generateKey creates a new ECDSA P-256 host key and writes it in PEM format.
func generateKey(path string) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	b, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	return os.WriteFile(path, pemBytes, 0600)
}

// New creates a new embedded chisel server configured for reverse tunnelling.
// If keyFile is non-empty, a persistent host key is loaded from (or created at)
// that path, keeping the SSH fingerprint stable across restarts.
func New(keyFile string) (*Chisel, error) {
	if keyFile != "" {
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			if err := generateKey(keyFile); err != nil {
				return nil, fmt.Errorf("generate chisel host key: %w", err)
			}
		} else if err != nil {
			return nil, fmt.Errorf("stat chisel host key: %w", err)
		}
	}
	c := &chserver.Config{
		Reverse: true,
		Socks5:  false,
		TLS:     chserver.TLSConfig{}, // internal; TLS is handled by the frontend
		KeyFile: keyFile,
	}
	s, err := chserver.NewServer(c)
	if err != nil {
		return nil, fmt.Errorf("new chisel server: %w", err)
	}
	ch := &Chisel{
		server: s,
		config: c,
	}
	slog.Info("chisel server initialized", "fingerprint", ch.Fingerprint())
	return ch, nil
}

// Handler returns the http.Handler for the chisel websocket endpoint.
func (c *Chisel) Handler() http.Handler {
	return c.server.Handler()
}

// AddUser registers a temporary user:pass for the upcoming client connection.
func (c *Chisel) AddUser(user, pass string) error {
	// Allow all addresses for MVP.
	return c.server.AddUser(user, pass, ".*")
}

// DeleteUser removes a previously registered user.
func (c *Chisel) DeleteUser(user string) {
	c.server.DeleteUser(user)
}

// Fingerprint returns the server's SSH host key fingerprint.
func (c *Chisel) Fingerprint() string {
	return c.server.GetFingerprint()
}
