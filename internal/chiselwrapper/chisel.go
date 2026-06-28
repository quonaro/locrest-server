package chiselwrapper

import (
	"fmt"
	"net/http"

	chserver "locrest-server/internal/chiselvendor/server"
)

// Chisel wraps the embedded chisel server.
type Chisel struct {
	server *chserver.Server
	config *chserver.Config
}

// New creates a new embedded chisel server configured for reverse tunnelling.
func New() (*Chisel, error) {
	c := &chserver.Config{
		Reverse: true,
		Socks5:  false,
		TLS:     chserver.TLSConfig{}, // internal; TLS is handled by the frontend
	}
	s, err := chserver.NewServer(c)
	if err != nil {
		return nil, fmt.Errorf("new chisel server: %w", err)
	}
	return &Chisel{
		server: s,
		config: c,
	}, nil
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
