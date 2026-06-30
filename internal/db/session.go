package db

import (
	"sync"
	"time"
)

// sessionData is the JSON-serializable representation of a session.
type sessionData struct {
	PubKey     []byte    `json:"pubkey"`
	Subdomain  string    `json:"subdomain"`
	LocalPort  int       `json:"local_port"`
	ServerPort int       `json:"server_port"`
	TargetHost string    `json:"target_host"`
	Token      string    `json:"token"`
	SetupToken string    `json:"setup_token"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Nonce      string    `json:"nonce"`
	NonceAt    time.Time `json:"nonce_at"`
	Activated  bool      `json:"activated"`
	Mode       string    `json:"mode"`
	Role       string    `json:"role"`
	HTTPAuth   string    `json:"http_auth"`
	AllowedIPs []string  `json:"allowed_ips"`
	Infinity   bool      `json:"infinity"`
	Username   string    `json:"username"`
}

// Session holds tunnel metadata and the registered client public key.
type Session struct {
	mu         sync.Mutex
	PubKey     []byte
	Subdomain  string
	LocalPort  int
	ServerPort int
	TargetHost string
	Token      string
	SetupToken string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Nonce      string
	NonceAt    time.Time
	Activated  bool
	Mode       string
	Role       string
	HTTPAuth   string
	AllowedIPs []string
	Infinity   bool
	Username   string
}

func (s *Session) toData() *sessionData {
	return &sessionData{
		PubKey: s.PubKey, Subdomain: s.Subdomain, LocalPort: s.LocalPort,
		ServerPort: s.ServerPort, TargetHost: s.TargetHost, Token: s.Token,
		SetupToken: s.SetupToken, CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt,
		Nonce: s.Nonce, NonceAt: s.NonceAt, Activated: s.Activated,
		Mode: s.Mode, Role: s.Role, HTTPAuth: s.HTTPAuth, AllowedIPs: s.AllowedIPs,
		Infinity: s.Infinity, Username: s.Username,
	}
}

func (s *Session) fromData(d *sessionData) {
	s.PubKey = d.PubKey
	s.Subdomain = d.Subdomain
	s.LocalPort = d.LocalPort
	s.ServerPort = d.ServerPort
	s.TargetHost = d.TargetHost
	s.Token = d.Token
	s.SetupToken = d.SetupToken
	s.CreatedAt = d.CreatedAt
	s.ExpiresAt = d.ExpiresAt
	s.Nonce = d.Nonce
	s.NonceAt = d.NonceAt
	s.Activated = d.Activated
	s.Mode = d.Mode
	s.Role = d.Role
	s.HTTPAuth = d.HTTPAuth
	s.AllowedIPs = d.AllowedIPs
	s.Infinity = d.Infinity
	s.Username = d.Username
}

// SetNonce stores a fresh nonce and its timestamp under lock.
func (sess *Session) SetNonce(nonce string) {
	sess.mu.Lock()
	sess.Nonce = nonce
	sess.NonceAt = time.Now()
	sess.mu.Unlock()
}

// ConsumeNonce validates the given nonce, ensures it has not expired,
// and clears it so it cannot be reused. It returns true if the nonce is valid.
func (sess *Session) ConsumeNonce(nonce string, ttl time.Duration) bool {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.Nonce == "" || sess.Nonce != nonce || time.Since(sess.NonceAt) > ttl {
		return false
	}
	sess.Nonce = ""
	return true
}

// Activate marks the session as activated (used). Safe for concurrent use.
func (sess *Session) Activate() {
	sess.mu.Lock()
	sess.Activated = true
	sess.mu.Unlock()
}

// IsActivated reports whether the session has already been activated.
func (sess *Session) IsActivated() bool {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.Activated
}
