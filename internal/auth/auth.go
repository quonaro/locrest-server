package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Session holds the per-script ephemeral keypair and allocated port.
type Session struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	Subdomain  string
	LocalPort  int
	ServerPort int
	TargetHost string
	Token      string
	CreatedAt  time.Time
}

// Store is an in-memory, TTL-aware session map.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session // keyed by public-key hex
	cleaner  *time.Ticker
}

// NewStore creates a session store and starts the background cleanup.
func NewStore(ttl time.Duration) *Store {
	s := &Store{
		sessions: make(map[string]*Session),
		cleaner:  time.NewTicker(30 * time.Second),
	}
	go s.cleanupLoop(ttl)
	return s
}

// Create generates a fresh ED25519 keypair and session entry.
func (s *Store) Create(subdomain string, localPort, serverPort int, targetHost string) (*Session, error) {
	if targetHost == "" {
		targetHost = "localhost"
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	sess := &Session{
		PrivateKey: priv,
		PublicKey:  priv.Public().(ed25519.PublicKey),
		Subdomain:  subdomain,
		LocalPort:  localPort,
		ServerPort: serverPort,
		TargetHost: targetHost,
		Token:      randHex(32),
		CreatedAt:  time.Now(),
	}
	s.mu.Lock()
	s.sessions[sess.PublicKeyHex()] = sess
	s.mu.Unlock()
	return sess, nil
}

// Get retrieves a session by public-key hex.
func (s *Store) Get(pubHex string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[pubHex]
	return sess, ok
}

// Delete removes a session.
func (s *Store) Delete(pubHex string) {
	s.mu.Lock()
	delete(s.sessions, pubHex)
	s.mu.Unlock()
}

// PublicKeyHex returns the hex-encoded public key.
func (sess *Session) PublicKeyHex() string {
	return hex.EncodeToString(sess.PublicKey)
}

// PrivateKeyHex returns the hex-encoded private key.
func (sess *Session) PrivateKeyHex() string {
	return hex.EncodeToString(sess.PrivateKey)
}

// SSHToken returns the user:pass string suitable for Chisel auth.
func (sess *Session) SSHToken() string {
	return fmt.Sprintf("%s:%s", sess.Subdomain, sess.Token)
}

func (s *Store) cleanupLoop(ttl time.Duration) {
	for range s.cleaner.C {
		cutoff := time.Now().Add(-ttl)
		s.mu.Lock()
		for k, v := range s.sessions {
			if v.CreatedAt.Before(cutoff) {
				delete(s.sessions, k)
			}
		}
		s.mu.Unlock()
	}
}

// Nonce generates a random base64 string for challenge-response.
func Nonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// VerifySignature checks whether sig is a valid Ed25519 signature for msg.
func VerifySignature(pub ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}

// SSHFingerprint returns the SHA256 fingerprint used by Chisel for host key verification.
func SSHFingerprint(pub ed25519.PublicKey) string {
	// Chisel uses ssh.PublicKey fingerprinting internally, but for our
	// ephemeral keys we just return the base64-encoded raw key.
	return base64.StdEncoding.EncodeToString(pub)
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// RandString returns a random alphanumeric string of length n.
func RandString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}
