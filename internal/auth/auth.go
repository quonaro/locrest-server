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
	mu             sync.Mutex
	PrivateKey     ed25519.PrivateKey
	PublicKey      ed25519.PublicKey
	Subdomain      string
	LocalPort      int
	ServerPort     int
	TargetHost     string
	Token          string
	RetrievalToken string
	CreatedAt      time.Time
	Nonce          string
	NonceAt        time.Time
	Activated      bool
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

// Store is an in-memory session map.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session // keyed by public-key hex
}

// NewStore creates a session store.
func NewStore() *Store {
	return &Store{
		sessions: make(map[string]*Session),
	}
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
	token, err := randHex(32)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	retrieval, err := randHex(32)
	if err != nil {
		return nil, fmt.Errorf("generate retrieval token: %w", err)
	}
	sess := &Session{
		PrivateKey:     priv,
		PublicKey:      priv.Public().(ed25519.PublicKey),
		Subdomain:      subdomain,
		LocalPort:      localPort,
		ServerPort:     serverPort,
		TargetHost:     targetHost,
		Token:          token,
		RetrievalToken: retrieval,
		CreatedAt:      time.Now(),
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

// HasSubdomain reports whether any existing session uses the given subdomain.
func (s *Store) HasSubdomain(subdomain string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sess := range s.sessions {
		if sess.Subdomain == subdomain {
			return true
		}
	}
	return false
}

// Len returns the number of active sessions.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// FindByRetrievalToken returns the session with the given retrieval token, or nil.
func (s *Store) FindByRetrievalToken(token string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sess := range s.sessions {
		if sess.RetrievalToken == token {
			return sess
		}
	}
	return nil
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

// Expired returns all sessions created before the given cutoff time.
func (s *Store) Expired(cutoff time.Time) []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Session
	for _, sess := range s.sessions {
		if sess.CreatedAt.Before(cutoff) {
			out = append(out, sess)
		}
	}
	return out
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

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RandString returns a uniformly random alphanumeric string of length n.
func RandString(n int) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	reject := 256 - 256%len(letters)
	for i := range b {
		for {
			var buf [1]byte
			if _, err := rand.Read(buf[:]); err != nil {
				return "", err
			}
			v := int(buf[0])
			if v < reject {
				b[i] = letters[v%len(letters)]
				break
			}
		}
	}
	return string(b), nil
}
