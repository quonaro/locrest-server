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

// Store is an in-memory session map keyed by setup token, with secondary indexes
// for fast pubkey and subdomain lookups.
type Store struct {
	mu          sync.RWMutex
	sessions    map[string]*Session // keyed by setup token
	byPubkey    map[string]*Session // keyed by hex-encoded pubkey
	bySubdomain map[string]*Session // keyed by subdomain
}

// NewStore creates a session store.
func NewStore() *Store {
	return &Store{
		sessions:    make(map[string]*Session),
		byPubkey:    make(map[string]*Session),
		bySubdomain: make(map[string]*Session),
	}
}

// Create generates a new session with a setup token and chisel token.
func (s *Store) Create(subdomain string, localPort, serverPort int, targetHost string, ttl time.Duration) (*Session, error) {
	if targetHost == "" {
		targetHost = "localhost"
	}
	token, err := randHex(32)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	setup, err := randHex(32)
	if err != nil {
		return nil, fmt.Errorf("generate setup token: %w", err)
	}
	sess := &Session{
		Subdomain:  subdomain,
		LocalPort:  localPort,
		ServerPort: serverPort,
		TargetHost: targetHost,
		Token:      token,
		SetupToken: setup,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
	}
	s.mu.Lock()
	s.sessions[setup] = sess
	s.bySubdomain[subdomain] = sess
	s.mu.Unlock()
	return sess, nil
}

// Get retrieves a session by setup token.
func (s *Store) Get(setupToken string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[setupToken]
	return sess, ok
}

// GetByPubkey finds a session by its registered public key (hex).
func (s *Store) GetByPubkey(pubHex string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.byPubkey[pubHex]
	return sess, ok
}

// GetBySubdomain finds a session by its subdomain.
func (s *Store) GetBySubdomain(subdomain string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.bySubdomain[subdomain]
	return sess, ok
}

// RegisterPubkey links a public key to a pending session.
// Returns false if the token is unknown, already activated, or already has a pubkey.
func (s *Store) RegisterPubkey(setupToken, pubHex string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[setupToken]
	if !ok || sess.Activated || len(sess.PubKey) > 0 {
		return false
	}
	b, err := hex.DecodeString(pubHex)
	if err != nil {
		return false
	}
	sess.PubKey = b
	s.byPubkey[pubHex] = sess
	return true
}

// Delete removes a session and its indexes.
func (s *Store) Delete(setupToken string) {
	s.mu.Lock()
	sess, ok := s.sessions[setupToken]
	if ok {
		delete(s.sessions, setupToken)
		delete(s.bySubdomain, sess.Subdomain)
		if len(sess.PubKey) > 0 {
			delete(s.byPubkey, hex.EncodeToString(sess.PubKey))
		}
	}
	s.mu.Unlock()
}

// HasSubdomain reports whether any existing session uses the given subdomain.
func (s *Store) HasSubdomain(subdomain string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.bySubdomain[subdomain]
	return ok
}

// Len returns the number of active sessions.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// All returns a snapshot of all sessions.
func (s *Store) All() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, sess)
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
