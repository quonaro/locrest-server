package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"time"

	"locrest-server/internal/db"
)

// Session is an alias for db.Session for backward compatibility.
type Session = db.Session

// Store is a thin adapter over db.DB that preserves the original API surface.
type Store struct {
	db *db.DB
}

// NewStore creates a session store backed by BoltDB.
func NewStore(d *db.DB) *Store {
	return &Store{db: d}
}

// Create generates a new session with a unique subdomain, setup token and chisel token.
func (s *Store) Create(localPort, serverPort int, targetHost string, ttl time.Duration, infinity bool, subdomainLen int, mode, role, httpAuth, preferredSubdomain string, allowedIPs []string, username string) (*Session, error) {
	return s.db.CreateSession(localPort, serverPort, targetHost, ttl, infinity, subdomainLen, mode, role, httpAuth, preferredSubdomain, allowedIPs, username)
}

// Get retrieves a session by setup token.
func (s *Store) Get(setupToken string) (*Session, bool) {
	return s.db.GetSession(setupToken)
}

// GetByPubkey finds a session by its registered public key (hex).
func (s *Store) GetByPubkey(pubHex string) (*Session, bool) {
	return s.db.GetSessionByPubkey(pubHex)
}

// GetBySubdomain finds a session by its subdomain.
func (s *Store) GetBySubdomain(subdomain string) (*Session, bool) {
	return s.db.GetSessionBySubdomain(subdomain)
}

// RegisterPubkey links a public key to a pending session.
// Returns false if the token is unknown, already activated, or already has a pubkey.
func (s *Store) RegisterPubkey(setupToken, pubHex string) bool {
	return s.db.RegisterPubkey(setupToken, pubHex)
}

// Delete removes a session and its indexes.
func (s *Store) Delete(setupToken string) {
	s.db.DeleteSession(setupToken)
}

// HasSubdomain reports whether any existing session uses the given subdomain.
func (s *Store) HasSubdomain(subdomain string) bool {
	return s.db.HasSubdomain(subdomain)
}

// Len returns the number of active sessions.
func (s *Store) Len() int {
	return s.db.SessionCount()
}

// All returns a snapshot of all sessions.
func (s *Store) All() []*Session {
	out, _ := s.db.AllSessions()
	return out
}

// UpdateNonce persists the given nonce and its timestamp for a session.
func (s *Store) UpdateNonce(setupToken, nonce string, nonceAt time.Time) error {
	return s.db.UpdateSessionNonce(setupToken, nonce, nonceAt)
}

// Activate marks a session as activated in persistent storage.
func (s *Store) Activate(setupToken string) error {
	return s.db.ActivateSession(setupToken)
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

// TokenPrefix returns a short, non-sensitive prefix of a token for logging.
func TokenPrefix(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
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
