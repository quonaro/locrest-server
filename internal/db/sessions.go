package db

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
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
}

func (s *Session) toData() *sessionData {
	return &sessionData{
		PubKey: s.PubKey, Subdomain: s.Subdomain, LocalPort: s.LocalPort,
		ServerPort: s.ServerPort, TargetHost: s.TargetHost, Token: s.Token,
		SetupToken: s.SetupToken, CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt,
		Nonce: s.Nonce, NonceAt: s.NonceAt, Activated: s.Activated,
		Mode: s.Mode, Role: s.Role, HTTPAuth: s.HTTPAuth, AllowedIPs: s.AllowedIPs,
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

func validateSubdomain(s string) error {
	if len(s) < 3 || len(s) > 63 {
		return fmt.Errorf("subdomain must be 3-63 characters")
	}
	for i, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return fmt.Errorf("subdomain must contain only lowercase letters, digits, and hyphens")
		}
		if i == 0 && r == '-' {
			return fmt.Errorf("subdomain must not start with a hyphen")
		}
	}
	if s[len(s)-1] == '-' {
		return fmt.Errorf("subdomain must not end with a hyphen")
	}
	return nil
}

// CreateSession generates a new session with a unique subdomain, setup token and chisel token.
// If preferredSubdomain is non-empty it is validated and used; otherwise a random one is generated.
func (d *DB) CreateSession(localPort, serverPort int, targetHost string, ttl time.Duration, subdomainLen int, mode, role, httpAuth, preferredSubdomain string, allowedIPs []string) (*Session, error) {
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

	var sess Session
	if err := d.Update(func(tx *bolt.Tx) error {
		subB := tx.Bucket([]byte(bucketSessionsBySub))
		var subdomain string
		if preferredSubdomain != "" {
			if err := validateSubdomain(preferredSubdomain); err != nil {
				return err
			}
			if subB.Get([]byte(preferredSubdomain)) != nil {
				return fmt.Errorf("subdomain already in use")
			}
			subdomain = preferredSubdomain
		} else {
			for attempts := 0; attempts < 100; attempts++ {
				subdomain, err = randString(subdomainLen)
				if err != nil {
					return fmt.Errorf("generate subdomain: %w", err)
				}
				if subB.Get([]byte(subdomain)) == nil {
					break
				}
			}
			if subB.Get([]byte(subdomain)) != nil {
				return fmt.Errorf("could not generate unique subdomain")
			}
		}

		sess = Session{
			Subdomain:  subdomain,
			LocalPort:  localPort,
			ServerPort: serverPort,
			TargetHost: targetHost,
			Token:      token,
			SetupToken: setup,
			CreatedAt:  time.Now(),
			ExpiresAt:  time.Now().Add(ttl),
			Mode:       mode,
			Role:       role,
			HTTPAuth:   httpAuth,
			AllowedIPs: allowedIPs,
		}
		data, err := json.Marshal(sess.toData())
		if err != nil {
			return err
		}
		if err := tx.Bucket([]byte(bucketSessions)).Put([]byte(setup), data); err != nil {
			return err
		}
		if err := subB.Put([]byte(subdomain), []byte(setup)); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &sess, nil
}

// GetSession retrieves a session by setup token.
func (d *DB) GetSession(setupToken string) (*Session, bool) {
	var sess Session
	err := d.View(func(tx *bolt.Tx) error {
		data := tx.Bucket([]byte(bucketSessions)).Get([]byte(setupToken))
		if data == nil {
			return fmt.Errorf("not found")
		}
		var d sessionData
		if err := json.Unmarshal(data, &d); err != nil {
			return err
		}
		sess.fromData(&d)
		return nil
	})
	if err != nil {
		return nil, false
	}
	return &sess, true
}

// GetSessionByPubkey finds a session by its registered public key (hex).
func (d *DB) GetSessionByPubkey(pubHex string) (*Session, bool) {
	var sess Session
	err := d.View(func(tx *bolt.Tx) error {
		setup := tx.Bucket([]byte(bucketSessionsByPubkey)).Get([]byte(pubHex))
		if setup == nil {
			return fmt.Errorf("not found")
		}
		data := tx.Bucket([]byte(bucketSessions)).Get(setup)
		if data == nil {
			return fmt.Errorf("not found")
		}
		var sd sessionData
		if err := json.Unmarshal(data, &sd); err != nil {
			return err
		}
		sess.fromData(&sd)
		return nil
	})
	if err != nil {
		return nil, false
	}
	return &sess, true
}

// GetSessionBySubdomain finds a session by its subdomain.
func (d *DB) GetSessionBySubdomain(subdomain string) (*Session, bool) {
	var sess Session
	err := d.View(func(tx *bolt.Tx) error {
		setup := tx.Bucket([]byte(bucketSessionsBySub)).Get([]byte(subdomain))
		if setup == nil {
			return fmt.Errorf("not found")
		}
		data := tx.Bucket([]byte(bucketSessions)).Get(setup)
		if data == nil {
			return fmt.Errorf("not found")
		}
		var sd sessionData
		if err := json.Unmarshal(data, &sd); err != nil {
			return err
		}
		sess.fromData(&sd)
		return nil
	})
	if err != nil {
		return nil, false
	}
	return &sess, true
}

// RegisterPubkey links a public key to a pending session.
// Returns false if the token is unknown, already activated, or already has a pubkey.
func (d *DB) RegisterPubkey(setupToken, pubHex string) bool {
	var ok bool
	err := d.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketSessions))
		data := b.Get([]byte(setupToken))
		if data == nil {
			return fmt.Errorf("not found")
		}
		var sd sessionData
		if err := json.Unmarshal(data, &sd); err != nil {
			return err
		}
		if sd.Activated || len(sd.PubKey) > 0 {
			return fmt.Errorf("already active")
		}
		bPub, err := hex.DecodeString(pubHex)
		if err != nil {
			return err
		}
		sd.PubKey = bPub
		newData, err := json.Marshal(&sd)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(setupToken), newData); err != nil {
			return err
		}
		if err := tx.Bucket([]byte(bucketSessionsByPubkey)).Put([]byte(pubHex), []byte(setupToken)); err != nil {
			return err
		}
		ok = true
		return nil
	})
	if err != nil {
		return false
	}
	return ok
}

// DeleteSession removes a session and its indexes.
func (d *DB) DeleteSession(setupToken string) {
	_ = d.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketSessions))
		data := b.Get([]byte(setupToken))
		if data == nil {
			return nil
		}
		var sd sessionData
		if err := json.Unmarshal(data, &sd); err != nil {
			return err
		}
		_ = b.Delete([]byte(setupToken))
		_ = tx.Bucket([]byte(bucketSessionsBySub)).Delete([]byte(sd.Subdomain))
		if len(sd.PubKey) > 0 {
			_ = tx.Bucket([]byte(bucketSessionsByPubkey)).Delete([]byte(hex.EncodeToString(sd.PubKey)))
		}
		return nil
	})
}

// HasSubdomain reports whether any existing session uses the given subdomain.
func (d *DB) HasSubdomain(subdomain string) bool {
	var ok bool
	_ = d.View(func(tx *bolt.Tx) error {
		ok = tx.Bucket([]byte(bucketSessionsBySub)).Get([]byte(subdomain)) != nil
		return nil
	})
	return ok
}

// SessionCount returns the number of sessions.
func (d *DB) SessionCount() int {
	var count int
	_ = d.View(func(tx *bolt.Tx) error {
		count = tx.Bucket([]byte(bucketSessions)).Stats().KeyN
		return nil
	})
	return count
}

// AllSessions returns a snapshot of all sessions.
func (d *DB) AllSessions() ([]*Session, error) {
	var out []*Session
	err := d.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketSessions)).ForEach(func(k, v []byte) error {
			var sd sessionData
			if err := json.Unmarshal(v, &sd); err != nil {
				return err
			}
			s := &Session{}
			s.fromData(&sd)
			out = append(out, s)
			return nil
		})
	})
	return out, err
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randString(n int) (string, error) {
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
