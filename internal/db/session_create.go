package db

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

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
