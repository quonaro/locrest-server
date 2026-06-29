package db

import (
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

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
