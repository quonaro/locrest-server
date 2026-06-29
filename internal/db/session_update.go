package db

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

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

// UpdateSessionNonce stores a fresh nonce and its timestamp for the given session.
func (d *DB) UpdateSessionNonce(setupToken, nonce string, nonceAt time.Time) error {
	return d.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketSessions))
		data := b.Get([]byte(setupToken))
		if data == nil {
			return fmt.Errorf("session not found")
		}
		var sd sessionData
		if err := json.Unmarshal(data, &sd); err != nil {
			return err
		}
		sd.Nonce = nonce
		sd.NonceAt = nonceAt
		newData, err := json.Marshal(&sd)
		if err != nil {
			return err
		}
		return b.Put([]byte(setupToken), newData)
	})
}

// ActivateSession marks the session as activated and clears the nonce.
func (d *DB) ActivateSession(setupToken string) error {
	return d.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketSessions))
		data := b.Get([]byte(setupToken))
		if data == nil {
			return fmt.Errorf("session not found")
		}
		var sd sessionData
		if err := json.Unmarshal(data, &sd); err != nil {
			return err
		}
		sd.Activated = true
		sd.Nonce = ""
		newData, err := json.Marshal(&sd)
		if err != nil {
			return err
		}
		return b.Put([]byte(setupToken), newData)
	})
}
