package db

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

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
