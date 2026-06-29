package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// User represents an authorized user with an API token and seed phrase hash.
type User struct {
	Username      string    `json:"username"`
	APIToken      string    `json:"api_token"`
	SeedPhraseHash string   `json:"seed_phrase_hash"`
	Expire        time.Time `json:"expire"`
	CreatedAt     time.Time `json:"created_at"`
}

// HashSeedPhrase computes SHA-256 of the plaintext seed phrase.
func HashSeedPhrase(seed string) string {
	h := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(h[:])
}

// CreateUser inserts a new user into the database.
func (d *DB) CreateUser(user *User) error {
	return d.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketUsers))
		if b == nil {
			return fmt.Errorf("users bucket missing")
		}
		key := []byte(user.Username)
		if b.Get(key) != nil {
			return fmt.Errorf("user already exists")
		}
		data, err := json.Marshal(user)
		if err != nil {
			return err
		}
		if err := b.Put(key, data); err != nil {
			return err
		}
		// secondary indexes
		if err := tx.Bucket([]byte(bucketUsersByToken)).Put([]byte(user.APIToken), key); err != nil {
			return err
		}
		if err := tx.Bucket([]byte(bucketUsersBySeedHash)).Put([]byte(user.SeedPhraseHash), key); err != nil {
			return err
		}
		return nil
	})
}

// GetUserByToken looks up a user by their API bearer token.
func (d *DB) GetUserByToken(token string) (*User, error) {
	var user User
	err := d.View(func(tx *bolt.Tx) error {
		idx := tx.Bucket([]byte(bucketUsersByToken))
		if idx == nil {
			return fmt.Errorf("users_by_token bucket missing")
		}
		userKey := idx.Get([]byte(token))
		if userKey == nil {
			return fmt.Errorf("token not found")
		}
		data := tx.Bucket([]byte(bucketUsers)).Get(userKey)
		if data == nil {
			return fmt.Errorf("user missing")
		}
		return json.Unmarshal(data, &user)
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserBySeedHash looks up a user by the SHA-256 hash of their seed phrase.
func (d *DB) GetUserBySeedHash(hash string) (*User, error) {
	var user User
	err := d.View(func(tx *bolt.Tx) error {
		idx := tx.Bucket([]byte(bucketUsersBySeedHash))
		if idx == nil {
			return fmt.Errorf("users_by_seed_hash bucket missing")
		}
		userKey := idx.Get([]byte(hash))
		if userKey == nil {
			return fmt.Errorf("seed hash not found")
		}
		data := tx.Bucket([]byte(bucketUsers)).Get(userKey)
		if data == nil {
			return fmt.Errorf("user missing")
		}
		return json.Unmarshal(data, &user)
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateUserToken atomically replaces a user's API token.
func (d *DB) UpdateUserToken(username, newToken string) error {
	return d.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketUsers))
		if b == nil {
			return fmt.Errorf("users bucket missing")
		}
		key := []byte(username)
		data := b.Get(key)
		if data == nil {
			return fmt.Errorf("user not found")
		}
		var user User
		if err := json.Unmarshal(data, &user); err != nil {
			return err
		}
		// remove old index
		if err := tx.Bucket([]byte(bucketUsersByToken)).Delete([]byte(user.APIToken)); err != nil {
			return err
		}
		user.APIToken = newToken
		newData, err := json.Marshal(user)
		if err != nil {
			return err
		}
		if err := b.Put(key, newData); err != nil {
			return err
		}
		if err := tx.Bucket([]byte(bucketUsersByToken)).Put([]byte(newToken), key); err != nil {
			return err
		}
		return nil
	})
}

// DeleteUser removes a user and their indexes.
func (d *DB) DeleteUser(username string) error {
	return d.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketUsers))
		if b == nil {
			return fmt.Errorf("users bucket missing")
		}
		key := []byte(username)
		data := b.Get(key)
		if data == nil {
			return nil
		}
		var user User
		if err := json.Unmarshal(data, &user); err != nil {
			return err
		}
		if err := b.Delete(key); err != nil {
			return err
		}
		if err := tx.Bucket([]byte(bucketUsersByToken)).Delete([]byte(user.APIToken)); err != nil {
			return err
		}
		if err := tx.Bucket([]byte(bucketUsersBySeedHash)).Delete([]byte(user.SeedPhraseHash)); err != nil {
			return err
		}
		return nil
	})
}
