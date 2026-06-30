package db

import (
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	bucketUsers            = "users"
	bucketUsersByToken     = "users_by_token"
	bucketUsersBySeedHash  = "users_by_seed_hash"
	bucketSessions         = "sessions"
	bucketSessionsByPubkey = "sessions_by_pubkey"
	bucketSessionsBySub    = "sessions_by_subdomain"
)

// DB wraps a bolt database with typed helpers.
type DB struct {
	*bolt.DB
}

// Open opens or creates the BoltDB file and initializes buckets.
// A 5-second timeout prevents CLI commands from blocking forever when the
// server process already holds the database lock.
func Open(path string) (*DB, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := initBuckets(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("init buckets: %w", err)
	}
	return &DB{db}, nil
}

func initBuckets(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		buckets := []string{
			bucketUsers, bucketUsersByToken, bucketUsersBySeedHash,
			bucketSessions, bucketSessionsByPubkey, bucketSessionsBySub,
		}
		for _, name := range buckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	})
}

// Close closes the database.
func (d *DB) Close() error {
	return d.DB.Close()
}
