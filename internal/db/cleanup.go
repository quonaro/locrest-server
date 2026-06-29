package db

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	bolt "go.etcd.io/bbolt"
)

// StartCleaner launches a background goroutine that removes expired sessions
// and invalidates expired user tokens every interval.
func (d *DB) StartCleaner(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.cleanSessions()
				d.invalidateExpiredUsers()
			}
		}
	}()
}

func (d *DB) cleanSessions() {
	now := time.Now()
	var removed int
	_ = d.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketSessions))
		if b == nil {
			return nil
		}
		cursor := b.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var sd sessionData
			if err := json.Unmarshal(v, &sd); err != nil {
				continue
			}
			if now.After(sd.ExpiresAt) {
				_ = tx.Bucket([]byte(bucketSessionsBySub)).Delete([]byte(sd.Subdomain))
				if len(sd.PubKey) > 0 {
					_ = tx.Bucket([]byte(bucketSessionsByPubkey)).Delete([]byte(string(sd.PubKey)))
				}
				_ = b.Delete(k)
				removed++
			}
		}
		return nil
	})
	if removed > 0 {
		slog.Info("cleaner removed expired sessions", "count", removed)
	}
}

func (d *DB) invalidateExpiredUsers() {
	now := time.Now()
	var invalidated int
	_ = d.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketUsers))
		if b == nil {
			return nil
		}
		cursor := b.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var u User
			if err := json.Unmarshal(v, &u); err != nil {
				continue
			}
			if now.After(u.Expire) {
				u.APIToken = ""
				newData, _ := json.Marshal(u)
				_ = b.Put(k, newData)
				_ = tx.Bucket([]byte(bucketUsersByToken)).Delete([]byte(u.APIToken))
				invalidated++
			}
		}
		return nil
	})
	if invalidated > 0 {
		slog.Info("cleaner invalidated expired users", "count", invalidated)
	}
}
