package db

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	bolt "go.etcd.io/bbolt"
)

// StartCleaner launches a background goroutine that invalidates expired user tokens
// every interval. Session cleanup is handled by the frontend cleaner, which also
// removes stale chisel users and routes.
func (d *DB) StartCleaner(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.invalidateExpiredUsers()
			}
		}
	}()
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
				_ = tx.Bucket([]byte(bucketUsersByToken)).Delete([]byte(u.APIToken))
				u.APIToken = ""
				newData, _ := json.Marshal(u)
				_ = b.Put(k, newData)
				invalidated++
			}
		}
		return nil
	})
	if invalidated > 0 {
		slog.Info("cleaner invalidated expired users", "count", invalidated)
	}
}
