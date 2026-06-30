package server

import (
	"fmt"
	"net/http"
	"time"

	"locrest-server/internal/config"
	"locrest-server/internal/db"
)

// isAuthenticated returns true if the request carries a valid Bearer token.
func isAuthenticated(r *http.Request, database *db.DB) bool {
	return bearerUser(r, database) != nil
}

// effectiveTTL returns the final TTL and an infinity flag for a request considering role permissions.
// rolePublic is true when the caller is unauthenticated. When infinity is true, ttl is meaningless.
func effectiveTTL(r *http.Request, cfg *config.ServerConfig, rolePublic bool) (time.Duration, bool, error) {
	var perms config.Permissions
	if rolePublic {
		perms = cfg.Permissions.Public
	} else {
		perms = cfg.Permissions.Auth
	}

	if r.URL.Query().Get("infinity") == "true" {
		return 0, true, nil
	}

	ttl := cfg.TTL
	if !perms.SetTTL {
		return perms.MaxTTL, false, nil
	}

	if raw := r.URL.Query().Get("ttl"); raw != "" {
		reqTTL, err := time.ParseDuration(raw)
		if err != nil {
			return 0, false, fmt.Errorf("invalid ttl: expected duration like 1h, 30m, 90s")
		}
		if reqTTL <= 0 {
			return 0, false, fmt.Errorf("ttl must be positive")
		}
		if reqTTL > cfg.TTLLimit {
			return 0, false, fmt.Errorf("requested ttl exceeds maximum %s", cfg.TTLLimit)
		}
		if reqTTL > perms.MaxTTL {
			return 0, false, fmt.Errorf("requested ttl exceeds maximum allowed for your role (%s)", perms.MaxTTL)
		}
		ttl = reqTTL
	}
	if ttl > perms.MaxTTL {
		ttl = perms.MaxTTL
	}
	return ttl, false, nil
}
