package server

import (
	"net/http"
	"strings"

	"locrest-server/internal/db"
)

// bearerUser extracts the user from the Authorization: Bearer header.
// It returns nil if the header is missing, malformed, or the token is invalid/expired.
func bearerUser(r *http.Request, database *db.DB) *db.User {
	h := r.Header.Get("Authorization")
	if h == "" {
		return nil
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return nil
	}
	token := strings.TrimPrefix(h, prefix)
	user, err := database.GetUserByToken(token)
	if err != nil {
		return nil
	}
	if user.APIToken == "" {
		return nil
	}
	return user
}
