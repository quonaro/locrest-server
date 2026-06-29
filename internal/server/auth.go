package server

import (
	"context"
	"net/http"
	"strings"

	"locrest-server/internal/db"
)

type contextKey string

const userContextKey contextKey = "auth_user"

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

// requireBearer checks the Authorization: Bearer header and writes 401 or 403 on failure.
// On success it stores the user in the request context and returns true.
func requireBearer(w http.ResponseWriter, r *http.Request, database *db.DB) (*http.Request, bool) {
	user := bearerUser(r, database)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return r, false
	}
	ctx := context.WithValue(r.Context(), userContextKey, user)
	return r.WithContext(ctx), true
}

// contextUser returns the authenticated user from the request context, or nil.
func contextUser(r *http.Request) *db.User {
	u, _ := r.Context().Value(userContextKey).(*db.User)
	return u
}
