package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"locrest-server/internal/db"
)

func TestBearerUser(t *testing.T) {
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "auth.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	user := &db.User{
		Username:       "alice",
		APIToken:       "valid-token-123",
		SeedPhraseHash: "deadbeef",
	}
	if err := database.CreateUser(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cases := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "valid bearer header",
			header: "Bearer valid-token-123",
			want:   "alice",
		},
		{
			name:   "invalid bearer token",
			header: "Bearer invalid-token",
			want:   "",
		},
		{
			name: "missing token",
			want: "",
		},
		{
			name:   "non-bearer authorization scheme",
			header: "Basic dXNlcjpwYXNz",
			want:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/8080", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}

			got := bearerUser(req, database)
			var gotName string
			if got != nil {
				gotName = got.Username
			}
			if gotName != tc.want {
				t.Fatalf("got username %q, want %q", gotName, tc.want)
			}
		})
	}
}
