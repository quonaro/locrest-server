package server

import (
	"net/http"
	"strings"
)

// isCurlLikeRequest returns true for curl/wget user-agents.
func isCurlLikeRequest(r *http.Request) bool {
	ua := strings.ToLower(r.UserAgent())
	return strings.Contains(ua, "curl") || strings.Contains(ua, "wget")
}
