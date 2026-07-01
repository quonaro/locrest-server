package server

import (
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
)

//go:embed assets/error.html
var errorPageBytes []byte

//go:embed assets/root.html
var rootPageBytes []byte

var errorPageTmpl = template.Must(template.New("error").Parse(string(errorPageBytes)))
var rootPageTmpl = template.Must(template.New("root").Parse(string(rootPageBytes)))

func (f *Frontend) sendHTMLError(w http.ResponseWriter, r *http.Request, code int, title, message string) {
	if r.URL.Query().Get("error") == "json" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  code,
			"error":   title,
			"message": message,
		})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	var domain string
	if cfg := f.cfg.Load(); cfg != nil {
		domain = cfg.Network.Domain
	}
	_ = errorPageTmpl.Execute(w, map[string]any{
		"Code":    code,
		"Title":   title,
		"Message": message,
		"Domain":  domain,
	})
}

func stripErrorParam(rawQuery string) string {
	q, _ := url.ParseQuery(rawQuery)
	q.Del("error")
	return q.Encode()
}

func ipAllowed(ip string, allowedIPs []string) bool {
	if len(allowedIPs) == 0 {
		return true
	}
	client := net.ParseIP(ip)
	if client == nil {
		return false
	}
	for _, cidr := range allowedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(client) {
			return true
		}
	}
	return false
}

func (f *Frontend) checkAllowedIPs(w http.ResponseWriter, r *http.Request, subdomain string) bool {
	sess, ok := f.store.GetBySubdomain(subdomain)
	if !ok || len(sess.AllowedIPs) == 0 {
		return true
	}
	cfg := f.cfg.Load()
	if !ipAllowed(clientIP(r, cfg.Network.BehindProxy), sess.AllowedIPs) {
		f.sendHTMLError(w, r, http.StatusForbidden, "Forbidden", "Access from this IP is not allowed.")
		return false
	}
	return true
}

func (f *Frontend) checkBasicAuth(w http.ResponseWriter, r *http.Request, subdomain string) bool {
	sess, ok := f.store.GetBySubdomain(subdomain)
	if !ok || sess.HTTPAuth == "" {
		return true
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="locrest"`)
		f.sendHTMLError(w, r, http.StatusUnauthorized, "Unauthorized", "Authentication required.")
		return false
	}
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		f.sendHTMLError(w, r, http.StatusUnauthorized, "Unauthorized", "Invalid authorization scheme.")
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(authHeader[len(prefix):])
	if err != nil {
		f.sendHTMLError(w, r, http.StatusUnauthorized, "Unauthorized", "Invalid credentials.")
		return false
	}
	expected := []byte(sess.HTTPAuth)
	if subtle.ConstantTimeCompare(decoded, expected) != 1 {
		f.sendHTMLError(w, r, http.StatusUnauthorized, "Unauthorized", "Invalid credentials.")
		return false
	}
	return true
}

func (f *Frontend) isRootHost(host string) bool {
	if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}
	cfg := f.cfg.Load()
	return host == cfg.Network.Domain
}

func (f *Frontend) handleRoot(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	var domain string
	if cfg := f.cfg.Load(); cfg != nil {
		domain = cfg.Network.Domain
	}
	_ = rootPageTmpl.Execute(w, map[string]any{
		"Domain": domain,
	})
}
