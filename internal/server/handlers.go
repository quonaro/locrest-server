package server

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"locrest-server/internal/config"
	"locrest-server/internal/script"
)

func parseAllowedIPs(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "/") {
			_, _, err := net.ParseCIDR(p)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q", p)
			}
		} else {
			ip := net.ParseIP(p)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP %q", p)
			}
			p = p + "/32"
		}
		out = append(out, p)
	}
	return out, nil
}

// sendScriptError returns a shell script that prints the error and exits,
// so `curl | bash` surfaces the message instead of trying to execute plain text.
func sendScriptError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "text/x-shellscript")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, "#!/bin/sh\necho %q >&2\nexit 1\n", msg)
}

func (f *Frontend) handleScript(w http.ResponseWriter, r *http.Request, localPort, remotePort int, targetHost, mode, httpAuth string) {
	role := "auth"
	if !isAuthenticated(r, f.db) {
		role = "public"
	}
	cfg := f.cfg.Load()
	ip := clientIP(r, cfg.Network.BehindProxy)
	slog.Debug("script request", "ip", ip, "local_port", localPort, "mode", mode, "role", role)
	if !f.rateLimiter.allow(ip) {
		slog.Warn("rate limit exceeded", "ip", ip)
		sendScriptError(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if cfg.Tunnel.MaxSessions > 0 && f.store.Len() >= cfg.Tunnel.MaxSessions {
		slog.Warn("max sessions reached", "count", f.store.Len(), "limit", cfg.Tunnel.MaxSessions)
		sendScriptError(w, "Server busy", http.StatusServiceUnavailable)
		return
	}

	binaries, err := f.binCache.List()
	if err != nil || len(binaries) == 0 {
		slog.Warn("binary cache empty, cannot generate script", "ip", ip)
		sendScriptError(w, "Client binaries not available, run 'lrs binary update'", http.StatusServiceUnavailable)
		return
	}

	var perms config.Permissions
	if role == "public" {
		perms = cfg.Permissions.Public
	} else {
		perms = cfg.Permissions.Auth
	}

	if httpAuth != "" && !perms.HTTPAuth {
		slog.Warn("permission denied", "ip", ip, "feature", "http_auth", "role", role)
		sendScriptError(w, "Permission DENIED", http.StatusForbidden)
		return
	}

	if targetHost != "" && !perms.SetHost {
		slog.Warn("permission denied", "ip", ip, "feature", "set_host", "role", role)
		sendScriptError(w, "Permission DENIED", http.StatusForbidden)
		return
	}
	if targetHost != "" && !f.isAllowedTunnelHost(targetHost) {
		slog.Warn("target host not allowed", "ip", ip, "target_host", targetHost)
		sendScriptError(w, "target host is not allowed", http.StatusBadRequest)
		return
	}

	requestedSubdomain := r.URL.Query().Get("subdomain")
	if requestedSubdomain != "" && !perms.SetSubdomain {
		slog.Warn("permission denied", "ip", ip, "feature", "set_subdomain", "role", role)
		sendScriptError(w, "Permission DENIED", http.StatusForbidden)
		return
	}
	if requestedSubdomain != "" && f.isReservedSubdomain(requestedSubdomain) {
		slog.Warn("subdomain is reserved", "ip", ip, "subdomain", requestedSubdomain)
		sendScriptError(w, "subdomain is reserved", http.StatusBadRequest)
		return
	}

	allowedIPsRaw := r.URL.Query().Get("allowed_ips")
	var allowedIPs []string
	if allowedIPsRaw != "" {
		if !perms.SetAllowedIPs {
			slog.Warn("permission denied", "ip", ip, "feature", "set_allowed_ips", "role", role)
			sendScriptError(w, "Permission DENIED", http.StatusForbidden)
			return
		}
		var err error
		allowedIPs, err = parseAllowedIPs(allowedIPsRaw)
		if err != nil {
			slog.Warn("invalid allowed_ips", "ip", ip, "error", err)
			sendScriptError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	rolePublic := role == "public"
	ttl, infinity, err := effectiveTTL(r, cfg, rolePublic)
	if err != nil {
		slog.Warn("invalid ttl", "ip", ip, "error", err)
		sendScriptError(w, err.Error(), http.StatusBadRequest)
		return
	}

	serverPort := remotePort
	if serverPort <= 0 {
		serverPort = f.NextServerPort()
	} else if f.isPortInUse(serverPort) {
		slog.Warn("port already in use", "ip", ip, "server_port", serverPort)
		sendScriptError(w, "Port already in use", http.StatusConflict)
		return
	}

	var username string
	if u := bearerUser(r, f.db); u != nil {
		username = u.Username
	}
	sess, err := f.store.Create(localPort, serverPort, targetHost, ttl, infinity, cfg.Tunnel.SubdomainLength, mode, role, httpAuth, requestedSubdomain, allowedIPs, username)
	if err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		if msg == "subdomain already in use" {
			status = http.StatusConflict
		} else if strings.Contains(msg, "subdomain must") || strings.Contains(msg, "subdomain must not") {
			status = http.StatusBadRequest
		}
		slog.Error("session creation failed", "ip", ip, "error", err, "status", status)
		sendScriptError(w, msg, status)
		return
	}

	hostOnly := r.Host
	if colonIdx := strings.LastIndex(hostOnly, ":"); colonIdx != -1 {
		hostOnly = hostOnly[:colonIdx]
	}
	serverURL := fmt.Sprintf("https://%s", hostOnly)
	if cfg.Network.HTTPSPort != 443 {
		serverURL = fmt.Sprintf("https://%s:%d", hostOnly, cfg.Network.HTTPSPort)
	}
	if cfg.TLS.Cert == "" && !cfg.TLS.AutoTLS {
		serverURL = fmt.Sprintf("http://%s", hostOnly)
		if cfg.Network.HTTPPort != 80 {
			serverURL = fmt.Sprintf("http://%s:%d", hostOnly, cfg.Network.HTTPPort)
		}
	}

	flags := map[string]string{
		"debug": r.URL.Query().Get("debug"),
	}
	scr, err := script.Generate(serverURL, sess, r.UserAgent(), flags, ttl, infinity, binaries)
	if err != nil {
		slog.Error("script generation failed", "ip", ip, "subdomain", sess.Subdomain, "error", err)
		sendScriptError(w, "Script generation failed", http.StatusInternalServerError)
		return
	}

	slog.Info("script generated", "ip", ip, "subdomain", sess.Subdomain, "server_port", sess.ServerPort, "mode", sess.Mode, "role", sess.Role, "username", username)
	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Header().Set("Content-Disposition", "attachment; filename=install.sh")
	_, _ = w.Write([]byte(scr))
}
