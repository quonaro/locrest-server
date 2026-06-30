package server

import (
	"fmt"
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

func (f *Frontend) handleScript(w http.ResponseWriter, r *http.Request, localPort, remotePort int, targetHost, mode, httpAuth string) {
	role := "auth"
	if !isAuthenticated(r, f.db) {
		role = "public"
	}
	if !f.rateLimiter.allow(clientIP(r, f.cfg.BehindProxy)) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if f.cfg.MaxSessions > 0 && f.store.Len() >= f.cfg.MaxSessions {
		http.Error(w, "Server busy", http.StatusServiceUnavailable)
		return
	}

	var perms config.Permissions
	if role == "public" {
		perms = f.cfg.Permissions.Public
	} else {
		perms = f.cfg.Permissions.Auth
	}

	if httpAuth != "" && !perms.HTTPAuth {
		http.Error(w, "Permission DENIED", http.StatusForbidden)
		return
	}

	if targetHost != "" && !perms.SetHost {
		http.Error(w, "Permission DENIED", http.StatusForbidden)
		return
	}
	if targetHost != "" && !f.isAllowedTunnelHost(targetHost) {
		http.Error(w, "target host is not allowed", http.StatusBadRequest)
		return
	}

	requestedSubdomain := r.URL.Query().Get("subdomain")
	if requestedSubdomain != "" && !perms.SetSubdomain {
		http.Error(w, "Permission DENIED", http.StatusForbidden)
		return
	}
	if requestedSubdomain != "" && f.isReservedSubdomain(requestedSubdomain) {
		http.Error(w, "subdomain is reserved", http.StatusBadRequest)
		return
	}

	allowedIPsRaw := r.URL.Query().Get("allowed_ips")
	var allowedIPs []string
	if allowedIPsRaw != "" {
		if !perms.SetAllowedIPs {
			http.Error(w, "Permission DENIED", http.StatusForbidden)
			return
		}
		var err error
		allowedIPs, err = parseAllowedIPs(allowedIPsRaw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	rolePublic := role == "public"
	ttl, infinity, err := effectiveTTL(r, f.cfg, rolePublic)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	serverPort := remotePort
	if serverPort <= 0 {
		serverPort = f.NextServerPort()
	} else if f.isPortInUse(serverPort) {
		http.Error(w, "Port already in use", http.StatusConflict)
		return
	}

	sess, err := f.store.Create(localPort, serverPort, targetHost, ttl, infinity, f.cfg.SubdomainLength, mode, role, httpAuth, requestedSubdomain, allowedIPs)
	if err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		if msg == "subdomain already in use" {
			status = http.StatusConflict
		} else if strings.Contains(msg, "subdomain must") || strings.Contains(msg, "subdomain must not") {
			status = http.StatusBadRequest
		}
		http.Error(w, msg, status)
		return
	}

	hostOnly := r.Host
	if colonIdx := strings.LastIndex(hostOnly, ":"); colonIdx != -1 {
		hostOnly = hostOnly[:colonIdx]
	}
	serverURL := fmt.Sprintf("https://%s", hostOnly)
	if f.cfg.HTTPSPort != 443 {
		serverURL = fmt.Sprintf("https://%s:%d", hostOnly, f.cfg.HTTPSPort)
	}
	if f.cfg.TLS.Cert == "" && !f.cfg.TLS.AutoTLS {
		serverURL = fmt.Sprintf("http://%s", hostOnly)
		if f.cfg.HTTPPort != 80 {
			serverURL = fmt.Sprintf("http://%s:%d", hostOnly, f.cfg.HTTPPort)
		}
	}

	flags := map[string]string{
		"debug": r.URL.Query().Get("debug"),
	}
	binaryURL := f.cfg.BinaryURL
	if f.cfg.Dev {
		binaryURL = ""
	}
	scr, err := script.Generate(serverURL, binaryURL, sess, r.UserAgent(), flags, ttl, infinity)
	if err != nil {
		http.Error(w, "Script generation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Header().Set("Content-Disposition", "attachment; filename=install.sh")
	w.Write([]byte(scr))
}
