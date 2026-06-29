package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"locrest-server/internal/auth"
	"locrest-server/internal/chiselwrapper"
	"locrest-server/internal/config"
	"locrest-server/internal/db"
)

func newTestFrontend(t *testing.T, cfg *config.ServerConfig) *Frontend {
	t.Helper()
	if cfg == nil {
		cfg = config.DefaultConfig()
		cfg.Domain = "localtest.me"
		cfg.HTTPPort = 8080
		cfg.HTTPSPort = 8443
		cfg.Dev = true
		cfg.RootPage = true
		cfg.StatusEndpoint = true
	}
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	store := auth.NewStore(database)
	chisel, err := chiselwrapper.New()
	if err != nil {
		t.Fatalf("new chisel: %v", err)
	}
	return NewFrontend(cfg, store, chisel, database)
}

func TestNextServerPort(t *testing.T) {
	f := newTestFrontend(t, nil)
	p1 := f.NextServerPort()
	p2 := f.NextServerPort()
	if p1 < 20000 || p1 >= 60000 {
		t.Fatalf("port %d out of range", p1)
	}
	if p1 == p2 {
		t.Fatal("consecutive ports should differ")
	}
	f.RegisterRoute("test", p1)
	p3 := f.NextServerPort()
	if p3 == p1 {
		t.Fatal("NextServerPort should skip ports already in use by routes")
	}
}

func TestRegisterAndResolveRoute(t *testing.T) {
	f := newTestFrontend(t, nil)
	f.RegisterRoute("sub1", 30001)
	port, sub, ok := f.resolveRoute("sub1.localtest.me")
	if !ok {
		t.Fatal("route not found")
	}
	if port != 30001 || sub != "sub1" {
		t.Fatalf("got port=%d sub=%q", port, sub)
	}
	f.UnregisterRoute("sub1")
	_, _, ok = f.resolveRoute("sub1.localtest.me")
	if ok {
		t.Fatal("route should be removed")
	}
}

func TestResolveRouteWithPort(t *testing.T) {
	f := newTestFrontend(t, nil)
	f.RegisterRoute("sub1", 30001)
	port, sub, ok := f.resolveRoute("sub1.localtest.me:8080")
	if !ok || port != 30001 || sub != "sub1" {
		t.Fatalf("resolve failed: port=%d sub=%q ok=%v", port, sub, ok)
	}
}

func TestIsPortInUse(t *testing.T) {
	f := newTestFrontend(t, nil)
	if f.isPortInUse(30001) {
		t.Fatal("port should not be in use")
	}
	f.RegisterRoute("sub1", 30001)
	if !f.isPortInUse(30001) {
		t.Fatal("port should be in use")
	}
}

func TestIsReservedSubdomain(t *testing.T) {
	f := newTestFrontend(t, nil)
	f.cfg.ReservedSubdomains = []string{"www", "api"}
	if !f.isReservedSubdomain("www") {
		t.Fatal("www should be reserved")
	}
	if f.isReservedSubdomain("sub1") {
		t.Fatal("sub1 should not be reserved")
	}
}

func TestIsAllowedTunnelHost(t *testing.T) {
	f := newTestFrontend(t, nil)
	f.cfg.AllowedTunnelHosts = []string{"localhost", "127.0.0.1"}
	if !f.isAllowedTunnelHost("localhost") {
		t.Fatal("localhost should be allowed")
	}
	if f.isAllowedTunnelHost("example.com") {
		t.Fatal("example.com should not be allowed")
	}
	f.cfg.AllowedTunnelHosts = nil
	f.cfg.BlockedTunnelHosts = []string{"bad.example.com"}
	if f.isAllowedTunnelHost("bad.example.com") {
		t.Fatal("blocked host should not be allowed")
	}
	if !f.isAllowedTunnelHost("good.example.com") {
		t.Fatal("good host should be allowed")
	}
}

func TestSecurityHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := securityHeaders(next, true, map[string]string{"X-Custom": "yes"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("missing deny")
	}
	if hsts := rec.Header().Get("Strict-Transport-Security"); hsts == "" {
		t.Fatal("missing HSTS")
	}
	if rec.Header().Get("X-Custom") != "yes" {
		t.Fatal("missing custom header")
	}
}

func TestRedirectToHTTPS(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not call next")
	})
	h := redirectToHTTPS(next, 8443)
	req := httptest.NewRequest(http.MethodGet, "/foo?bar=1", nil)
	req.Host = "example.com:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d", rec.Code)
	}
	want := "https://example.com:8443/foo?bar=1"
	if loc := rec.Header().Get("Location"); loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
}

func TestRedirectToHTTPSDefaultPort(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h := redirectToHTTPS(next, 443)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	want := "https://example.com/"
	if loc := rec.Header().Get("Location"); loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
}

func TestIPFilterMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.10:1234"
	rec := httptest.NewRecorder()

	h := ipFilterMiddleware(next, []string{"192.168.1.0/24"}, nil, false)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	h2 := ipFilterMiddleware(next, []string{"10.0.0.0/8"}, nil, false)
	rec2 := httptest.NewRecorder()
	h2.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec2.Code)
	}

	h3 := ipFilterMiddleware(next, nil, []string{"192.168.1.0/24"}, false)
	rec3 := httptest.NewRecorder()
	h3.ServeHTTP(rec3, req)
	if rec3.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec3.Code)
	}
}

func TestClientIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	if got := clientIP(req, false); got != "1.2.3.4" {
		t.Fatalf("clientIP = %q, want 1.2.3.4", got)
	}
	req.Header.Set("X-Forwarded-For", "9.8.7.6, 5.4.3.2")
	if got := clientIP(req, true); got != "9.8.7.6" {
		t.Fatalf("clientIP behind proxy = %q, want 9.8.7.6", got)
	}
	req.Header.Del("X-Forwarded-For")
	req.Header.Set("X-Real-Ip", "10.0.0.1")
	if got := clientIP(req, true); got != "10.0.0.1" {
		t.Fatalf("clientIP X-Real-Ip = %q, want 10.0.0.1", got)
	}
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(2, time.Minute)
	if !rl.allow("1.2.3.4") {
		t.Fatal("first request should be allowed")
	}
	if !rl.allow("1.2.3.4") {
		t.Fatal("second request should be allowed")
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("third request should be denied")
	}
	if !rl.allow("5.6.7.8") {
		t.Fatal("different IP should be allowed")
	}
}

func TestEffectiveTTL(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TTL = time.Hour
	cfg.TTLLimit = 24 * time.Hour

	req := httptest.NewRequest(http.MethodGet, "/?ttl=30m", nil)
	ttl, err := effectiveTTL(req, cfg, false)
	if err != nil {
		t.Fatalf("effectiveTTL: %v", err)
	}
	if ttl != 30*time.Minute {
		t.Fatalf("ttl = %v, want 30m", ttl)
	}

	// Public user cannot set TTL, capped to MaxTTL.
	cfg.Permissions.Public.SetTTL = false
	cfg.Permissions.Public.MaxTTL = 5 * time.Minute
	req2 := httptest.NewRequest(http.MethodGet, "/?ttl=30m", nil)
	ttl2, err := effectiveTTL(req2, cfg, true)
	if err != nil {
		t.Fatalf("effectiveTTL: %v", err)
	}
	if ttl2 != 5*time.Minute {
		t.Fatalf("ttl = %v, want 5m", ttl2)
	}

	req3 := httptest.NewRequest(http.MethodGet, "/?ttl=bad", nil)
	if _, err := effectiveTTL(req3, cfg, false); err == nil {
		t.Fatal("expected error for invalid ttl")
	}
}

func TestHandleScript(t *testing.T) {
	f := newTestFrontend(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/8080", nil)
	req.Host = "localtest.me"
	rec := httptest.NewRecorder()
	f.handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "text/x-shellscript" {
		t.Fatalf("Content-Type = %q, want text/x-shellscript", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "#!/bin/sh") {
		t.Fatal("missing shebang")
	}
	if !strings.Contains(body, "8080") {
		t.Fatal("missing port")
	}
}

func TestHandleScriptMaxSessions(t *testing.T) {
	f := newTestFrontend(t, nil)
	f.cfg.MaxSessions = 1
	if _, err := f.store.Create(8080, 30001, "localhost", time.Hour, 8, "http", "public", "", "", nil); err != nil {
		t.Fatalf("create session: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/8080", nil)
	req.Host = "localtest.me"
	rec := httptest.NewRecorder()
	f.handler(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestHandleChallengeAndVerify(t *testing.T) {
	f := newTestFrontend(t, nil)

	// Create a session and register a pubkey.
	sess, err := f.store.Create(8080, 30001, "localhost", time.Hour, 8, "http", "public", "", "", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubHex := fmt.Sprintf("%x", pub)
	if !f.store.RegisterPubkey(sess.SetupToken, pubHex) {
		t.Fatal("register pubkey failed")
	}

	// Challenge.
	chalReq := httptest.NewRequest(http.MethodGet, "/challenge?pubkey="+pubHex, nil)
	chalRec := httptest.NewRecorder()
	f.handleChallenge(chalRec, chalReq)
	if chalRec.Code != http.StatusOK {
		t.Fatalf("challenge status = %d: %s", chalRec.Code, chalRec.Body.String())
	}
	var chalResp struct {
		Nonce      string `json:"nonce"`
		Subdomain  string `json:"subdomain"`
		ServerPort int    `json:"server_port"`
	}
	if err := json.Unmarshal(chalRec.Body.Bytes(), &chalResp); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if chalResp.Subdomain != sess.Subdomain {
		t.Fatalf("subdomain = %q, want %q", chalResp.Subdomain, sess.Subdomain)
	}

	// Verify.
	sig := ed25519.Sign(priv, []byte(chalResp.Nonce))
	vReq := struct {
		PubKey    string `json:"pubkey"`
		Signature string `json:"signature"`
		Nonce     string `json:"nonce"`
		Subdomain string `json:"subdomain"`
	}{
		PubKey:    pubHex,
		Signature: base64.StdEncoding.EncodeToString(sig),
		Nonce:     chalResp.Nonce,
		Subdomain: sess.Subdomain,
	}
	vBody, _ := json.Marshal(vReq)
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(vBody))
	rec := httptest.NewRecorder()
	f.handleVerify(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d: %s", rec.Code, rec.Body.String())
	}
	var vResp struct {
		Token string `json:"token"`
		Mode  string `json:"mode"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &vResp); err != nil {
		t.Fatalf("decode verify: %v", err)
	}
	if vResp.Token == "" {
		t.Fatal("token empty")
	}
	if vResp.Mode != "http" {
		t.Fatalf("mode = %q, want http", vResp.Mode)
	}
}

func TestHandleVerifyReplayNonce(t *testing.T) {
	f := newTestFrontend(t, nil)
	sess, err := f.store.Create(8080, 30001, "localhost", time.Hour, 8, "http", "public", "", "", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubHex := fmt.Sprintf("%x", pub)
	f.store.RegisterPubkey(sess.SetupToken, pubHex)

	chalReq := httptest.NewRequest(http.MethodGet, "/challenge?pubkey="+pubHex, nil)
	chalRec := httptest.NewRecorder()
	f.handleChallenge(chalRec, chalReq)
	var chalResp struct {
		Nonce string `json:"nonce"`
	}
	json.Unmarshal(chalRec.Body.Bytes(), &chalResp)

	sig := ed25519.Sign(priv, []byte(chalResp.Nonce))
	vReq := struct {
		PubKey    string `json:"pubkey"`
		Signature string `json:"signature"`
		Nonce     string `json:"nonce"`
		Subdomain string `json:"subdomain"`
	}{
		PubKey:    pubHex,
		Signature: base64.StdEncoding.EncodeToString(sig),
		Nonce:     chalResp.Nonce,
		Subdomain: sess.Subdomain,
	}
	vBody, _ := json.Marshal(vReq)
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(vBody))
	rec := httptest.NewRecorder()
	f.handleVerify(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first verify status = %d", rec.Code)
	}
	// Reuse nonce on an activated session returns 409.
	rec2 := httptest.NewRecorder()
	f.handleVerify(rec2, httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(vBody)))
	if rec2.Code != http.StatusConflict {
		t.Fatalf("replay status = %d, want 409", rec2.Code)
	}
}

func TestHandleRegister(t *testing.T) {
	f := newTestFrontend(t, nil)
	sess, err := f.store.Create(8080, 30001, "localhost", time.Hour, 8, "http", "public", "", "", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	body, _ := json.Marshal(map[string]string{
		"setup_token": sess.SetupToken,
		"pubkey":      "abcd1234",
	})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	f.handleRegister(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("body = %s", rec.Body.String())
	}

	// Second registration should fail.
	rec2 := httptest.NewRecorder()
	f.handleRegister(rec2, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
	if rec2.Code != http.StatusConflict {
		t.Fatalf("second status = %d, want 409", rec2.Code)
	}
}

func TestHandleRegenerate(t *testing.T) {
	f := newTestFrontend(t, nil)
	seed := "abandon abandon abandon"
	user := &db.User{
		Username:       "alice",
		APIToken:       "tok123",
		SeedPhraseHash: db.HashSeedPhrase(seed),
		Expire:         time.Now().Add(time.Hour),
		CreatedAt:      time.Now(),
	}
	if err := f.db.CreateUser(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"seed_phrase": seed})
	req := httptest.NewRequest(http.MethodPost, "/regenerate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	f.handleRegenerate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token == "" || resp.Token == "tok123" {
		t.Fatalf("token unchanged: %q", resp.Token)
	}

	// Old token should no longer work.
	if _, err := f.db.GetUserByToken("tok123"); err == nil {
		t.Fatal("old token should be invalid")
	}
	if _, err := f.db.GetUserByToken(resp.Token); err != nil {
		t.Fatalf("new token invalid: %v", err)
	}
}

func TestHandleStatus(t *testing.T) {
	f := newTestFrontend(t, nil)
	sess, err := f.store.Create(8080, 30001, "localhost", time.Hour, 8, "http", "public", "", "", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	f.store.RegisterPubkey(sess.SetupToken, "deadbeef")

	req := httptest.NewRequest(http.MethodGet, "/status?pubkey=deadbeef", nil)
	rec := httptest.NewRecorder()
	f.handleStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"alive":true`) {
		t.Fatalf("body = %s", rec.Body.String())
	}

	rec2 := httptest.NewRecorder()
	f.handleStatus(rec2, httptest.NewRequest(http.MethodGet, "/status?pubkey=unknown", nil))
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec2.Code)
	}
}

func TestProxyTunnelNotFound(t *testing.T) {
	f := newTestFrontend(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "missing.localtest.me"
	rec := httptest.NewRecorder()
	f.proxyTunnel(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestProxyWebSocketNotFound(t *testing.T) {
	f := newTestFrontend(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "missing.localtest.me"
	req.Header.Set("Upgrade", "websocket")
	rec := httptest.NewRecorder()
	f.proxyWebSocket(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestRootHost(t *testing.T) {
	f := newTestFrontend(t, nil)
	if !f.isRootHost("localtest.me") {
		t.Fatal("should be root host")
	}
	if !f.isRootHost("localtest.me:8080") {
		t.Fatal("should be root host with port")
	}
	if f.isRootHost("sub.localtest.me") {
		t.Fatal("should not be root host")
	}
}

func TestHandleRoot(t *testing.T) {
	f := newTestFrontend(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "localtest.me"
	rec := httptest.NewRecorder()
	f.handleRoot(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Locrest") {
		t.Fatalf("body missing Locrest: %s", rec.Body.String())
	}
}

func TestStripErrorParam(t *testing.T) {
	got := stripErrorParam("foo=1&error=json&bar=2")
	if strings.Contains(got, "error") {
		t.Fatalf("error param not stripped: %q", got)
	}
	if !strings.Contains(got, "foo=1") || !strings.Contains(got, "bar=2") {
		t.Fatalf("other params lost: %q", got)
	}
}

func TestSendHTMLError(t *testing.T) {
	f := newTestFrontend(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	f.sendHTMLError(rec, req, http.StatusBadRequest, "Bad", "msg")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Bad") {
		t.Fatalf("body missing title: %s", rec.Body.String())
	}
}

func TestSendJSONError(t *testing.T) {
	f := newTestFrontend(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/?error=json", nil)
	rec := httptest.NewRecorder()
	f.sendHTMLError(rec, req, http.StatusBadRequest, "Bad", "msg")
	if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", rec.Header().Get("Content-Type"))
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if resp["status"] != float64(http.StatusBadRequest) {
		t.Fatalf("status = %v", resp["status"])
	}
}

func TestCheckBasicAuth(t *testing.T) {
	f := newTestFrontend(t, nil)
	sess, err := f.store.Create(8080, 30001, "localhost", time.Hour, 8, "http", "public", "user:pass", "", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	f.RegisterRoute(sess.Subdomain, 30001)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = sess.Subdomain + ".localtest.me"
	rec := httptest.NewRecorder()
	if f.checkBasicAuth(rec, req, sess.Subdomain) {
		t.Fatal("missing auth should be rejected")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Host = sess.Subdomain + ".localtest.me"
	req2.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))
	rec2 := httptest.NewRecorder()
	if !f.checkBasicAuth(rec2, req2, sess.Subdomain) {
		t.Fatal("valid auth should be accepted")
	}
}

func TestCheckAllowedIPs(t *testing.T) {
	f := newTestFrontend(t, nil)
	sess, err := f.store.Create(8080, 30001, "localhost", time.Hour, 8, "http", "public", "", "", []string{"192.168.1.0/24"})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.10:1234"
	req.Host = sess.Subdomain + ".localtest.me"
	rec := httptest.NewRecorder()
	if !f.checkAllowedIPs(rec, req, sess.Subdomain) {
		t.Fatal("allowed IP should pass")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.0.0.1:1234"
	req2.Host = sess.Subdomain + ".localtest.me"
	rec2 := httptest.NewRecorder()
	if f.checkAllowedIPs(rec2, req2, sess.Subdomain) {
		t.Fatal("blocked IP should fail")
	}
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec2.Code)
	}
}

func TestBuildTLSConfigBYO(t *testing.T) {
	f := newTestFrontend(t, nil)
	// Generate a self-signed cert.
	certPath := filepath.Join(t.TempDir(), "cert.pem")
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	if err := generateTestCert(certPath, keyPath); err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	f.cfg.TLS.Cert = certPath
	f.cfg.TLS.Key = keyPath
	cfg, err := f.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected TLS config")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("certificates = %d", len(cfg.Certificates))
	}
}

func TestBuildTLSConfigDisabled(t *testing.T) {
	f := newTestFrontend(t, nil)
	cfg, err := f.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected nil TLS config")
	}
}

func TestBuildTLSConfigMissingFiles(t *testing.T) {
	f := newTestFrontend(t, nil)
	f.cfg.TLS.Cert = "/nonexistent/cert.pem"
	f.cfg.TLS.Key = "/nonexistent/key.pem"
	if _, err := f.buildTLSConfig(); err == nil {
		t.Fatal("expected error for missing cert files")
	}
}

func TestHandlerNotFound(t *testing.T) {
	f := newTestFrontend(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	req.Host = "missing.localtest.me"
	rec := httptest.NewRecorder()
	f.handler(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	f := newTestFrontend(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/challenge", nil)
	req.Host = "localtest.me"
	rec := httptest.NewRecorder()
	f.handler(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestHandlerStatusEndpoint(t *testing.T) {
	f := newTestFrontend(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Host = "localtest.me"
	rec := httptest.NewRecorder()
	f.handler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestHandlerStatusEndpointDisabled(t *testing.T) {
	f := newTestFrontend(t, nil)
	f.cfg.StatusEndpoint = false
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Host = "sub.localtest.me"
	rec := httptest.NewRecorder()
	f.handler(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestChallengeActivated(t *testing.T) {
	f := newTestFrontend(t, nil)
	sess, err := f.store.Create(3000, 0, "localhost", time.Hour, 8, "http", "public", "", "", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubHex := hex.EncodeToString(pubKey)
	if !f.store.RegisterPubkey(sess.SetupToken, pubHex) {
		t.Fatal("register pubkey failed")
	}
	if err := f.store.Activate(sess.SetupToken); err != nil {
		t.Fatalf("activate: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/challenge?pubkey="+pubHex, nil)
	req.Host = "localtest.me"
	rec := httptest.NewRecorder()
	f.handleChallenge(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

func TestBasicAuthCheck(t *testing.T) {
	f := newTestFrontend(t, nil)
	sess, err := f.store.Create(3000, 30001, "localhost", time.Hour, 8, "http", "public", "user:pass", "", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = sess.Subdomain + ".localtest.me"
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))
	rec := httptest.NewRecorder()
	if !f.checkBasicAuth(rec, req, sess.Subdomain) {
		t.Fatal("valid credentials should pass")
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Host = sess.Subdomain + ".localtest.me"
	req2.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:wrong")))
	if f.checkBasicAuth(rec2, req2, sess.Subdomain) {
		t.Fatal("invalid credentials should fail")
	}
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec2.Code)
	}
}

func TestReloadChiselUsers(t *testing.T) {
	f := newTestFrontend(t, nil)
	sess, err := f.store.Create(3000, 30001, "localhost", time.Hour, 8, "http", "public", "", "", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubHex := hex.EncodeToString(pubKey)
	if !f.store.RegisterPubkey(sess.SetupToken, pubHex) {
		t.Fatal("register pubkey failed")
	}
	if err := f.store.Activate(sess.SetupToken); err != nil {
		t.Fatalf("activate: %v", err)
	}

	f.ReloadChiselUsers()

	port, sub, ok := f.resolveRoute(sess.Subdomain + ".localtest.me")
	if !ok {
		t.Fatal("route should be registered after reload")
	}
	if port != sess.ServerPort || sub != sess.Subdomain {
		t.Fatalf("got port=%d sub=%q, want port=%d sub=%q", port, sub, sess.ServerPort, sess.Subdomain)
	}
}

func generateTestCert(certPath, keyPath string) error {
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-days", "1", "-nodes", "-subj", "/CN=test")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("openssl: %w: %s", err, out)
	}
	return nil
}
