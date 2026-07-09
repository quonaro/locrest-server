package server

import (
	"testing"
	"time"

	tunnel "locrest-server/internal/chiselvendor/tunnel"
)

func TestWaitProxyPipeAppears(t *testing.T) {
	f := newTestFrontend(t, nil)
	port := 39001

	start := time.Now()
	if ch := f.waitProxyPipe(port, "tcp"); ch != nil {
		t.Fatal("expected nil pipe before registration")
	}
	if elapsed := time.Since(start); elapsed < 450*time.Millisecond {
		t.Fatalf("wait loop returned too early: %v", elapsed)
	}

	tunnel.RegisterProxyPipe(port, "tcp", tunnel.NewTestPipeListener())
	t.Cleanup(func() { tunnel.UnregisterProxyPipe(port, "tcp") })

	start = time.Now()
	if ch := f.waitProxyPipe(port, "tcp"); ch == nil {
		t.Fatal("expected pipe to be found")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("wait loop took too long after registration: %v", elapsed)
	}
}

func TestCleanStaleHTTPRouteRemovesSession(t *testing.T) {
	f := newTestFrontend(t, nil)
	sess, err := f.store.Create(8080, 30001, "localhost", time.Hour, false, 8, "http", "public", "", "", nil, "")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := f.store.Activate(sess.SetupToken); err != nil {
		t.Fatalf("activate: %v", err)
	}

	f.RegisterRoute(sess.Subdomain, sess.ServerPort)
	if _, _, ok := f.resolveRoute(sess.Subdomain + ".localtest.me"); !ok {
		t.Fatal("route should exist")
	}

	// Pipe is missing: route and session should be removed.
	f.cleanStaleRoutesAndSessions()
	if _, _, ok := f.resolveRoute(sess.Subdomain + ".localtest.me"); ok {
		t.Fatal("route should be removed when pipe is missing")
	}
	if _, ok := f.store.Get(sess.SetupToken); ok {
		t.Fatal("session should be deleted when pipe is missing")
	}
}
