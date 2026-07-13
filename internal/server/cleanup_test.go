package server

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"locrest-server/internal/auth"
	"locrest-server/internal/chiselwrapper"
	"locrest-server/internal/config"
	"locrest-server/internal/db"
)

func TestCleanupRemovesDisconnectedHTTPSession(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Network.Domain = "localtest.me"
	cfg.Tunnel.TTL = time.Hour
	cfg.Tunnel.ActivationGracePeriod = 0

	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	store := auth.NewStore(database)
	chisel, err := chiselwrapper.New("")
	if err != nil {
		t.Fatalf("new chisel: %v", err)
	}
	f := NewFrontend(cfg, store, chisel, database, "", "")

	sess, err := store.Create(8080, 30001, "localhost", time.Hour, false, 8, "http", "public", "", "", nil, "")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := store.Activate(sess.SetupToken); err != nil {
		t.Fatalf("activate: %v", err)
	}
	f.RegisterRoute(sess.Subdomain, sess.ServerPort)

	f.cleanStaleRoutesAndSessions()

	if _, ok := store.Get(sess.SetupToken); ok {
		t.Fatal("disconnected http session should be deleted by cleanup")
	}
	if _, _, ok := f.resolveRoute(sess.Subdomain + ".localtest.me"); ok {
		t.Fatal("route should be deleted when pipe is missing")
	}
}

func TestCleanupKeepsFreshlyActivatedHTTPSession(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Network.Domain = "localtest.me"
	cfg.Tunnel.TTL = time.Hour
	cfg.Tunnel.ActivationGracePeriod = time.Minute

	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	store := auth.NewStore(database)
	chisel, err := chiselwrapper.New("")
	if err != nil {
		t.Fatalf("new chisel: %v", err)
	}
	f := NewFrontend(cfg, store, chisel, database, "", "")

	sess, err := store.Create(8080, 30005, "localhost", time.Hour, false, 8, "http", "public", "", "", nil, "")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := store.Activate(sess.SetupToken); err != nil {
		t.Fatalf("activate: %v", err)
	}
	f.RegisterRoute(sess.Subdomain, sess.ServerPort)

	f.cleanStaleRoutesAndSessions()

	if _, ok := store.Get(sess.SetupToken); !ok {
		t.Fatal("freshly activated http session should not be deleted during grace period")
	}
	if _, _, ok := f.resolveRoute(sess.Subdomain + ".localtest.me"); !ok {
		t.Fatal("route should still exist during grace period")
	}
}

func TestCleanupRemovesDisconnectedTCPPort(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Network.Domain = "localtest.me"
	cfg.Tunnel.TTL = time.Hour
	cfg.Tunnel.ActivationGracePeriod = 0

	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	store := auth.NewStore(database)
	chisel, err := chiselwrapper.New("")
	if err != nil {
		t.Fatalf("new chisel: %v", err)
	}
	f := NewFrontend(cfg, store, chisel, database, "", "")

	sess, err := store.Create(8080, 30002, "localhost", time.Hour, false, 8, "tcp", "public", "", "", nil, "")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := store.Activate(sess.SetupToken); err != nil {
		t.Fatalf("activate: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:30002")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	f.tcpListeners[30002] = ln

	// No proxy pipe registered -> tunnel is considered disconnected.
	f.cleanStaleRoutesAndSessions()

	if _, ok := store.Get(sess.SetupToken); ok {
		t.Fatal("disconnected tcp session should be deleted by cleanup")
	}
	if f.isPortInUse(30002) {
		t.Fatal("tcp port should be freed after disconnect cleanup")
	}
}
