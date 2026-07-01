package server

import (
	"path/filepath"
	"testing"
	"time"

	"locrest-server/internal/auth"
	"locrest-server/internal/chiselwrapper"
	"locrest-server/internal/config"
	"locrest-server/internal/db"
)

func TestCleanupKeepsActiveSessionOnDisconnect(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Network.Domain = "localtest.me"
	cfg.Tunnel.TTL = time.Hour

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

	if _, ok := store.Get(sess.SetupToken); !ok {
		t.Fatal("active session should not be deleted by cleanup")
	}
	if _, _, ok := f.resolveRoute(sess.Subdomain + ".localtest.me"); !ok {
		t.Fatal("route should not be deleted by cleanup")
	}
}
