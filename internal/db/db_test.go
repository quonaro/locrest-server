package db

import (
	"os"
	"testing"
	"time"
)

func TestUserCRUD(t *testing.T) {
	path := "test_users.db"
	defer os.Remove(path)

	db, err := Open(path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	u := &User{
		Username:       "alice",
		APIToken:       "tok123",
		SeedPhraseHash: HashSeedPhrase("abandon abandon abandon"),
		Expire:         time.Now().Add(24 * time.Hour),
		CreatedAt:      time.Now(),
	}
	if err := db.CreateUser(u); err != nil {
		t.Fatalf("create user: %v", err)
	}

	byTok, err := db.GetUserByToken("tok123")
	if err != nil {
		t.Fatalf("get by token: %v", err)
	}
	if byTok.Username != "alice" {
		t.Fatalf("expected alice, got %s", byTok.Username)
	}

	bySeed, err := db.GetUserBySeedHash(u.SeedPhraseHash)
	if err != nil {
		t.Fatalf("get by seed: %v", err)
	}
	if bySeed.Username != "alice" {
		t.Fatalf("expected alice, got %s", bySeed.Username)
	}

	if err := db.UpdateUserToken("alice", "newtok"); err != nil {
		t.Fatalf("update token: %v", err)
	}
	_, err = db.GetUserByToken("tok123")
	if err == nil {
		t.Fatal("old token should be invalid")
	}
	byNew, err := db.GetUserByToken("newtok")
	if err != nil {
		t.Fatalf("get by new token: %v", err)
	}
	if byNew.APIToken != "newtok" {
		t.Fatalf("expected newtok, got %s", byNew.APIToken)
	}
}

func TestSessionCRUD(t *testing.T) {
	path := "test_sessions.db"
	defer os.Remove(path)

	db, err := Open(path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	sess, err := db.CreateSession(8080, 30001, "localhost", time.Hour, 8, "http", "public")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if sess.Subdomain == "" {
		t.Fatal("subdomain should not be empty")
	}

	got, ok := db.GetSession(sess.SetupToken)
	if !ok {
		t.Fatal("session not found by setup token")
	}
	if got.Subdomain != sess.Subdomain {
		t.Fatalf("expected %s, got %s", sess.Subdomain, got.Subdomain)
	}

	if !db.RegisterPubkey(sess.SetupToken, "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234") {
		t.Fatal("register pubkey failed")
	}

	byPub, ok := db.GetSessionByPubkey("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	if !ok {
		t.Fatal("session not found by pubkey")
	}
	if byPub.Subdomain != sess.Subdomain {
		t.Fatalf("expected %s, got %s", sess.Subdomain, byPub.Subdomain)
	}

	bySub, ok := db.GetSessionBySubdomain(sess.Subdomain)
	if !ok {
		t.Fatal("session not found by subdomain")
	}
	if bySub.SetupToken != sess.SetupToken {
		t.Fatalf("expected %s, got %s", sess.SetupToken, bySub.SetupToken)
	}

	db.DeleteSession(sess.SetupToken)
	_, ok = db.GetSession(sess.SetupToken)
	if ok {
		t.Fatal("session should be deleted")
	}
}
