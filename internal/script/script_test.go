package script

import (
	"strings"
	"testing"
	"time"

	"locrest-server/internal/auth"
)

func TestDetectOS(t *testing.T) {
	tests := []struct {
		ua   string
		want string
	}{
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", OSDarwin},
		{"curl/7.68.0", OSLinux},
		{"Wget/1.20.3 (linux-gnu)", OSLinux},
		{"Mozilla/5.0 (X11; Linux x86_64)", OSLinux},
		{"", OSLinux},
	}
	for _, tt := range tests {
		if got := DetectOS(tt.ua); got != tt.want {
			t.Fatalf("DetectOS(%q) = %q, want %q", tt.ua, got, tt.want)
		}
	}
}

func TestWsURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://example.com", "wss://example.com"},
		{"https://example.com/", "wss://example.com/"},
		{"http://example.com", "ws://example.com"},
		{"http://example.com/path", "ws://example.com/path"},
		{"ws://example.com", "ws://example.com"},
		{"wss://example.com", "wss://example.com"},
	}
	for _, tt := range tests {
		if got := wsURL(tt.in); got != tt.want {
			t.Fatalf("wsURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestShellEscape(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"hello", "hello"},
		{"say \"hi\"", "say \\\"hi\\\""},
		{"$HOME", "\\$HOME"},
		{"`cmd`", "\\`cmd\\`"},
		{"a\nb", "a\\\nb"},
	}
	for _, tt := range tests {
		if got := shellEscape(tt.in); got != tt.want {
			t.Fatalf("shellEscape(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestGenerate(t *testing.T) {
	sess := &auth.Session{
		Subdomain:  "testsub",
		LocalPort:  8080,
		TargetHost: "localhost",
		SetupToken: "setuptoken123",
		HTTPAuth:   "user:pass",
	}
	scr, err := Generate("https://example.com", "https://cdn.example.com", sess, "curl/7.68.0", nil, time.Hour, false)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.HasPrefix(scr, "#!/bin/sh") {
		t.Fatalf("script should start with shebang, got: %q", scr[:50])
	}
	for _, want := range []string{
		"testsub",
		"setuptoken123",
		"https://cdn.example.com",
		"wss://example.com/tunnel",
		"8080",
		"user:pass",
		"Basic Auth",
	} {
		if !strings.Contains(scr, want) {
			t.Fatalf("script missing %q", want)
		}
	}
}

func TestGenerateDebugFlag(t *testing.T) {
	sess := &auth.Session{
		Subdomain:  "testsub",
		LocalPort:  8080,
		TargetHost: "localhost",
		SetupToken: "setuptoken123",
	}
	scr, err := Generate("https://example.com", "", sess, "wget/1.20.3", map[string]string{"debug": "true"}, time.Hour, false)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(scr, "-debug") {
		t.Fatal("debug flag should appear in script")
	}
	if !strings.Contains(scr, "https://example.com") {
		t.Fatal("binary URL should fall back to server URL")
	}
}

func TestGenerateEscapes(t *testing.T) {
	sess := &auth.Session{
		Subdomain:  "sub",
		LocalPort:  8080,
		TargetHost: "127.0.0.1",
		SetupToken: "token",
		HTTPAuth:   "user:pass",
	}
	scr, err := Generate("https://example.com/path", "https://bin.example.com", sess, "", nil, 30*time.Minute, false)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// server URL should have trailing slash removed
	if strings.Contains(scr, "https://example.com/path//") {
		t.Fatal("trailing slash not trimmed")
	}
}

func TestGenerateInfinity(t *testing.T) {
	sess := &auth.Session{
		Subdomain:  "infsub",
		LocalPort:  8080,
		TargetHost: "localhost",
		SetupToken: "token",
	}
	scr, err := Generate("https://example.com", "", sess, "curl/7.68.0", nil, 0, true)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if strings.Contains(scr, "-token-ttl") {
		t.Fatal("infinite script should not contain token-ttl flag")
	}
	if !strings.Contains(scr, "infsub") {
		t.Fatal("script missing subdomain")
	}
}
