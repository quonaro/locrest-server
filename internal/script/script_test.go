package script

import (
	"strings"
	"testing"
	"time"

	"locrest-server/internal/auth"
	"locrest-server/internal/binary"
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
	scr, err := Generate("https://example.com", "", sess, "curl/7.68.0", nil, time.Hour, false, false, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.HasPrefix(scr, "#!/bin/sh") {
		t.Fatalf("script should start with shebang, got: %q", scr[:50])
	}
	for _, want := range []string{
		"testsub",
		"setuptoken123",
		"https://example.com/bin/${BIN_NAME}",
		"wss://example.com/tunnel",
		"8080",
		"user:pass",
		"Basic Auth",
		"NEED_DOWNLOAD",
		"rm -f \"$BIN\"",
		"mv \"$TMP\" \"$BIN\"",
	} {
		if !strings.Contains(scr, want) {
			t.Fatalf("script missing %q", want)
		}
	}
}

func TestGenerateChecksums(t *testing.T) {
	sess := &auth.Session{
		Subdomain:  "testsub",
		LocalPort:  8080,
		TargetHost: "localhost",
		SetupToken: "setuptoken123",
	}
	bins := []binary.FileInfo{
		{Name: "lrc-linux-amd64", SHA256: "abc123deadbeef"},
		{Name: "lrc-darwin-arm64", SHA256: "deadbeefabc123"},
	}
	scr, err := Generate("https://example.com", "", sess, "curl/7.68.0", nil, time.Hour, false, false, bins)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(scr, "linux_amd64)") {
		t.Fatal("script missing linux_amd64 case")
	}
	if !strings.Contains(scr, "abc123deadbeef") {
		t.Fatal("script missing linux-amd64 checksum")
	}
	if !strings.Contains(scr, "darwin_arm64)") {
		t.Fatal("script missing darwin_arm64 case")
	}
	if !strings.Contains(scr, "deadbeefabc123") {
		t.Fatal("script missing darwin-arm64 checksum")
	}
}

func TestGenerateDebugFlag(t *testing.T) {
	sess := &auth.Session{
		Subdomain:  "testsub",
		LocalPort:  8080,
		TargetHost: "localhost",
		SetupToken: "setuptoken123",
	}
	scr, err := Generate("https://example.com", "", sess, "wget/1.20.3", map[string]string{"debug": "true"}, time.Hour, false, false, nil)
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
	scr, err := Generate("https://example.com/path", "", sess, "", nil, 30*time.Minute, false, false, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// server URL should have trailing slash removed
	if strings.Contains(scr, "https://example.com/path//") {
		t.Fatal("trailing slash not trimmed")
	}
}

func TestGenerateInsecureURL(t *testing.T) {
	sess := &auth.Session{
		Subdomain:  "testsub",
		LocalPort:  8080,
		TargetHost: "localhost",
		SetupToken: "setuptoken123",
	}
	scr, err := Generate("https://example.com", "http://example.com", sess, "curl/7.68.0", nil, time.Hour, false, false, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(scr, `-insecure-url "ws://example.com/tunnel"`) {
		t.Fatalf("script missing insecure-url flag: %q", scr)
	}
	if !strings.Contains(scr, `https://example.com/bin/${BIN_NAME}`) {
		t.Fatal("script should use HTTPS for binary download")
	}
}

func TestGenerateInfinity(t *testing.T) {
	sess := &auth.Session{
		Subdomain:  "infsub",
		LocalPort:  8080,
		TargetHost: "localhost",
		SetupToken: "token",
	}
	scr, err := Generate("https://example.com", "", sess, "curl/7.68.0", nil, 0, true, false, nil)
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

func TestGenerateDaemon(t *testing.T) {
	sess := &auth.Session{
		Subdomain:  "daemon-sub",
		LocalPort:  8080,
		TargetHost: "localhost",
		SetupToken: "token",
	}
	scr, err := Generate("https://example.com", "", sess, "curl/7.68.0", nil, time.Hour, false, true, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(scr, "-supervisor") {
		t.Fatal("daemon script should start supervisor")
	}
	if !strings.Contains(scr, "$BIN add") {
		t.Fatal("daemon script should use 'add' command")
	}
	if !strings.Contains(scr, "lrc list") {
		t.Fatal("daemon script should show 'lrc list' to user")
	}
	if strings.Contains(scr, "while true") {
		t.Fatal("daemon script should not have foreground loop")
	}
	if !strings.Contains(scr, "INSTALL_DIR") {
		t.Fatal("daemon script should install lrc to PATH")
	}
	if !strings.Contains(scr, "rm -f \"$INSTALL_DIR/lrc\"") {
		t.Fatal("daemon script should remove old binary before copying to INSTALL_DIR")
	}
	if !strings.Contains(scr, "cp -f \"$BIN\" \"$INSTALL_DIR/lrc\"") {
		t.Fatal("daemon script should copy binary to INSTALL_DIR")
	}
	if strings.Contains(scr, "Failed to start supervisor") {
		t.Fatal("daemon script should not contain the old broken 'Failed to start supervisor' check")
	}
	if !strings.Contains(scr, "\"$BIN\" -supervisor >/dev/null 2>&1 &\nSUP_PID=$!") {
		t.Fatal("daemon script should start supervisor in background directly")
	}
}
