package script

import (
	"fmt"
	"strings"
	"text/template"
	"time"

	"locrest-server/internal/auth"
)

// UserAgent constants for platform detection.
const (
	OSLinux  = "linux"
	OSDarwin = "darwin"
)

// DetectOS returns the target OS based on the User-Agent header.
func DetectOS(ua string) string {
	ua = strings.ToLower(ua)
	if strings.Contains(ua, "darwin") || strings.Contains(ua, "mac") {
		return OSDarwin
	}
	return OSLinux
}

// Params contains everything needed to render the one-liner script.
type Params struct {
	ServerURL   string
	WSServerURL string
	Subdomain   string
	LocalPort   int
	TargetHost  string
	SetupToken  string
	TokenTTL    time.Duration
	OS          string
	BinaryName  string
	ExtraFlags  string
}

func wsURL(httpURL string) string {
	if strings.HasPrefix(httpURL, "https://") {
		return "wss://" + strings.TrimPrefix(httpURL, "https://")
	}
	if strings.HasPrefix(httpURL, "http://") {
		return "ws://" + strings.TrimPrefix(httpURL, "http://")
	}
	return httpURL
}

func shellEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"', '$', '`', '\\':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

var scriptTemplate = template.Must(template.New("install").Parse(`#!/bin/sh
set -e

# Locrest ephemeral tunnel client
OS="{{.OS}}"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
esac

BIN_NAME="locrest-client-${OS}-${ARCH}"
URL="{{.ServerURL}}/bin/${BIN_NAME}"
CHECKSUM_URL="{{.ServerURL}}/bin/${BIN_NAME}.sha256"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

curl -fsSL -o "$TMP" "$URL" || wget -q -O "$TMP" "$URL"

EXPECTED=$(curl -fsSL "$CHECKSUM_URL" || wget -q -O - "$CHECKSUM_URL")
ACTUAL=$(sha256sum "$TMP" | awk '{print $1}')
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "Checksum verification failed" >&2
  exit 1
fi

# Install to a writable persistent location (handles noexec /tmp)
CACHE_DIR="${HOME}/.cache/locrest"
if [ ! -d "$CACHE_DIR" ]; then
  mkdir -p "$CACHE_DIR"
fi
BIN="$CACHE_DIR/$BIN_NAME"
cp "$TMP" "$BIN"
chmod +x "$BIN"

# Hide sensitive values from process listings
export LOCREST_SUBDOMAIN="{{.Subdomain}}"
export LOCREST_SETUP_TOKEN="{{.SetupToken}}"

# Supervisor loop with exponential backoff
BACKOFF=1
MAX_BACKOFF=30
while true; do
  if "$BIN" \
    -server "{{.WSServerURL}}/tunnel" \
    -port {{.LocalPort}} \
    -token-ttl "{{.TokenTTL}}"{{if ne .TargetHost "localhost"}} \
    -host "{{.TargetHost}}"{{end}}{{.ExtraFlags}}; then
    BACKOFF=1
  else
    echo "locrest-client exited ($?), restarting in ${BACKOFF}s..." >&2
    sleep "$BACKOFF"
    BACKOFF=$((BACKOFF * 2))
    if [ "$BACKOFF" -gt "$MAX_BACKOFF" ]; then
      BACKOFF=$MAX_BACKOFF
    fi
  fi
done
`))

// Generate returns a rendered shell script for the given session.
func Generate(serverURL string, sess *auth.Session, ua string, flags map[string]string, tokenTTL time.Duration) (string, error) {
	os := DetectOS(ua)
	serverURL = strings.TrimRight(serverURL, "/")
	extra := ""
	if flags["debug"] == "true" {
		extra = " -debug"
	}
	p := Params{
		ServerURL:   shellEscape(serverURL),
		WSServerURL: shellEscape(wsURL(serverURL)),
		Subdomain:   shellEscape(sess.Subdomain),
		LocalPort:   sess.LocalPort,
		TargetHost:  shellEscape(sess.TargetHost),
		SetupToken:  sess.SetupToken,
		TokenTTL:    tokenTTL,
		OS:          shellEscape(os),
		BinaryName:  "locrest-client",
		ExtraFlags:  extra,
	}
	var buf strings.Builder
	if err := scriptTemplate.Execute(&buf, p); err != nil {
		return "", fmt.Errorf("template: %w", err)
	}
	return buf.String(), nil
}
