package script

import (
	"fmt"
	"strings"
	"text/template"
	"time"

	"locrest-server/internal/auth"
	"locrest-server/internal/binary"
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
	ServerURL     string
	WSServerURL   string
	InsecureURL   string
	WSInsecureURL string
	Subdomain     string
	LocalPort     int
	TargetHost    string
	SetupToken    string
	TokenTTL      time.Duration
	OS            string
	BinaryName    string
	ExtraFlags    string
	HTTPAuth      string
	Infinity      bool
	Daemon        bool
	Checksums     map[string]string
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
		case '"', '$', '`', '\\', '\n', '\r':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

var scriptTemplate = template.Must(template.New("install").Parse(`#!/bin/sh
set -e

# Locrest ephemeral tunnel client
trap 'echo "Interrupted" >&2; exit 0' INT TERM

OS="{{.OS}}"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
esac

BIN_NAME="lrc-${OS}-${ARCH}"
URL="{{.ServerURL}}/bin/${BIN_NAME}"

# Install to a writable persistent location (handles noexec /tmp)
CACHE_DIR="${HOME}/.cache/locrest"
if [ ! -d "$CACHE_DIR" ]; then
  mkdir -p "$CACHE_DIR"
fi
BIN="$CACHE_DIR/$BIN_NAME"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# Pick the right sha256 command once
if command -v sha256sum >/dev/null 2>&1; then
  SHA256_CMD="sha256sum"
else
  SHA256_CMD="shasum -a 256"
fi

EXPECTED=""
case "${OS}_${ARCH}" in
{{range $plat, $hash := .Checksums}}  {{$plat}}) EXPECTED="{{$hash}}" ;;
{{end}}esac

NEED_DOWNLOAD=1
if [ -f "$BIN" ] && [ -n "$EXPECTED" ]; then
  GOT=$($SHA256_CMD "$BIN" | awk '{print $1}')
  if [ "$GOT" = "$EXPECTED" ]; then
    NEED_DOWNLOAD=0
  fi
fi

if [ "$NEED_DOWNLOAD" = "1" ]; then
  echo "Downloading client binary..." >&2
  if ! curl -fsSL -o "$TMP" "$URL" 2>/dev/null && ! wget -q -O "$TMP" "$URL" 2>/dev/null; then
    echo "Failed to download client binary: $URL" >&2
    exit 1
  fi
  if [ -n "$EXPECTED" ]; then
    GOT=$($SHA256_CMD "$TMP" | awk '{print $1}')
    if [ "$GOT" != "$EXPECTED" ]; then
      echo "Binary checksum mismatch" >&2
      exit 1
    fi
  fi
  cp "$TMP" "$BIN"
  chmod +x "$BIN"
fi

# Ensure lrc is available in PATH
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
if [ "$(id -u)" -ne 0 ] && [ "$INSTALL_DIR" = "/usr/local/bin" ]; then
  INSTALL_DIR="${HOME}/.local/bin"
fi
if [ -d "$INSTALL_DIR" ]; then
  cp "$BIN" "$INSTALL_DIR/lrc"
  chmod +x "$INSTALL_DIR/lrc"
else
  mkdir -p "$INSTALL_DIR"
  cp "$BIN" "$INSTALL_DIR/lrc"
  chmod +x "$INSTALL_DIR/lrc"
fi
if ! command -v lrc >/dev/null 2>&1; then
  echo "add $INSTALL_DIR to your PATH, e.g. export PATH=\"$INSTALL_DIR:\$PATH\""
fi

# Hide sensitive values from process listings
export LOCREST_SUBDOMAIN="{{.Subdomain}}"
export LOCREST_SETUP_TOKEN="{{.SetupToken}}"

{{if ne .HTTPAuth ""}}
echo "Tunnel URL: {{.ServerURL}} (Basic Auth: {{.HTTPAuth}})"
{{end}}
{{if .Daemon}}
# Daemon mode: start supervisor in background, then add tunnel
if ! "$BIN" -supervisor >/dev/null 2>&1 &
then
  echo "Failed to start supervisor" >&2
  exit 1
fi
SUP_PID=$!
sleep 2
if ! kill -0 "$SUP_PID" 2>/dev/null; then
  echo "Supervisor failed to start" >&2
  exit 1
fi

RES=$($BIN add \
  -server "{{.WSServerURL}}/tunnel" \
  -port {{.LocalPort}} \
  -subdomain "{{.Subdomain}}" \
{{if ne .WSInsecureURL ""}}  -insecure-url "{{.WSInsecureURL}}/tunnel" \
{{end}}{{if not .Infinity}}  -token-ttl "{{.TokenTTL}}" \
{{end}}{{if ne .TargetHost "localhost"}}  -host "{{.TargetHost}}" \
{{end}}{{if ne .ExtraFlags ""}}  {{.ExtraFlags}} \
{{end}}  2>&1)

if [ $? -ne 0 ]; then
  echo "Failed to add tunnel: $RES" >&2
  exit 1
fi

echo ""
echo "Tunnel registered in background."
echo ""
echo "Manage with:"
echo "  lrc list              # show all tunnels"
echo "  lrc kill <id>         # stop a tunnel"
echo "  lrc status <id>       # show tunnel details"
echo "  lrc logs <id>         # show tunnel logs"
{{else}}
# Supervisor loop with exponential backoff
BACKOFF=1
MAX_BACKOFF=30
ORANGE='\033[38;5;208m'
RESET='\033[0m'
while true; do
  if "$BIN" \
    -server "{{.WSServerURL}}/tunnel" \
    -port {{.LocalPort}} \
{{if ne .WSInsecureURL ""}}    -insecure-url "{{.WSInsecureURL}}/tunnel" \
{{end}}{{if not .Infinity}}    -token-ttl "{{.TokenTTL}}" \
{{end}}{{if ne .TargetHost "localhost"}}    -host "{{.TargetHost}}" \
{{end}}{{if ne .ExtraFlags ""}}    {{.ExtraFlags}} \
{{end}}; then
    BACKOFF=1
  else
    EXIT_CODE=$?
    if [ "$EXIT_CODE" -eq 2 ]; then
      exit "$EXIT_CODE"
    fi
    printf "${ORANGE}Exited (%d), retrying in %ds...${RESET}\n" "$EXIT_CODE" "$BACKOFF" >&2
    sleep "$BACKOFF"
    BACKOFF=$((BACKOFF * 2))
    if [ "$BACKOFF" -gt "$MAX_BACKOFF" ]; then
      BACKOFF=$MAX_BACKOFF
    fi
  fi
done
{{end}}
`))

// Generate returns a rendered shell script for the given session.
func Generate(serverURL, insecureURL string, sess *auth.Session, ua string, flags map[string]string, tokenTTL time.Duration, infinity, daemon bool, binaries []binary.FileInfo) (string, error) {
	os := DetectOS(ua)
	serverURL = strings.TrimRight(serverURL, "/")
	extra := ""
	if flags["debug"] == "true" {
		extra = "-debug"
	}
	checksums := make(map[string]string)
	for _, fi := range binaries {
		plat := strings.TrimPrefix(fi.Name, "lrc-")
		key := strings.ReplaceAll(plat, "-", "_")
		checksums[key] = fi.SHA256
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
		BinaryName:  "lrc",
		ExtraFlags:  extra,
		HTTPAuth:    shellEscape(sess.HTTPAuth),
		Infinity:    infinity,
		Daemon:      daemon,
		Checksums:   checksums,
	}
	if insecureURL != "" {
		p.InsecureURL = shellEscape(strings.TrimRight(insecureURL, "/"))
		p.WSInsecureURL = shellEscape(wsURL(insecureURL))
	}
	var buf strings.Builder
	if err := scriptTemplate.Execute(&buf, p); err != nil {
		return "", fmt.Errorf("template: %w", err)
	}
	return buf.String(), nil
}
