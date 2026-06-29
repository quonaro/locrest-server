package script

import (
	"fmt"
	"strings"
	"text/template"

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
	ServerURL      string
	WSServerURL    string
	Subdomain      string
	LocalPort      int
	TargetHost     string
	RetrievalToken string
	OS             string
	BinaryName     string
	ExtraFlags     string
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

URL="{{.ServerURL}}/bin/locrest-client-${OS}-${ARCH}"
TMP=$(mktemp)
KEYFILE=$(mktemp)
trap 'rm -f "$TMP" "$KEYFILE"' EXIT

curl -fsSL -o "$TMP" "$URL" || wget -q -O "$TMP" "$URL"
chmod +x "$TMP"

curl -fsSL "{{.ServerURL}}/key/{{.RetrievalToken}}" > "$KEYFILE"
chmod 600 "$KEYFILE"

exec "$TMP" \
  -server "{{.WSServerURL}}/tunnel" \
  -port {{.LocalPort}} \
  -subdomain "{{.Subdomain}}" \
  -keyfile "$KEYFILE"{{if ne .TargetHost "localhost"}} \
  -host "{{.TargetHost}}"{{end}}{{.ExtraFlags}}
`))

// Generate returns a rendered shell script for the given session.
func Generate(serverURL string, sess *auth.Session, ua string, flags map[string]string) (string, error) {
	os := DetectOS(ua)
	serverURL = strings.TrimRight(serverURL, "/")
	extra := ""
	if flags["debug"] == "true" {
		extra = " -debug"
	}
	p := Params{
		ServerURL:      shellEscape(serverURL),
		WSServerURL:    shellEscape(wsURL(serverURL)),
		Subdomain:      shellEscape(sess.Subdomain),
		LocalPort:      sess.LocalPort,
		TargetHost:     shellEscape(sess.TargetHost),
		RetrievalToken: sess.RetrievalToken,
		OS:             shellEscape(os),
		BinaryName:     "locrest-client",
		ExtraFlags:     extra,
	}
	var buf strings.Builder
	if err := scriptTemplate.Execute(&buf, p); err != nil {
		return "", fmt.Errorf("template: %w", err)
	}
	return buf.String(), nil
}

// OneLiner returns a single-line curl | bash command.
func OneLiner(serverURL, subdomain string, localPort int, privKey, ua string) string {
	return fmt.Sprintf(
		"curl -fsSL %s/install/%s | bash",
		strings.TrimRight(serverURL, "/"),
		subdomain,
	)
}
