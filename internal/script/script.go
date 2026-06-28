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
	ServerURL   string
	WSServerURL string
	Subdomain   string
	LocalPort   int
	TargetHost  string
	PrivateKey  string
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
trap "rm -f $TMP" EXIT

curl -fsSL -o "$TMP" "$URL" || wget -q -O "$TMP" "$URL"
chmod +x "$TMP"
exec "$TMP" \
  -server "{{.WSServerURL}}/tunnel" \
  -port {{.LocalPort}} \
  -subdomain "{{.Subdomain}}" \
  -key "{{.PrivateKey}}"{{if ne .TargetHost "localhost"}} \
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
		ServerURL:   serverURL,
		WSServerURL: wsURL(serverURL),
		Subdomain:   sess.Subdomain,
		LocalPort:   sess.LocalPort,
		TargetHost:  sess.TargetHost,
		PrivateKey:  sess.PrivateKeyHex(),
		OS:          os,
		BinaryName:  "locrest-client",
		ExtraFlags:  extra,
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
