package embedbin

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
)

//go:embed bin/*
var binFS embed.FS

var checksums = make(map[string]string)

func init() {
	entries, err := binFS.ReadDir("bin")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "locrest-client-") {
			continue
		}
		f, err := binFS.Open("bin/" + entry.Name())
		if err != nil {
			continue
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			continue
		}
		f.Close()
		checksums[entry.Name()] = hex.EncodeToString(h.Sum(nil))
	}
}

// ServeBinary serves an embedded client binary matching the requested OS/arch.
func ServeBinary(w http.ResponseWriter, r *http.Request) {
	fileName := path.Base(r.URL.Path)
	if !strings.HasPrefix(fileName, "locrest-client-") {
		http.NotFound(w, r)
		return
	}

	f, err := binFS.Open("bin/" + fileName)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	stat, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	if stat != nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	}

	io.Copy(w, f)
}

// ServeChecksum serves the SHA-256 hex checksum for a binary.
func ServeChecksum(w http.ResponseWriter, r *http.Request) {
	fileName := strings.TrimSuffix(path.Base(r.URL.Path), ".sha256")
	if !strings.HasPrefix(fileName, "locrest-client-") {
		http.NotFound(w, r)
		return
	}
	sum, ok := checksums[fileName]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(sum))
}

// NewHandler returns an http.HandlerFunc that routes /bin/ requests.
// When dev is false and binaryURL is non-empty, it redirects to the external URL.
// Otherwise it serves embedded binaries directly.
func NewHandler(dev bool, binaryURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fileName := path.Base(r.URL.Path)
		if !strings.HasPrefix(fileName, "locrest-client-") {
			http.NotFound(w, r)
			return
		}

		if !dev && binaryURL != "" {
			target := strings.TrimRight(binaryURL, "/") + "/" + fileName
			http.Redirect(w, r, target, http.StatusTemporaryRedirect)
			return
		}

		if strings.HasSuffix(r.URL.Path, ".sha256") {
			ServeChecksum(w, r)
		} else {
			ServeBinary(w, r)
		}
	}
}

// Handler routes /bin/ requests to either ServeBinary or ServeChecksum.
var Handler = NewHandler(true, "")
