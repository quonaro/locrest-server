package embedbin

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed bin
var binFS embed.FS

// staticFS is the filesystem used by the handlers. Tests may replace it with a directory FS.
var staticFS fs.FS = binFS

var checksums = make(map[string]string)

func init() {
	initChecksums()
}

func initChecksums() {
	checksums = make(map[string]string)
	entries, err := fs.ReadDir(staticFS, "bin")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "lrc-") {
			continue
		}
		f, err := staticFS.Open("bin/" + entry.Name())
		if err != nil {
			continue
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			_ = f.Close()
			continue
		}
		_ = f.Close()
		checksums[entry.Name()] = hex.EncodeToString(h.Sum(nil))
	}
}

// ServeBinary serves an embedded client binary matching the requested OS/arch.
func ServeBinary(w http.ResponseWriter, r *http.Request) {
	fileName := path.Base(r.URL.Path)
	if !strings.HasPrefix(fileName, "lrc-") {
		http.NotFound(w, r)
		return
	}

	f, err := staticFS.Open("bin/" + fileName)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = f.Close() }()

	stat, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	if stat != nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	}

	_, _ = io.Copy(w, f)
}

// ServeChecksum serves the SHA-256 hex checksum for a binary.
func ServeChecksum(w http.ResponseWriter, r *http.Request) {
	fileName := strings.TrimSuffix(path.Base(r.URL.Path), ".sha256")
	if !strings.HasPrefix(fileName, "lrc-") {
		http.NotFound(w, r)
		return
	}
	sum, ok := checksums[fileName]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(sum))
}

// NewHandler returns an http.HandlerFunc that routes /bin/ requests.
// When binaryURL is non-empty, it redirects to the external URL.
func NewHandler(binaryURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fileName := path.Base(r.URL.Path)
		if !strings.HasPrefix(fileName, "lrc-") {
			http.NotFound(w, r)
			return
		}

		if binaryURL != "" {
			target := strings.TrimRight(binaryURL, "/") + "/" + fileName
			http.Redirect(w, r, target, http.StatusTemporaryRedirect)
			return
		}

		http.NotFound(w, r)
	}
}
