package binary

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
)

// NewHandler returns an http.HandlerFunc that serves cached binaries from dir.
// If dir is empty or the requested file does not exist, it returns 404.
func NewHandler(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fileName := path.Base(r.URL.Path)
		if !strings.HasPrefix(fileName, "lrc-") {
			http.NotFound(w, r)
			return
		}

		if dir == "" {
			http.NotFound(w, r)
			return
		}

		if strings.HasSuffix(r.URL.Path, ".sha256") {
			serveChecksum(w, r, dir, fileName)
			return
		}
		serveBinary(w, r, dir, fileName)
	}
}

func serveBinary(w http.ResponseWriter, r *http.Request, dir, fileName string) {
	f, err := os.Open(path.Join(dir, fileName))
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

func serveChecksum(w http.ResponseWriter, r *http.Request, dir, fileName string) {
	binName := strings.TrimSuffix(fileName, ".sha256")
	b, err := os.ReadFile(path.Join(dir, binName+".sha256"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(b)
}
