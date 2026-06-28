package embedbin

import (
	"embed"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
)

//go:embed bin/*
var binFS embed.FS

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
