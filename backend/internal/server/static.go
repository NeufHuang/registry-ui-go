package server

import (
	"embed"
	"fmt"
	"hash/fnv"
	"net/http"
	"path"
	"strconv"
	"strings"
)

//go:embed static/*
var staticFiles embed.FS

// contentTypeFor maps a static asset file name to its Content-Type.
func contentTypeFor(name string) string {
	switch {
	case strings.HasSuffix(name, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(name, ".png"):
		return "image/png"
	}
	return "text/plain; charset=utf-8"
}

// staticETag derives a stable ETag from the embedded asset content, letting the
// browser skip re-downloading unchanged JS/CSS on every page load.
func staticETag(name string, data []byte) string {
	h := fnv.New64a()
	_, _ = h.Write(data)
	return fmt.Sprintf("\"%s-%x\"", path.Base(name), h.Sum64())
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	clean := path.Clean(r.URL.Path)
	if clean == "/" || clean == "." {
		clean = "/index.html"
	}
	if strings.Contains(clean, "..") {
		http.NotFound(w, r)
		return
	}
	name := "static" + clean
	data, err := staticFiles.ReadFile(name)
	if err != nil {
		// A missing asset (anything with a file extension) is a genuine 404.
		// Otherwise fall back to the SPA shell — and serve it as HTML: deriving
		// the Content-Type from the requested path used to return index.html as
		// text/plain, so a deep link/reload rendered the page source.
		if path.Ext(clean) != "" {
			http.NotFound(w, r)
			return
		}
		name = "static/index.html"
		data, err = staticFiles.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
	}
	etag := staticETag(name, data)
	h := w.Header()
	h.Set("ETag", etag)
	// no-cache means "revalidate", so the ETag still saves the body transfer.
	h.Set("Cache-Control", "no-cache")
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Type", contentTypeFor(name))
	h.Set("Content-Length", strconv.Itoa(len(data)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(data)
}
