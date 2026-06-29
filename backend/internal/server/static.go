package server

import (
	"embed"
	"net/http"
	"path"
	"strings"
)

//go:embed static/*
var staticFiles embed.FS

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	clean := path.Clean(r.URL.Path)
	if clean == "/" || clean == "." {
		clean = "/index.html"
	}
	name := "static" + clean
	if strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	data, err := staticFiles.ReadFile(name)
	if err != nil {
		data, _ = staticFiles.ReadFile("static/index.html")
	}
	if data == nil {
		http.NotFound(w, r)
		return
	}
	ct := "text/plain; charset=utf-8"
	switch {
	case strings.HasSuffix(name, ".js"):
		ct = "application/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		ct = "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".html"):
		ct = "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".svg"):
		ct = "image/svg+xml"
	case strings.HasSuffix(name, ".png"):
		ct = "image/png"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	w.Write(data)
}
