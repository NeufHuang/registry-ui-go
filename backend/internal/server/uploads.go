package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const maxLogoUploadBytes = 2 << 20 // 2 MiB

var allowedLogoContentTypes = map[string]string{
	"image/png":     ".png",
	"image/jpeg":    ".jpg",
	"image/gif":     ".gif",
	"image/webp":    ".webp",
	"image/svg+xml": ".svg",
}

func (s *Server) handleLogoUpload(w http.ResponseWriter, r *http.Request) {
	url, contentType, ok := s.handleImageUpload(w, r, "logo", "logo")
	if !ok {
		return
	}
	_ = s.store.SetSetting(r.Context(), "appLogo", url)
	writeJSON(w, http.StatusCreated, map[string]any{"url": url, "contentType": contentType})
}

func (s *Server) handleAvatarUpload(w http.ResponseWriter, r *http.Request) {
	url, contentType, ok := s.handleImageUpload(w, r, "avatar", "avatar")
	if !ok {
		return
	}
	_ = s.store.SetSetting(r.Context(), "userAvatar", url)
	writeJSON(w, http.StatusCreated, map[string]any{"url": url, "contentType": contentType})
}

func (s *Server) handleImageUpload(w http.ResponseWriter, r *http.Request, field, prefix string) (string, string, bool) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return "", "", false
	}
	if err := os.MkdirAll(s.cfg.UploadDir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return "", "", false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLogoUploadBytes)
	file, header, err := r.FormFile(field)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": field + " file is required", "details": err.Error()})
		return "", "", false
	}
	defer file.Close()

	buf := make([]byte, 512)
	n, _ := io.ReadFull(file, buf)
	buf = buf[:n]
	contentType := http.DetectContentType(buf)
	if strings.HasSuffix(strings.ToLower(header.Filename), ".svg") {
		contentType = "image/svg+xml"
	}
	ext, ok := allowedLogoContentTypes[contentType]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported image type", "details": "allowed: png, jpg, gif, webp, svg"})
		return "", "", false
	}
	name, err := randomHex(16)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return "", "", false
	}
	name = prefix + "-" + name + ext
	path := filepath.Join(s.cfg.UploadDir, name)
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return "", "", false
	}
	defer out.Close()
	if _, err := out.Write(buf); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return "", "", false
	}
	if _, err := io.Copy(out, file); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return "", "", false
	}
	return "/uploads/" + name, contentType, true
}

func (s *Server) handleUploads(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/uploads/")
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	filePath := filepath.Join(s.cfg.UploadDir, name)
	// logo.png is a stable alias for the latest uploaded logo (used as favicon).
	// Accepts any common image extension (jpg, webp, svg, png, gif), not just PNG.
	if strings.ToLower(name) == "logo.png" {
		entries, err := os.ReadDir(s.cfg.UploadDir)
		if err == nil {
			var latest os.DirEntry
			var latestTime int64
			for _, entry := range entries {
				n := entry.Name()
				if !strings.HasPrefix(strings.ToLower(n), "logo-") || entry.IsDir() {
					continue
				}
				info, ierr := entry.Info()
				if ierr != nil {
					continue
				}
				if latest == nil || info.ModTime().Unix() > latestTime {
					latest = entry
					latestTime = info.ModTime().Unix()
				}
			}
			if latest != nil {
				filePath = filepath.Join(s.cfg.UploadDir, latest.Name())
			}
		}
	}
	// Uploaded assets are user-controlled. SVG (and any sniffed HTML) can
	// carry inline script that would execute same-origin, so prevent MIME
	// sniffing and serve SVG as a non-rendering download to defuse stored
	// XSS. Other image types render inline as expected.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if strings.HasSuffix(strings.ToLower(filePath), ".svg") {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
		w.Header().Set("Content-Disposition", "inline; filename=\""+filepath.Base(filePath)+"\"")
	}
	http.ServeFile(w, r, filePath)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random name: %w", err)
	}
	return hex.EncodeToString(b), nil
}
