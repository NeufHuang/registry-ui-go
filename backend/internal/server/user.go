package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/neuf/registry-ui/backend/internal/store"
)

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		avatar := s.userAvatar(r)
		username := ""
		isAdmin := false
		mustChange := false
		var userID int64
		if u := s.GetCurrentUser(r); u != nil {
			userID = u.ID
			username = u.Username
			isAdmin = u.IsAdmin
			mustChange = u.MustChangePassword
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id":                 userID,
			"username":           username,
			"avatar":             avatar,
			"authMode":           s.cfg.AuthMode,
			"isAdmin":            isAdmin,
			"mustChangePassword": mustChange,
		})
	case http.MethodPut:
		var body struct {
			Avatar string `json:"avatar"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json", "details": err.Error()})
			return
		}
		if body.Avatar != "" {
			_ = s.store.SetSetting(r.Context(), "userAvatar", body.Avatar)
		}
		_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "user.avatar.update", "", "", "", "ok", "user="+s.currentUsername(r))
		writeJSON(w, http.StatusOK, map[string]any{"username": s.currentUsername(r), "avatar": body.Avatar})
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleUserPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var body struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, err)
		return
	}
	if len(body.NewPassword) < 6 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "password too short", "code": "passwordTooShort", "details": "new password must be at least 6 characters"})
		return
	}
	cur := s.GetCurrentUser(r)
	if cur == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	full, err := s.store.GetUserByID(r.Context(), cur.ID)
	if err != nil || !store.VerifyPasswordHash(full.PasswordHash, body.OldPassword) {
		_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "user.password.change", "", "", "", "error", "old password incorrect user="+s.currentUsername(r))
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "old password is incorrect", "code": "oldPasswordIncorrect"})
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), cur.ID, body.NewPassword); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "user.password.change", "", "", "", "ok", "user="+s.currentUsername(r))
	writeJSON(w, http.StatusOK, map[string]any{"changed": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Logout mutates session state, so it must be a POST guarded by CSRF
	// (a GET endpoint could be triggered cross-site, e.g. <img src=...>,
	// to forcibly log a user out).
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		s.sessionStore.Delete(cookie.Value)
	}
	s.clearSession(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"loggedOut": true})
}

func (s *Server) currentUsername(r *http.Request) string {
	if u := s.GetCurrentUser(r); u != nil {
		return u.Username
	}
	return ""
}

func (s *Server) userAvatar(r *http.Request) string {
	if v, err := s.store.GetSetting(r.Context(), "userAvatar"); err == nil && strings.TrimSpace(v) != "" {
		return v
	}
	avatar, err := s.ensureDefaultAvatar(r)
	if err == nil && avatar != "" {
		_ = s.store.SetSetting(r.Context(), "userAvatar", avatar)
		return avatar
	}
	return ""
}

func (s *Server) ensureDefaultAvatar(r *http.Request) (string, error) {
	if err := os.MkdirAll(s.cfg.UploadDir, 0o755); err != nil {
		return "", err
	}
	username := s.currentUsername(r)
	if username == "" {
		username = store.DefaultAdminUsername
	}
	sum := sha256.Sum256([]byte(username))
	name := "avatar-default-" + hex.EncodeToString(sum[:4]) + ".svg"
	path := filepath.Join(s.cfg.UploadDir, name)
	if _, err := os.Stat(path); err == nil {
		return "/uploads/" + name, nil
	}
	initial := strings.ToUpper(string([]rune(username)[0]))
	colors := []string{"#4da3ff", "#42d392", "#ffb84d", "#a78bfa", "#ff5c72"}
	bg := colors[int(sum[0])%len(colors)]
	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128"><rect width="128" height="128" rx="32" fill="%s"/><text x="64" y="78" text-anchor="middle" font-family="Arial, sans-serif" font-size="56" font-weight="700" fill="white">%s</text></svg>`, bg, html.EscapeString(initial))
	if err := os.WriteFile(path, []byte(svg), 0o644); err != nil {
		return "", err
	}
	return "/uploads/" + name, nil
}
