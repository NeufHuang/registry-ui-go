package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/neuf/registry-ui/backend/internal/store"
)

// settableSettings is the whitelist of keys that PUT /api/settings is
// allowed to write. Centralising the list here prevents admins from
// polluting the settings table with arbitrary keys (and from overwriting
// the password hash or other sensitive entries by accident).
var settableSettings = map[string]bool{
	// UI appearance / behavior
	"theme":         true,
	"language":      true,
	"appLogo":       true,
	"appTitle":      true,
	"appSubtitle":   true,
	"pageSize":      true,
	"showAudit":     true,
	"tls_enabled":   true,
	"recycleGCDays": true,
	// Global policy defaults
	"protection_mode":      true,
	"overwrite_action":     true,
	"retention_keep_count": true,
	"allow_anonymous_pull": true,
	"push_create_repo":     true,
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settings, err := s.store.Settings(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		// Fill in defaults for any known key not yet persisted so the
		// frontend never has to ship its own default dictionary.
		for k, def := range store.DefaultSettings {
			if _, ok := settings[k]; !ok {
				settings[k] = def
			}
		}
		writeJSON(w, http.StatusOK, settings)
	case http.MethodPut:
		if u := s.GetCurrentUser(r); u != nil && !u.IsAdmin {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
			return
		}
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		for k, v := range req {
			if !settableSettings[k] {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown or protected setting: " + k})
				return
			}
			if err := s.store.SetSetting(r.Context(), k, v); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"saved": true})
	default:
		methodNotAllowed(w)
	}
}

// Admin user management APIs
func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	u := s.GetCurrentUser(r)
	if u == nil || !u.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		users, err := s.store.ListUsers(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": users})
	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			IsAdmin  bool   `json:"isAdmin"`
			Enabled  bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if len(req.Password) < 6 {
			writeError(w, http.StatusBadRequest, nil)
			return
		}
		hash, err := store.HashPassword(req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		user, err := s.store.CreateUser(r.Context(), req.Username, hash, req.IsAdmin, false)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "user.create", "", "", "", "ok", fmt.Sprintf("user_id=%d username=%s isAdmin=%t", user.ID, user.Username, user.IsAdmin))
		writeJSON(w, http.StatusCreated, user)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleAdminUserByID(w http.ResponseWriter, r *http.Request) {
	u := s.GetCurrentUser(r)
	if u == nil || !u.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/users/")
	id, ok := parseID(idStr)
	if !ok {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		user, err := s.store.GetUserByID(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		perms, err := s.store.ListUserPermissions(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"user": user, "permissions": perms})
	case http.MethodPut:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password,omitempty"`
			IsAdmin  bool   `json:"isAdmin"`
			Enabled  bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.Password != "" {
			if len(req.Password) < 6 {
				writeError(w, http.StatusBadRequest, nil)
				return
			}
		}
		err := s.store.UpdateUser(r.Context(), id, req.Username, req.Password, req.IsAdmin, req.Enabled)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		user, err := s.store.GetUserByID(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		detail := fmt.Sprintf("user_id=%d username=%s isAdmin=%t enabled=%t", user.ID, user.Username, user.IsAdmin, user.Enabled)
		if req.Password != "" {
			detail += " password_changed=true"
		}
		_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "user.update", "", "", "", "ok", detail)
		writeJSON(w, http.StatusOK, user)
	case http.MethodDelete:
		cur := s.GetCurrentUser(r)
		if cur != nil && cur.ID == id {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "cannot delete yourself", "details": "an admin cannot delete their own account"})
			return
		}
		target, err := s.store.GetUserByID(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		if target.IsAdmin {
			remaining, _ := s.store.CountEnabledAdmins(r.Context())
			if remaining <= 1 {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "cannot delete the last enabled admin", "details": "promote another user to admin first"})
				return
			}
		}
		if err := s.store.DeleteUser(r.Context(), id); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "user.delete", "", "", "", "ok", fmt.Sprintf("user_id=%d", id))
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
	default:
		methodNotAllowed(w)
	}
}

// handleAdminUserDisable and handleAdminUserEnable toggle a user's
// enabled flag via dedicated POST endpoints. Two handlers (rather than
// one with a path suffix) keep the call sites self-explanatory and let
// each be wired to its own route without path parsing.
func (s *Server) handleAdminUserDisable(w http.ResponseWriter, r *http.Request) {
	s.setUserEnabled(w, r, false)
}

func (s *Server) handleAdminUserEnable(w http.ResponseWriter, r *http.Request) {
	s.setUserEnabled(w, r, true)
}

// setUserEnabled is the shared core of disable/enable. Guards:
//   - caller must be an admin
//   - target user must exist
//   - cannot toggle your own account (would lock yourself out of the
//     session-based UI and out of basic auth recovery)
//   - when disabling, the target must not be the last enabled admin
//     (would lock the system out of admin access)
func (s *Server) setUserEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	caller := s.GetCurrentUser(r)
	if caller == nil || !caller.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	id, ok := parseID(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if caller.ID == id {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "cannot toggle your own enabled flag", "details": "an admin cannot disable or re-enable their own account"})
		return
	}
	target, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	action := "user.enable"
	if !enabled {
		action = "user.disable"
		if target.IsAdmin {
			remaining, _ := s.store.CountEnabledAdmins(r.Context())
			if remaining <= 1 {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "cannot disable the last enabled admin", "details": "promote another user to admin first"})
				return
			}
		}
	}
	if err := s.store.SetUserEnabled(r.Context(), id, enabled); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.store.AddAudit(r.Context(), s.currentUserID(r), action, "", "", "", "ok", fmt.Sprintf("user_id=%d enabled=%t", id, enabled))
	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleAdminUserPermissions(w http.ResponseWriter, r *http.Request) {
	u := s.GetCurrentUser(r)
	if u == nil || !u.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}

	userID, ok := parseID(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		perms, err := s.store.ListUserPermissions(r.Context(), userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"permissions": perms})
	case http.MethodPost:
		var req struct {
			Patterns         []string `json:"patterns"`
			NamespacePattern string   `json:"namespacePattern"`
			CanRead          bool     `json:"canRead"`
			CanWrite         bool     `json:"canWrite"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		patterns := req.Patterns
		if len(patterns) == 0 && req.NamespacePattern != "" {
			patterns = []string{req.NamespacePattern}
		}
		if len(patterns) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "no patterns provided"})
			return
		}
		// can_write implies can_read, so normalise the read flag.
		canRead := req.CanRead || req.CanWrite
		var saved []store.UserPermission
		for _, pattern := range patterns {
			perm, err := s.store.UpsertUserPermission(r.Context(), store.UserPermission{UserID: userID, NamespacePattern: pattern, CanRead: canRead, CanWrite: req.CanWrite})
			if err != nil {
				continue
			}
			saved = append(saved, perm)
			_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "user.permission.set", "", "", "", "ok", fmt.Sprintf("target_user_id=%d pattern=%s can_read=%t can_write=%t", userID, perm.NamespacePattern, perm.CanRead, perm.CanWrite))
		}
		writeJSON(w, http.StatusOK, map[string]any{"permissions": saved})
	case http.MethodDelete:
		var req struct {
			NamespacePattern string `json:"namespacePattern"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.NamespacePattern == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "no pattern provided"})
			return
		}
		if err := s.store.DeleteUserPermissionByPattern(r.Context(), userID, req.NamespacePattern); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "user.permission.delete", "", "", "", "ok", fmt.Sprintf("target_user_id=%d pattern=%s", userID, req.NamespacePattern))
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleAdminUserPermissionByID(w http.ResponseWriter, r *http.Request) {
	u := s.GetCurrentUser(r)
	if u == nil || !u.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}

	permID, ok := parseID(r.PathValue("permId"))
	if !ok {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodPut:
		var req store.UserPermission
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		err := s.store.UpdateUserPermission(r.Context(), permID, req.NamespacePattern, req.CanRead, req.CanWrite)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "user.permission.update", "", "", "", "ok", fmt.Sprintf("perm_id=%d pattern=%s can_read=%t can_write=%t", permID, req.NamespacePattern, req.CanRead, req.CanWrite))
		writeJSON(w, http.StatusOK, map[string]any{"updated": true})
	case http.MethodDelete:
		if err := s.store.DeleteUserPermission(r.Context(), permID); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "user.permission.delete", "", "", "", "ok", fmt.Sprintf("perm_id=%d", permID))
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFavorites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.store.ListImages(r.Context(), true, false)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		out := make([]map[string]any, 0, len(items))
		for _, img := range items {
			rname := func() string {
				repo, e := s.store.GetRepositoryByID(r.Context(), img.RepositoryID)
				if e != nil {
					return "?"
				}
				ns, e2 := s.store.GetNamespaceByID(r.Context(), repo.NamespaceID)
				if e2 != nil {
					return repo.Name
				}
				return ns.Name + "/" + repo.Name
			}()
			if !s.userCanAccessRepo(r, rname) {
				continue
			}
			out = append(out, map[string]any{
				"id":        img.ID,
				"repo":      rname,
				"reference": img.Tag,
				"digest":    img.Digest,
				"note":      img.Note,
				"createdAt": img.CreatedAt,
				"updatedAt": img.UpdatedAt,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"favorites": out})
	case http.MethodPost:
		var req struct {
			Repo      string `json:"repo"`
			Reference string `json:"reference"`
			Digest    string `json:"digest"`
			Note      string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		rid, rerr := s.resolveRepo(r.Context(), req.Repo)
		if rerr != nil {
			writeError(w, http.StatusBadRequest, rerr)
			return
		}
		_, err := s.store.UpsertImage(r.Context(), store.Image{RepositoryID: rid, Tag: req.Reference, Digest: req.Digest, Favorite: true, Note: req.Note})
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		img, err := s.store.GetImageByRepoTag(r.Context(), rid, req.Reference)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "favorite.upsert", req.Repo, req.Reference, req.Digest, "ok", req.Note)
		writeJSON(w, http.StatusOK, map[string]any{
			"id":        img.ID,
			"repo":      req.Repo,
			"reference": img.Tag,
			"digest":    img.Digest,
			"note":      img.Note,
			"createdAt": img.CreatedAt,
			"updatedAt": img.UpdatedAt,
		})
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleFavoriteByID(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(strings.TrimPrefix(r.URL.Path, "/api/favorites/"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	img, err := s.store.GetImageByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err := s.store.SetImageFavorite(r.Context(), img.RepositoryID, img.Tag, false, ""); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (s *Server) handleRecent(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListRecent(r.Context(), s.currentUserID(r), 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	filtered := items[:0]
	for _, item := range items {
		if s.userCanAccessRepo(r, item.Repo) {
			filtered = append(filtered, item)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"recent": filtered})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	u := s.GetCurrentUser(r)
	// Non-admins can only see their own actions; admins see all.
	userID := int64(0)
	if u != nil && !u.IsAdmin {
		userID = u.ID
	}
	items, err := s.store.ListAudit(r.Context(), userID, 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": items})
}
