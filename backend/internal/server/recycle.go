package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/neuf/registry-ui/backend/internal/store"
)

func (s *Server) handleRecycle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	includeRestored := r.URL.Query().Get("includeRestored") == "true"
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	items, err := s.store.ListRecycleItems(r.Context(), includeRestored, limit)
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
	writeJSON(w, http.StatusOK, map[string]any{"items": filtered})
}

func (s *Server) handleRecycleByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/recycle/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// DELETE /api/recycle/{id} — permanently delete recycle item
	if len(parts) == 1 && r.Method == http.MethodDelete {
		item, err := s.store.GetRecycleItem(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		if err := s.store.DeleteRecycleItem(r.Context(), id); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		imageNameSnapshot := item.Repo + ":" + item.Reference
		_ = s.store.AddAuditWithImage(r.Context(), s.currentUserID(r), "recycle.delete", item.Repo, item.Reference, item.Digest, "ok", fmt.Sprintf("permanently deleted recycle item %d", id), item.ImageID, imageNameSnapshot)
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
		return
	}
	// POST /api/recycle/{id}/restore
	if len(parts) != 2 || parts[1] != "restore" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	item, err := s.store.GetRecycleItem(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if item.Status != "pending_gc" {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "recycle item is not pending_gc", "status": item.Status})
		return
	}
	client := s.client
	// Check if tag now points to a different manifest (re-assigned after deletion).
	// If so, snapshot the current manifest before overwriting it.
	if currentDigest, _, derr := client.Digest(r.Context(), item.Repo, item.Reference); derr == nil && currentDigest != "" && currentDigest != item.Digest {
		if raw, rerr := client.ManifestRaw(r.Context(), item.Repo, item.Reference); rerr == nil && raw.Digest != "" {
			_ = s.store.AddRecycleItem(r.Context(), store.RecycleItem{
				Repo:         item.Repo,
				Reference:    item.Reference,
				Digest:       raw.Digest,
				ContentType:  raw.ContentType,
				ManifestBody: raw.Body,
			})
		}
	}
	if err := client.PutManifest(r.Context(), item.Repo, item.Reference, item.ContentType, item.ManifestBody); err != nil {
		_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "recycle.restore", item.Repo, item.Reference, item.Digest, "error", err.Error())
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if err := s.store.MarkRecycleRestored(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// SyncImage upserts the image row with the restored digest and clears
	// the deleted flag, while preserving favorite/note. This also fixes the
	// case where the tag has been reassigned to a new image after deletion:
	// the DB digest is updated to match the restored manifest in the registry.
	rid, _ := s.resolveRepo(r.Context(), item.Repo)
	if rid > 0 {
		_, _ = s.store.SyncImage(r.Context(), store.Image{
			RepositoryID: rid,
			Tag:          item.Reference,
			Digest:       item.Digest,
			ContentType:  item.ContentType,
			Size:         item.Size,
		})
	}
	s.fireWebhookEvent("restore", item.Repo, item.Reference, item.Digest)
	_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "recycle.restore", item.Repo, item.Reference, item.Digest, "ok", "tag restored from recycle bin before GC")
	writeJSON(w, http.StatusOK, map[string]any{"restored": true, "item": store.RecycleItem{ID: item.ID, Repo: item.Repo, Reference: item.Reference, Digest: item.Digest, ContentType: item.ContentType, Status: "restored", DeletedAt: item.DeletedAt}})
}
