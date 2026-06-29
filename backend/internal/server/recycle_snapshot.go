package server

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/neuf/registry-ui/backend/internal/store"
)

func (s *Server) snapshotRecycleItems(rctx requestContext, repo, digest string) int {
	tags, err := s.client.Tags(rctx.Context(), repo)
	if err != nil {
		_ = s.store.AddAudit(rctx.Context(), 0, "recycle.snapshot", repo, "", digest, "error", err.Error())
		return 0
	}
	count := 0
	seen := map[string]bool{}
	for _, tag := range tags.Tags {
		d, _, err := s.client.Digest(rctx.Context(), repo, tag)
		if err != nil || d != digest || seen[tag] {
			continue
		}
		seen[tag] = true
		raw, err := s.client.ManifestRaw(rctx.Context(), repo, tag)
		if err != nil {
			_ = s.store.AddAudit(rctx.Context(), 0, "recycle.snapshot", repo, tag, digest, "error", err.Error())
			continue
		}
		if raw.Digest == "" {
			raw.Digest = digest
		}
		if raw.Digest != digest && strings.TrimSpace(raw.Digest) != "" {
			continue
		}
		// Look up image record for image_id
		var imageID *int64
		if rid, rerr := s.resolveRepo(rctx.Context(), repo); rerr == nil {
			if img, ierr := s.store.GetImageByRepoTag(rctx.Context(), rid, tag); ierr == nil {
				imageID = &img.ID
			}
		}
		// Parse manifest body to compute actual image size
		var manifestSize int64
		if raw.Body != nil {
			var m map[string]any
			if err := json.Unmarshal(raw.Body, &m); err == nil {
				manifestSize = computeManifestSize(m)
			}
		}
		if err := s.store.AddRecycleItem(rctx.Context(), store.RecycleItem{Repo: repo, Reference: tag, Digest: digest, ContentType: raw.ContentType, ManifestBody: raw.Body, Size: manifestSize, ImageID: imageID}); err != nil {
			_ = s.store.AddAudit(rctx.Context(), 0, "recycle.snapshot", repo, tag, digest, "error", err.Error())
			continue
		}
		count++
	}
	return count
}

type requestContext interface {
	Context() context.Context
}
