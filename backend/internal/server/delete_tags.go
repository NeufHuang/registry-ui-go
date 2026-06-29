package server

import (
	"log"
	"net/http"
)

// tagDeleteResult describes the outcome of removing a single tag.
type tagDeleteResult struct {
	Tag    string `json:"tag"`
	Action string `json:"action"` // "delete" (digest removed) or "untag" (siblings remain)
	Ok     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

// deleteTagsAware removes the selected tags with proper tag semantics.
//
// The Docker Registry V2 API can only delete manifests by digest, which wipes
// every tag pointing at that digest and makes it GC-eligible. To delete an
// individual tag we group the selected tags by digest and, for each affected
// digest:
//
//   - if every tag of the digest is being removed (last-tag case) we snapshot
//     the manifest to the recycle bin, delete it, and fire a "delete" event;
//   - otherwise (pure untag) we delete the manifest and immediately re-push it
//     under each surviving tag (blobs persist until GC, so the re-push only
//     recreates the tag pointers), and fire an "untag" event. No recycle
//     snapshot is taken because the digest still exists.
//
// It returns the per-tag results and the number of recycle-bin snapshots taken.
func (s *Server) deleteTagsAware(r *http.Request, name string, selectedTags []string) ([]tagDeleteResult, int) {
	ctx := r.Context()
	client := s.client

	// Deduplicate selected tags, preserving order.
	seen := map[string]bool{}
	var sel []string
	for _, tg := range selectedTags {
		if tg != "" && !seen[tg] {
			seen[tg] = true
			sel = append(sel, tg)
		}
	}

	results := make([]tagDeleteResult, 0, len(sel))
	snapshotCount := 0

	// Full repo tag list, used to find sibling tags sharing a digest.
	var allTags []string
	if tagsResp, err := client.Tags(ctx, name); err == nil {
		allTags = tagsResp.Tags
	}

	// Cache tag -> digest to avoid duplicate HEAD requests.
	digestCache := map[string]string{}
	digestOf := func(tag string) string {
		if d, ok := digestCache[tag]; ok {
			return d
		}
		d, _, derr := client.Digest(ctx, name, tag)
		if derr != nil {
			d = ""
		}
		digestCache[tag] = d
		return d
	}

	// Group selected tags by their digest, preserving first-seen order.
	selByDigest := map[string][]string{}
	var digestOrder []string
	for _, tag := range sel {
		d := digestOf(tag)
		if d == "" {
			results = append(results, tagDeleteResult{Tag: tag, Ok: false, Error: "cannot resolve digest for tag"})
			continue
		}
		if _, ok := selByDigest[d]; !ok {
			digestOrder = append(digestOrder, d)
		}
		selByDigest[d] = append(selByDigest[d], tag)
	}

	rid, _ := s.resolveRepo(ctx, name)

	for _, digest := range digestOrder {
		removeTags := selByDigest[digest]
		removeSet := map[string]bool{}
		for _, tg := range removeTags {
			removeSet[tg] = true
		}

		// Determine which tags of this digest will survive.
		remaining := survivingTags(allTags, removeSet, func(tag string) string { return digestOf(tag) }, digest)

		// Fetch the manifest body once (needed for snapshot and/or re-push).
		raw, rawErr := client.ManifestRaw(ctx, name, digest)

		if len(remaining) == 0 {
			// Last-tag case: snapshot then delete the digest for good.
			snapshotCount += s.snapshotRecycleItems(r, name, digest)
			if err := client.DeleteManifest(ctx, name, digest); err != nil {
				for _, tg := range removeTags {
					results = append(results, tagDeleteResult{Tag: tg, Action: "delete", Ok: false, Error: err.Error()})
				}
				_ = s.store.AddAudit(ctx, s.currentUserID(r), "delete", name, "", digest, "error", err.Error())
				continue
			}
			s.fireWebhookEvent("delete", name, "", digest)
			if rid > 0 {
				_ = s.store.SoftDeleteImageByDigest(ctx, rid, digest)
			}
			var imageID *int64
			if img, ierr := s.store.GetImageByDigest(ctx, digest); ierr == nil {
				imageID = &img.ID
			}
			for _, tg := range removeTags {
				_ = s.store.AddAuditWithImage(ctx, s.currentUserID(r), "delete", name, tg, digest, "ok", "last tag removed; digest deleted (restore from recycle bin before GC)", imageID, name+":"+tg)
				results = append(results, tagDeleteResult{Tag: tg, Action: "delete", Ok: true})
			}
			continue
		}

		// Untag case: delete the digest then re-push surviving tags.
		if rawErr != nil || len(raw.Body) == 0 {
			errMsg := "cannot read manifest body for untag"
			if rawErr != nil {
				errMsg = rawErr.Error()
			}
			for _, tg := range removeTags {
				results = append(results, tagDeleteResult{Tag: tg, Action: "untag", Ok: false, Error: errMsg})
			}
			_ = s.store.AddAudit(ctx, s.currentUserID(r), "untag", name, "", digest, "error", errMsg)
			continue
		}
		if err := client.DeleteManifest(ctx, name, digest); err != nil {
			for _, tg := range removeTags {
				results = append(results, tagDeleteResult{Tag: tg, Action: "untag", Ok: false, Error: err.Error()})
			}
			_ = s.store.AddAudit(ctx, s.currentUserID(r), "untag", name, "", digest, "error", err.Error())
			continue
		}
		// Re-push the manifest under each surviving tag. Failures here are
		// serious (the surviving tag is gone), so they are logged and
		// surfaced; the manifest body is still held in memory for retry.
		for _, tg := range remaining {
			if err := client.PutManifest(ctx, name, tg, raw.ContentType, raw.Body); err != nil {
				log.Printf("untag re-push failed repo=%s tag=%s digest=%s: %v", name, tg, digest, err)
				_ = s.store.AddAudit(ctx, s.currentUserID(r), "untag", name, tg, digest, "error", "re-push of surviving tag failed: "+err.Error())
			}
		}
		for _, tg := range removeTags {
			if rid > 0 {
				_ = s.store.SoftDeleteImage(ctx, rid, tg)
			}
			_ = s.store.AddAudit(ctx, s.currentUserID(r), "untag", name, tg, digest, "ok", "tag removed; digest retained for remaining tags")
			results = append(results, tagDeleteResult{Tag: tg, Action: "untag", Ok: true})
		}
		s.fireWebhookEvent("untag", name, removeTags[0], digest)
	}

	return results, snapshotCount
}

// survivingTags returns the tags in allTags that point at the given digest and
// are not in removeSet. It is the core of the untag-vs-delete decision: an
// empty result means the digest's last tag is being removed (full delete),
// otherwise the surviving tags must be re-pushed after the manifest delete.
func survivingTags(allTags []string, removeSet map[string]bool, digestOf func(string) string, digest string) []string {
	var remaining []string
	for _, tg := range allTags {
		if removeSet[tg] {
			continue
		}
		if digestOf(tg) == digest {
			remaining = append(remaining, tg)
		}
	}
	return remaining
}
