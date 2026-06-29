package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/neuf/registry-ui/backend/internal/registry"
	"github.com/neuf/registry-ui/backend/internal/store"
)

func (s *Server) newV2Proxy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// During GC, block push/write requests but allow pull/read
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			s.gcLock.RLock()
			running := s.gcRunning
			s.gcLock.RUnlock()
			if running {
				w.Header().Set("Retry-After", "30")
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "garbage collection in progress", "details": "push is temporarily unavailable; pull is unaffected"})
				return
			}
		}
		// Check immutable tag rules on PUT manifests
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/manifests/") {
			parts := strings.Split(r.URL.Path, "/manifests/")
			if len(parts) == 2 {
				repoPath := strings.TrimPrefix(parts[0], "/v2/")
				ref := strings.TrimSpace(parts[1])
				// Check push_create_repo: per-repo table → global setting
				// If push_create is disabled, only allow pushing to repos that already exist in DB
				if !s.pushCreateAllowed(r.Context(), repoPath) {
					if nsParts := strings.SplitN(repoPath, "/", 2); len(nsParts) == 2 {
						if _, err := s.store.GetRepositoryByNamespacedName(r.Context(), nsParts[0], nsParts[1]); err != nil {
							writeJSON(w, http.StatusForbidden, map[string]any{"error": "push_create disabled", "details": "repository not found in DB and push_create_repo is disabled"})
							return
						}
					}
				}
				// Resolve protection mode: per-repo table → global setting → default 'rules'
				protectionMode := s.resolveProtectionMode(r.Context(), repoPath)
				if protectionMode != "overwrite" {
					// Not allowed to overwrite, check immutable rules
					forceImmutable := protectionMode == "immutable"
					if ok, pattern := s.checkImmutableTag(r.Context(), repoPath, ref, forceImmutable); ok {
						writeJSON(w, http.StatusConflict, map[string]any{
							"error":   "immutable tag",
							"details": fmt.Sprintf("tag '%s' matches immutable pattern '%s'", ref, pattern),
						})
						return
					}
				}
			}
		}
		// Track pull/push stats
		if strings.Contains(r.URL.Path, "/manifests/") {
			repoPath := ""
			parts := strings.Split(r.URL.Path, "/manifests/")
			if len(parts) == 2 {
				repoPath = strings.TrimPrefix(parts[0], "/v2/")
			}
			if repoPath != "" {
				ref := strings.TrimSpace(parts[1])
				userID := int64(0)
				detail := "anonymous"
				if u := s.GetCurrentUser(r); u != nil {
					userID = u.ID
					detail = ""
				}
				switch r.Method {
				case http.MethodGet, http.MethodHead:
					_ = s.store.IncrementRepoPull(r.Context(), repoPath)
					_ = s.store.AddAudit(r.Context(), userID, "pull", repoPath, ref, "", "ok", detail)
				case http.MethodPut:
					_ = s.store.IncrementRepoPush(r.Context(), repoPath)
					_ = s.store.AddAudit(r.Context(), userID, "push", repoPath, ref, "", "ok", detail)
				}
			}
		}
		target, err := url.Parse(strings.TrimRight(s.cfg.RegistryURL, "/"))
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
			return
		}
		externalHost := r.Host
		externalScheme := "http"
		if r.TLS != nil {
			externalScheme = "https"
		}
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			externalScheme = proto
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		baseDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			baseDirector(req)
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			switch s.v2AuthMode() {
			case "ui", "basic", "same":
				// Prefer the client's own basic auth header (set by
				// `docker login`). Fall back to the configured registry
				// credentials so the proxy still works for tooling
				// that never sent a basic auth header.
				if h := req.Header.Get("Authorization"); h == "" {
					if u, p := s.cfg.RegistryUsername, s.cfg.RegistryPassword; u != "" && p != "" {
						req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u+":"+p)))
					}
				}
			case "off":
				req.Header.Del("Authorization")
			default:
				s.client.ApplyAuth(req)
			}
			if req.Header.Get("Accept") == "" && strings.Contains(req.URL.Path, "/manifests/") {
				req.Header.Set("Accept", registry.ManifestAccept)
			}
		}
		proxy.ModifyResponse = func(resp *http.Response) error {
			// Filter /v2/_catalog response by user permissions (non-admin)
			if resp.StatusCode >= 200 && resp.StatusCode < 300 && r.URL.Path == "/v2/_catalog" {
				u := s.GetCurrentUser(r)
				if u != nil && !u.IsAdmin {
					body, err := io.ReadAll(resp.Body)
					if err == nil {
						resp.Body.Close()
						var cat struct {
							Repositories []string `json:"repositories"`
						}
						if err := json.Unmarshal(body, &cat); err == nil {
							filtered := make([]string, 0, len(cat.Repositories))
							for _, repo := range cat.Repositories {
								if s.userCanAccessRepo(r, repo) {
									filtered = append(filtered, repo)
								}
							}
							cat.Repositories = filtered
							if newBody, err := json.Marshal(cat); err == nil {
								resp.Body = io.NopCloser(bytes.NewReader(newBody))
								resp.ContentLength = int64(len(newBody))
								resp.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
							} else {
								resp.Body = io.NopCloser(bytes.NewReader(body))
							}
						} else {
							resp.Body = io.NopCloser(bytes.NewReader(body))
						}
					}
				}
			}
			// Fire webhook on successful PUT manifest (push)
			if resp.StatusCode >= 200 && resp.StatusCode < 300 && r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/manifests/") {
				if parts := strings.Split(r.URL.Path, "/manifests/"); len(parts) == 2 {
					repoPath := strings.TrimPrefix(parts[0], "/v2/")
					ref := strings.TrimSpace(parts[1])
					digest := resp.Header.Get("Docker-Content-Digest")
					s.fireWebhookEvent("push", repoPath, ref, digest)
					// Sync images table (clear deleted flag) and clean up recycle bin
					if digest != "" {
						bgCtx := context.Background()
						if rid, _ := s.resolveRepo(bgCtx, repoPath); rid > 0 {
							// Fetch manifest to compute size for database stats
							var size int64
							if m, merr := s.client.Manifest(bgCtx, repoPath, digest); merr == nil {
								size = computeManifestSize(m.Manifest)
							}
							_, _ = s.store.SyncImage(bgCtx, store.Image{
								RepositoryID: rid,
								Tag:          ref,
								Digest:       digest,
								Size:         size,
							})
						}
						_ = s.store.DeletePendingGCByRepoRef(bgCtx, repoPath, ref)
					}
				}
			}
			loc := resp.Header.Get("Location")
			if loc == "" {
				return nil
			}
			internalPrefix := target.Scheme + "://" + target.Host
			externalPrefix := externalScheme + "://" + externalHost
			if strings.HasPrefix(loc, internalPrefix) {
				resp.Header.Set("Location", externalPrefix+strings.TrimPrefix(loc, internalPrefix))
			}
			return nil
		}
		// Reuse the Server's shared transport so HTTP keep-alive
		// connections to the registry are pooled across requests instead
		// of allocating a fresh transport (and TLS config) per call.
		proxy.Transport = s.proxyTransport
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "registry proxy failed", "details": err.Error()})
		}
		// Snapshot old manifest if overwrite with recycle is enabled
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/manifests/") {
			parts := strings.Split(r.URL.Path, "/manifests/")
			if len(parts) == 2 {
				repoPath := strings.TrimPrefix(parts[0], "/v2/")
				ref := strings.TrimSpace(parts[1])
				if s.resolveOverwriteAction(r.Context(), repoPath) == "recycle" {
					// Try to get the old manifest and snapshot it
					raw, err := s.client.ManifestRaw(r.Context(), repoPath, ref)
					if err == nil && raw.Digest != "" {
						_ = s.store.AddRecycleItem(r.Context(), store.RecycleItem{
							Repo:         repoPath,
							Reference:    ref,
							Digest:       raw.Digest,
							ContentType:  raw.ContentType,
							ManifestBody: raw.Body,
						})
					}
				}
			}
		}
		// Snapshot manifest before DELETE (recycle bin safety net)
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/manifests/") {
			parts := strings.Split(r.URL.Path, "/manifests/")
			if len(parts) == 2 {
				repoPath := strings.TrimPrefix(parts[0], "/v2/")
				ref := strings.TrimSpace(parts[1])
				snapshotDigest := ref
				if !strings.HasPrefix(ref, "sha256:") {
					if d, _, derr := s.client.Digest(r.Context(), repoPath, ref); derr == nil && d != "" {
						snapshotDigest = d
					}
				}
				_ = s.snapshotRecycleItems(r, repoPath, snapshotDigest)
			}
		}
		proxy.ServeHTTP(w, r)
	})
}
