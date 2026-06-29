package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/neuf/registry-ui/backend/internal/config"
	"github.com/neuf/registry-ui/backend/internal/registry"
	"github.com/neuf/registry-ui/backend/internal/store"
)

type Server struct {
	cfg            config.Config
	store          *store.Store
	client         *registry.Client
	proxyTransport *http.Transport
	mux            *http.ServeMux
	sessionStore   sync.Map
	gcRunning      bool
	gcLock         sync.RWMutex
	restartCh      chan struct{}
}

func New(cfg config.Config, st *store.Store) *Server {
	cfg.RegistryURL = strings.TrimRight(cfg.RegistryURL, "/")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.RegistryTLSSkipVerify {
		transport.TLSClientConfig = cfg.RegistryTLSConfig()
	}
	s := &Server{cfg: cfg, store: st, client: registry.NewClient(cfg), proxyTransport: transport, mux: http.NewServeMux(), restartCh: make(chan struct{}, 1)}
	s.routes()
	go s.cleanupSessions()
	return s
}

// RestartRequested returns a channel that fires when an admin requests an
// in-place restart via POST /api/restart. main.go drains connections and
// re-execs the binary when this fires.
func (s *Server) RestartRequested() <-chan struct{} { return s.restartCh }

func computeManifestSize(manifest any) int64 {
	var total int64
	m, ok := manifest.(map[string]any)
	if !ok {
		return total
	}
	parseSize := func(v any) int64 {
		switch s := v.(type) {
		case float64:
			return int64(s)
		case json.Number:
			if n, err := s.Int64(); err == nil {
				return n
			}
		}
		return 0
	}
	if layers, ok := m["layers"].([]any); ok {
		for _, layer := range layers {
			if l, ok := layer.(map[string]any); ok {
				total += parseSize(l["size"])
			}
		}
	}
	if manifests, ok := m["manifests"].([]any); ok {
		for _, x := range manifests {
			if mf, ok := x.(map[string]any); ok {
				total += parseSize(mf["size"])
			}
		}
	}
	return total
}

func (s *Server) Handler() http.Handler {
	return logRequests(s.securityHeaders(s.requireCSRF(s.withAuth(s.mux))))
}

// securityHeaders adds baseline hardening response headers. The CSP is
// intentionally minimal: the SPA is fully self-hosted (no external CDN)
// and uses inline styles/handlers, so 'self' plus 'unsafe-inline' is the
// tightest policy that does not break the UI. Docker Registry API
// responses under /v2/* are left untouched so CLI clients are unaffected.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v2/") {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'")
			if s.secureCookie(r) {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/login", s.handleLogin)
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/gc/run", s.handleGCRun)
	s.mux.HandleFunc("/api/disk-usage", s.handleDiskUsage)
	s.mux.HandleFunc("/api/settings", s.handleSettings)
	s.mux.HandleFunc("/api/tls/cert", s.handleTLSCert)
	s.mux.HandleFunc("/api/restart", s.handleRestart)
	s.mux.HandleFunc("/api/user", s.handleUser)
	s.mux.HandleFunc("/api/user/password", s.handleUserPassword)
	s.mux.HandleFunc("/api/logout", s.handleLogout)
	s.mux.HandleFunc("/api/namespaces", s.handleNamespaces)
	s.mux.HandleFunc("/api/namespaces/", s.handleNamespaceByName)
	s.mux.HandleFunc("/api/favorites", s.handleFavorites)
	s.mux.HandleFunc("/api/favorites/", s.handleFavoriteByID)
	s.mux.HandleFunc("/api/recent", s.handleRecent)
	s.mux.HandleFunc("/api/audit", s.handleAudit)
	s.mux.HandleFunc("/api/recycle", s.handleRecycle)
	s.mux.HandleFunc("/api/recycle/", s.handleRecycleByID)
	s.mux.HandleFunc("/api/uploads/logo", s.handleLogoUpload)
	s.mux.HandleFunc("/api/uploads/avatar", s.handleAvatarUpload)
	s.mux.HandleFunc("/api/repositories", s.handleRepositories)
	s.mux.HandleFunc("/api/me", s.handleMe)
	s.mux.HandleFunc("/api/my-permissions", s.handleMyPermissions)
	s.mux.HandleFunc("/api/repositories/", s.handleRepositorySubroutes)
	// Repo descriptions (separate prefix to avoid route conflict)
	s.mux.HandleFunc("/api/repo-description/", s.handleRepoDescription)
	// Admin user management routes
	s.mux.HandleFunc("/api/admin/users", s.handleAdminUsers)
	s.mux.HandleFunc("/api/admin/users/", s.handleAdminUserByID)
	s.mux.HandleFunc("/api/admin/users/{id}/disable", s.handleAdminUserDisable)
	s.mux.HandleFunc("/api/admin/users/{id}/enable", s.handleAdminUserEnable)
	s.mux.HandleFunc("/api/admin/users/{id}/permissions", s.handleAdminUserPermissions)
	s.mux.HandleFunc("/api/admin/users/{id}/permissions/{permId}", s.handleAdminUserPermissionByID)
	// Immutable tag rules
	s.mux.HandleFunc("/api/admin/immutable-rules", s.handleImmutableRules)
	s.mux.HandleFunc("/api/admin/immutable-rules/", s.handleImmutableRuleByID)
	// API tokens
	s.mux.HandleFunc("/api/admin/tokens", s.handleTokens)
	s.mux.HandleFunc("/api/admin/tokens/", s.handleTokenByID)
	// Webhooks
	s.mux.HandleFunc("/api/admin/webhooks", s.handleWebhooks)
	s.mux.HandleFunc("/api/admin/webhooks/", s.handleWebhookByID)
	// Repo stats & export
	s.mux.HandleFunc("/api/repo-stats", s.handleRepoStats)
	s.mux.HandleFunc("/api/export", s.handleExport)
	s.mux.Handle("/v2/", s.newV2Proxy())
	s.mux.HandleFunc("/uploads/", s.handleUploads)
	s.mux.HandleFunc("/", s.handleStatic)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request"})
		return
	}
	u, err := s.store.GetUserByUsername(r.Context(), body.Username)
	if err == nil && u.Enabled && store.VerifyPasswordHash(u.PasswordHash, body.Password) {
		s.maybeUpgradePassword(r.Context(), u, body.Password)
		s.createSession(w, r, body.Username)
		_ = s.store.AddAudit(r.Context(), u.ID, "login", "", "", "", "ok", "user="+body.Username)
		writeJSON(w, http.StatusOK, map[string]any{
			"username":           body.Username,
			"isAdmin":            u.IsAdmin,
			"mustChangePassword": u.MustChangePassword,
		})
		return
	}
	_ = s.store.AddAudit(r.Context(), 0, "login", "", "", "", "error", "invalid credentials for user="+body.Username)
	writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
}

// currentUserID returns the ID of the authenticated user from the request
// context, or 0 for the env-fallback admin (no DB user record). Used to
// scope per-user state such as the recent-visits log.
func (s *Server) currentUserID(r *http.Request) int64 {
	if u := s.GetCurrentUser(r); u != nil {
		return u.ID
	}
	return 0
}

// userCanAccessRepo returns true if the current user can read the given repo.
// Admins can access all repos. Non-admins must have a matching namespace permission.
func (s *Server) userCanAccessRepo(r *http.Request, repo string) bool {
	u := s.GetCurrentUser(r)
	if u == nil || u.IsAdmin {
		return true
	}
	perms, err := s.store.ListUserPermissions(r.Context(), u.ID)
	if err != nil || len(perms) == 0 {
		return false
	}
	for _, p := range perms {
		if p.CanRead && (repo == p.NamespacePattern || strings.HasPrefix(repo, p.NamespacePattern+"/")) {
			return true
		}
	}
	return false
}

// extractRepoNameFromPath lives in repo_path.go (shared with the /v2/
// authorization path so both use identical repo-name parsing).

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	client := s.client
	// Get stats from database (avoids N+1 registry API calls)
	repoCount, totalTags, _, _ := s.store.GetGlobalImageStats(r.Context())
	status, header, body, err := client.Health(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                           status >= 200 && status < 300,
		"registryStatus":               status,
		"dockerDistributionApiVersion": header.Get("Docker-Distribution-Api-Version"),
		"repoCount":                    repoCount,
		"tagCount":                     totalTags,
		"body":                         string(body),
	})
}

func (s *Server) handleRepositories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	client := s.client
	out, err := client.Catalog(r.Context(), r.URL.Query().Get("n"), r.URL.Query().Get("last"))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	// Merge repos that exist only in DB (created via UI but no manifest pushed yet)
	if dbRepos, derr := s.store.ListAllRepoNames(r.Context()); derr == nil {
		seen := make(map[string]bool, len(out.Repositories))
		for _, repo := range out.Repositories {
			seen[repo] = true
		}
		for _, repo := range dbRepos {
			if !seen[repo] {
				out.Repositories = append(out.Repositories, repo)
				seen[repo] = true
			}
		}
		sort.Strings(out.Repositories)
	}
	// apply permissions: filter repositories by user permissions
	u := s.GetCurrentUser(r)
	if u != nil && !u.IsAdmin {
		perms, errPerm := s.store.ListUserPermissions(r.Context(), u.ID)
		if errPerm == nil && len(perms) > 0 {
			filtered := make([]string, 0, len(out.Repositories))
			for _, repo := range out.Repositories {
				// pattern match: exact repo or namespace prefix
				allowed := false
				for _, p := range perms {
					if p.CanRead && (repo == p.NamespacePattern || strings.HasPrefix(repo, p.NamespacePattern+"/")) {
						allowed = true
						break
					}
				}
				if allowed {
					filtered = append(filtered, repo)
				}
			}
			out.Repositories = filtered
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRepositorySubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/repositories/")
	if path == "" {
		http.NotFound(w, r)
		return
	}
	// Extract repo name (everything before the first known sub-suffix)
	repoName := extractRepoNameFromPath(path)
	if repoName != "" && !s.userCanAccessRepo(r, repoName) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden", "details": "no permission to access this repository"})
		return
	}
	client := s.client
	// Per-repo stats
	if strings.HasSuffix(path, "/stats") && r.Method == http.MethodGet {
		s.handleRepoStatsByRepo(w, r, client)
		return
	}
	// Per-repo tag policy
	if strings.HasSuffix(path, "/tag-policy") {
		s.handleRepoTagPolicy(w, r)
		return
	}
	// Initialize a new repo with minimal manifest
	if strings.HasSuffix(path, "/init") && r.Method == http.MethodPost {
		s.handleRepoInit(w, r, client)
		return
	}
	if strings.HasSuffix(path, "/manifests/batch-delete") && r.Method == http.MethodPost {
		s.handleBatchDelete(w, r, client)
		return
	}
	if strings.HasSuffix(path, "/retention-preview") && r.Method == http.MethodGet {
		s.handleRetentionPreview(w, r, client)
		return
	}
	if strings.HasSuffix(path, "/retention-run") && r.Method == http.MethodPost {
		s.handleRetentionRun(w, r, client)
		return
	}
	if strings.HasSuffix(path, "/tags") {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		name := strings.TrimSuffix(path, "/tags")
		out, err := client.Tags(r.Context(), name)
		if err != nil {
			// Registry may not know about the repo yet (e.g. UI-init empty repo).
			// Fallback to the tags stored in the local images table.
			if strings.Contains(err.Error(), "status=404") {
				rid, rerr := s.resolveRepo(r.Context(), name)
				if rerr == nil && rid > 0 {
					imgs, ierr := s.store.ListImagesByRepo(r.Context(), rid)
					if ierr == nil {
						dbTags := []string{}
						for _, img := range imgs {
							if !img.Deleted && img.Tag != "" && img.Tag != "_init" {
								dbTags = append(dbTags, img.Tag)
							}
						}
						writeJSON(w, http.StatusOK, map[string]any{"name": name, "tags": dbTags})
						return
					}
				}
			}
			writeError(w, http.StatusBadGateway, err)
			return
		}
		_ = s.store.AddRecent(r.Context(), s.currentUserID(r), name, "", "tags")
		// Respond immediately with the tag list. Syncing per-tag manifests
		// to the images table is an N+1 set of registry calls, so it runs
		// in the background on a detached context to avoid blocking the UI.
		s.syncTagsAsync(name, out.Tags)
		writeJSON(w, http.StatusOK, out)
		return
	}
	marker := "/manifests/"
	idx := strings.LastIndex(path, marker)
	if idx < 0 {
		http.NotFound(w, r)
		return
	}
	name := path[:idx]
	ref := path[idx+len(marker):]
	if name == "" || ref == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		out, err := client.Manifest(r.Context(), name, ref)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		// Sync image to images table
		digest := out.Digest
		if digest == "" {
			d, _, _ := client.Digest(r.Context(), name, ref)
			digest = d
		}
		if digest != "" {
			rid, _ := s.resolveRepo(r.Context(), name)
			if rid > 0 {
				_, _ = s.store.SyncImage(r.Context(), store.Image{RepositoryID: rid, Tag: ref, Digest: digest, ContentType: out.ContentType, Size: computeManifestSize(out.Manifest), ArtifactType: detectArtifactType(out.ContentType, out.Manifest)})
				shared, _ := s.store.ListTagsByDigest(r.Context(), rid, digest, ref)
				out.SharedTags = shared
			}
		}
		// Fetch config blob for image manifests to extract details
		out.Config = s.fetchImageConfig(client, name, out)
		out.ArtifactType = detectArtifactType(out.ContentType, out.Manifest)
		_ = s.store.AddRecent(r.Context(), s.currentUserID(r), name, ref, "manifest")
		writeJSON(w, http.StatusOK, out)
	case http.MethodHead:
		digest, contentType, err := client.Digest(r.Context(), name, ref)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		// A digest reference (sha256:...) is an explicit request to remove the
		// whole manifest, so delete it directly. A tag reference goes through
		// the tag-aware path: siblings sharing the digest are preserved by
		// re-pushing them, and the digest is only removed when its last tag is.
		if strings.HasPrefix(ref, "sha256:") {
			snapshotCount := s.snapshotRecycleItems(r, name, ref)
			if err := client.DeleteManifest(r.Context(), name, ref); err != nil {
				_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "delete", name, ref, ref, "error", err.Error())
				writeError(w, http.StatusBadGateway, err)
				return
			}
			s.fireWebhookEvent("delete", name, "", ref)
			rid, _ := s.resolveRepo(r.Context(), name)
			if rid > 0 {
				_ = s.store.SoftDeleteImageByDigest(r.Context(), rid, ref)
			}
			var imageID *int64
			if img, ierr := s.store.GetImageByDigest(r.Context(), ref); ierr == nil {
				imageID = &img.ID
			}
			_ = s.store.AddAuditWithImage(r.Context(), s.currentUserID(r), "delete", name, "", ref, "ok", "digest deleted; pending_gc snapshots can be restored before registry garbage-collect", imageID, name+"@"+ref)
			writeJSON(w, http.StatusAccepted, map[string]any{"deleted": true, "name": name, "digest": ref, "snapshotCount": snapshotCount, "gcRequired": true, "message": "digest deleted; restore from recycle bin before registry garbage-collect, or run GC later to reclaim storage"})
			return
		}
		results, snapshotCount := s.deleteTagsAware(r, name, []string{ref})
		ok := len(results) == 1 && results[0].Ok
		if !ok {
			errMsg := "delete failed"
			if len(results) == 1 && results[0].Error != "" {
				errMsg = results[0].Error
			}
			writeJSON(w, http.StatusBadGateway, map[string]any{"deleted": false, "name": name, "ref": ref, "error": errMsg, "results": results})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"deleted": true, "name": name, "ref": ref, "results": results, "snapshotCount": snapshotCount, "gcRequired": results[0].Action == "delete"})
	default:
		methodNotAllowed(w)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, err error) {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	writeJSON(w, status, registry.ErrorResponse{Error: http.StatusText(status), Details: detail})
}

// syncTagsAsync refreshes the images table for the given repo/tags in the
// background. It fetches each tag's manifest (N+1 against the registry) on a
// detached, time-bounded context so the foreground /tags response is not
// blocked. resolveRepo is done once up front.
func (s *Server) syncTagsAsync(name string, tags []string) {
	if len(tags) == 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		rid, err := s.resolveRepo(ctx, name)
		if err != nil || rid == 0 {
			return
		}
		for _, tag := range tags {
			m, err := s.client.Manifest(ctx, name, tag)
			if err != nil {
				continue
			}
			_, _ = s.store.SyncImage(ctx, store.Image{RepositoryID: rid, Tag: tag, Digest: m.Digest, Size: computeManifestSize(m.Manifest)})
		}
	}()
}

// SyncAll walks the registry catalog and writes repo+tag+digest into the
// images table. It uses SyncImage (not UpsertImage) so existing favorite
// and note fields are preserved. Failures on individual repos are logged
// and skipped; only a top-level error (e.g. registry unreachable) is returned.
func (s *Server) SyncAll(ctx context.Context) error {
	client := s.client
	var last string
	repoCount := 0
	imgCount := 0
	for {
		cat, err := client.Catalog(ctx, "100", last)
		if err != nil {
			log.Printf("startup sync: catalog failed: %v", err)
			return err
		}
		for _, name := range cat.Repositories {
			repoCount++
			tags, err := client.Tags(ctx, name)
			if err != nil {
				log.Printf("startup sync: tags failed for %s: %v", name, err)
				continue
			}
			for _, tag := range tags.Tags {
				m, err := client.Manifest(ctx, name, tag)
				if err != nil {
					log.Printf("startup sync: manifest failed for %s:%s: %v", name, tag, err)
					continue
				}
				rid, rerr := s.resolveRepo(ctx, name)
				if rerr != nil || rid == 0 {
					log.Printf("startup sync: resolveRepo failed for %s: %v", name, rerr)
					continue
				}
				if _, err := s.store.SyncImage(ctx, store.Image{RepositoryID: rid, Tag: tag, Digest: m.Digest, Size: computeManifestSize(m.Manifest)}); err != nil {
					log.Printf("startup sync: SyncImage failed for %s:%s: %v", name, tag, err)
					continue
				}
				imgCount++
			}
		}
		if cat.NextLast == "" {
			break
		}
		last = cat.NextLast
	}
	log.Printf("startup sync completed: %d repos, %d images", repoCount, imgCount)
	return nil
}
func methodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, registry.ErrorResponse{Error: "method not allowed"})
}
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
func parseID(s string) (int64, bool) {
	id, err := strconv.ParseInt(strings.Trim(s, "/"), 10, 64)
	return id, err == nil
}

func (s *Server) handleDiskUsage(w http.ResponseWriter, r *http.Request) {
	// Get stats from filesystem
	var registrySize int64 = 0
	registryDir := filepath.Join(s.cfg.DataDir, "registry")
	_ = filepath.WalkDir(registryDir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, e := d.Info(); e == nil {
				registrySize += info.Size()
			}
		}
		return nil
	})

	var totalSize int64 = 0
	_ = filepath.WalkDir(s.cfg.DataDir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, e := d.Info(); e == nil {
				totalSize += info.Size()
			}
		}
		return nil
	})

	// Count repositories and tags from database (avoids N+1 registry API calls)
	repoCount, tagCount, _, _ := s.store.GetGlobalImageStats(r.Context())
	// Get pending GC stats (only count digests no longer referenced by any active tag)
	pendingGCCount, pendingGCSizeBytes, _ := s.store.GetPendingGCStats(r.Context())

	writeJSON(w, http.StatusOK, map[string]any{
		"registrySizeBytes":  registrySize,
		"totalSizeBytes":     totalSize,
		"repositoryCount":    repoCount,
		"tagCount":           tagCount,
		"pendingGCCount":     pendingGCCount,
		"pendingGCSizeBytes": pendingGCSizeBytes,
	})
}

func (s *Server) handleRepoStatsByRepo(w http.ResponseWriter, r *http.Request, client *registry.Client) {
	path := strings.TrimPrefix(r.URL.Path, "/api/repositories/")
	name := strings.TrimSuffix(path, "/stats")
	// Get tag count and total size from database
	tagCount, totalSize, _ := s.store.GetRepoStats(r.Context(), name)
	// Fallback: if database has no records, use registry API
	if tagCount == 0 {
		tags, err := client.Tags(r.Context(), name)
		if err == nil {
			tagCount = len(tags.Tags)
		}
	}
	// Read per-repo tag policy settings, with global fallback
	protectionMode := s.resolveProtectionMode(r.Context(), name)
	overwriteAction := s.resolveOverwriteAction(r.Context(), name)
	keepCount := s.repoKeepCount(r.Context(), name)
	// Pending GC for this repo (only count digests no longer referenced by any active tag)
	pendingGCCount, pendingGCSize, _ := s.store.GetRepoPendingGCStats(r.Context(), name)
	writeJSON(w, http.StatusOK, map[string]any{
		"tagCount":        tagCount,
		"totalSize":       totalSize,
		"protectionMode":  protectionMode,
		"overwriteAction": overwriteAction,
		"keepCount":       keepCount,
		"pendingGCCount":  pendingGCCount,
		"pendingGCSize":   pendingGCSize,
		"anonymousPull":   s.isAnonymousPullAllowed(r.Context(), name),
		"pushCreateRepo":  s.pushCreateAllowed(r.Context(), name),
	})
}

func (s *Server) handleRepoTagPolicy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/repositories/")
	name := strings.TrimSuffix(path, "/tag-policy")
	switch r.Method {
	case http.MethodGet:
		protectionMode := s.resolveProtectionMode(r.Context(), name)
		overwriteAction := s.resolveOverwriteAction(r.Context(), name)
		keepCount := s.repoKeepCount(r.Context(), name)
		writeJSON(w, http.StatusOK, map[string]any{
			"protectionMode":  protectionMode,
			"overwriteAction": overwriteAction,
			"keepCount":       keepCount,
			"anonymousPull":   s.isAnonymousPullAllowed(r.Context(), name),
			"pushCreateRepo":  s.pushCreateAllowed(r.Context(), name),
		})
	case http.MethodPut:
		var req struct {
			ProtectionMode  string `json:"protectionMode"`
			OverwriteAction string `json:"overwriteAction"`
			KeepCount       int    `json:"keepCount"`
			AnonymousPull   *bool  `json:"anonymousPull"`
			PushCreateRepo  *bool  `json:"pushCreateRepo"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// All five per-repo tag-policy fields live in the repositories table.
		// Names without a namespace separator fall back to settings as a
		// defensive escape hatch (the API normally rejects such names).
		parts := strings.SplitN(name, "/", 2)
		hasRepo := len(parts) == 2
		// protection_mode
		pmCode := store.ProtectionStringToCode(req.ProtectionMode)
		if pmCode == store.ProtectionModeUnset {
			pmCode = store.ProtectionModeRules
		}
		if hasRepo {
			if err := s.store.SetRepositoryProtectionMode(r.Context(), parts[0], parts[1], pmCode); err == nil {
				_ = s.store.SetSetting(r.Context(), "protection_mode:"+name, "") // clear legacy
			} else {
				_ = s.store.SetSetting(r.Context(), "protection_mode:"+name, store.ProtectionCodeToString(pmCode))
			}
		} else {
			_ = s.store.SetSetting(r.Context(), "protection_mode:"+name, store.ProtectionCodeToString(pmCode))
		}
		// overwrite_action
		oaCode := store.OverwriteStringToCode(req.OverwriteAction)
		if oaCode == store.OverwriteActionUnset {
			oaCode = store.OverwriteActionRecycle
		}
		if hasRepo {
			if err := s.store.SetRepositoryOverwriteAction(r.Context(), parts[0], parts[1], oaCode); err == nil {
				_ = s.store.SetSetting(r.Context(), "overwrite_action:"+name, "") // clear legacy
			} else {
				_ = s.store.SetSetting(r.Context(), "overwrite_action:"+name, store.OverwriteCodeToString(oaCode))
			}
		} else {
			_ = s.store.SetSetting(r.Context(), "overwrite_action:"+name, store.OverwriteCodeToString(oaCode))
		}
		// retention_keep_count: write table only; also clear any stale
		// per-repo settings key so the GET path no longer reads them.
		if hasRepo {
			if err := s.store.SetRepositoryRetentionKeepCount(r.Context(), parts[0], parts[1], req.KeepCount); err == nil {
				_ = s.store.SetSetting(r.Context(), "retention_keep_count:"+name, "") // clear legacy
			}
		}
		if req.AnonymousPull != nil {
			if hasRepo {
				if err := s.store.SetRepositoryAnonymousPull(r.Context(), parts[0], parts[1], *req.AnonymousPull); err == nil {
					_ = s.store.SetSetting(r.Context(), "allow_anonymous_pull:"+name, "") // clear legacy
				} else {
					_ = s.store.SetSetting(r.Context(), "allow_anonymous_pull:"+name, strconv.FormatBool(*req.AnonymousPull))
				}
			} else {
				_ = s.store.SetSetting(r.Context(), "allow_anonymous_pull:"+name, strconv.FormatBool(*req.AnonymousPull))
			}
		}
		if req.PushCreateRepo != nil {
			if hasRepo {
				val := 0
				if *req.PushCreateRepo {
					val = 1
				}
				if err := s.store.SetRepositoryPushCreate(r.Context(), parts[0], parts[1], val); err == nil {
					_ = s.store.SetSetting(r.Context(), "push_create_repo:"+name, "") // clear legacy
				} else {
					_ = s.store.SetSetting(r.Context(), "push_create_repo:"+name, strconv.FormatBool(*req.PushCreateRepo))
				}
			} else {
				_ = s.store.SetSetting(r.Context(), "push_create_repo:"+name, strconv.FormatBool(*req.PushCreateRepo))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"saved": true})
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) pushCreateAllowed(ctx context.Context, repo string) bool {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) == 2 {
		if val, err := s.store.GetRepoPushCreate(ctx, parts[0], parts[1]); err == nil && val >= 0 {
			return val == 1
		}
	}
	// Global default: per the design specification push_create is enabled
	// by default ("v != 'false'") so we pass true as the default.
	return s.store.GetSettingBool(ctx, "push_create_repo", true)
}

// repoKeepCount returns the retention keep count for a repo, checking per-repo
// table first, then the global setting (default 0).
func (s *Server) repoKeepCount(ctx context.Context, repo string) int {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) == 2 {
		if val, err := s.store.GetRepoRetentionKeepCount(ctx, parts[0], parts[1]); err == nil && val >= 0 {
			return val
		}
	}
	return s.store.GetSettingInt(ctx, "retention_keep_count", 0)
}

// resolveProtectionMode returns the effective protection mode string for a
// repo, with the three-tier fallback: per-repo table -> global setting ->
// hardcoded "rules".
func (s *Server) resolveProtectionMode(ctx context.Context, repo string) string {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) == 2 {
		if code, err := s.store.GetRepoProtectionMode(ctx, parts[0], parts[1]); err == nil && code >= 0 {
			return store.ProtectionCodeToString(code)
		}
	}
	if v, _ := s.store.GetSetting(ctx, "protection_mode"); v != "" {
		return v
	}
	return "rules"
}

// resolveOverwriteAction returns the effective overwrite action string for a
// repo, with the three-tier fallback: per-repo table -> global setting ->
// hardcoded "recycle".
func (s *Server) resolveOverwriteAction(ctx context.Context, repo string) string {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) == 2 {
		if code, err := s.store.GetRepoOverwriteAction(ctx, parts[0], parts[1]); err == nil && code >= 0 {
			return store.OverwriteCodeToString(code)
		}
	}
	if v, _ := s.store.GetSetting(ctx, "overwrite_action"); v != "" {
		return v
	}
	return "recycle"
}

// resolveRepo resolves a repo name (e.g. "library/nginx") to a repository ID, creating namespace and repo if needed.
func (s *Server) resolveRepo(ctx context.Context, fullName string) (int64, error) {
	parts := strings.SplitN(fullName, "/", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid repo name: %s", fullName)
	}
	ns, err := s.store.UpsertNamespace(ctx, parts[0])
	if err != nil {
		return 0, err
	}
	repo, err := s.store.UpsertRepository(ctx, ns.ID, parts[1])
	if err != nil {
		return 0, err
	}
	return repo.ID, nil
}

func (s *Server) handleRepoInit(w http.ResponseWriter, r *http.Request, client *registry.Client) {
	path := strings.TrimPrefix(r.URL.Path, "/api/repositories/")
	name := strings.TrimSuffix(path, "/init")
	_, err := s.resolveRepo(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"created": true, "repo": name})
}

func (s *Server) handleBatchDelete(w http.ResponseWriter, r *http.Request, client *registry.Client) {
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/repositories/"), "/manifests/batch-delete")
	var req struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	results, snapshotCount := s.deleteTagsAware(r, name, req.Tags)
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "snapshotCount": snapshotCount})
}

// retentionCandidates groups images by digest, sorts the groups by the
// latest created_at within each group (descending), and returns the tags of
// the groups beyond the first keepCount.
func retentionCandidates(images []store.Image, keepCount int, registryTags map[string]bool) []struct {
	Digest    string    `json:"digest"`
	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"createdAt"`
} {
	if keepCount <= 0 {
		return nil
	}
	// Group by digest, keeping only tags that still exist in the registry.
	type group struct {
		digest   string
		tags     []string
		latestAt time.Time
	}
	groups := map[string]*group{}
	for _, img := range images {
		if img.Digest == "" || !registryTags[img.Tag] {
			continue
		}
		g, ok := groups[img.Digest]
		if !ok {
			g = &group{digest: img.Digest}
			groups[img.Digest] = g
		}
		g.tags = append(g.tags, img.Tag)
		if img.CreatedAt.After(g.latestAt) {
			g.latestAt = img.CreatedAt
		}
	}
	if len(groups) <= keepCount {
		return nil
	}
	// Sort groups by latestAt descending.
	var list []*group
	for _, g := range groups {
		list = append(list, g)
	}
	for i := 0; i < len(list)-1; i++ {
		for j := i + 1; j < len(list); j++ {
			if list[j].latestAt.After(list[i].latestAt) {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
	var out []struct {
		Digest    string    `json:"digest"`
		Tags      []string  `json:"tags"`
		CreatedAt time.Time `json:"createdAt"`
	}
	for i := keepCount; i < len(list); i++ {
		out = append(out, struct {
			Digest    string    `json:"digest"`
			Tags      []string  `json:"tags"`
			CreatedAt time.Time `json:"createdAt"`
		}{
			Digest:    list[i].digest,
			Tags:      list[i].tags,
			CreatedAt: list[i].latestAt,
		})
	}
	return out
}

func (s *Server) handleRetentionPreview(w http.ResponseWriter, r *http.Request, client *registry.Client) {
	path := strings.TrimPrefix(r.URL.Path, "/api/repositories/")
	name := strings.TrimSuffix(path, "/retention-preview")
	keepCountStr := r.URL.Query().Get("keepCount")
	var keepCount int
	if keepCountStr != "" {
		keepCount, _ = strconv.Atoi(keepCountStr)
	} else {
		keepCount = s.repoKeepCount(r.Context(), name)
	}
	if keepCount <= 0 {
		writeJSON(w, http.StatusOK, map[string]any{"keepCount": keepCount, "totalImages": 0, "candidates": []any{}})
		return
	}
	tagsResp, err := client.Tags(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	registryTags := map[string]bool{}
	for _, tag := range tagsResp.Tags {
		registryTags[tag] = true
	}
	rid, _ := s.resolveRepo(r.Context(), name)
	var candidates []any
	if rid > 0 {
		images, _ := s.store.ListImagesByRepo(r.Context(), rid)
		raw := retentionCandidates(images, keepCount, registryTags)
		for _, c := range raw {
			candidates = append(candidates, map[string]any{
				"digest":    c.Digest,
				"tags":      c.Tags,
				"createdAt": c.CreatedAt.Format(time.RFC3339),
			})
		}
	}
	if candidates == nil {
		candidates = []any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"keepCount":   keepCount,
		"totalImages": len(registryTags),
		"candidates":  candidates,
	})
}

func (s *Server) handleRetentionRun(w http.ResponseWriter, r *http.Request, client *registry.Client) {
	path := strings.TrimPrefix(r.URL.Path, "/api/repositories/")
	name := strings.TrimSuffix(path, "/retention-run")
	var req struct {
		KeepCount int `json:"keepCount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.KeepCount <= 0 {
		writeJSON(w, http.StatusOK, map[string]any{"deleted": []any{}, "snapshotCount": 0})
		return
	}
	tagsResp, err := client.Tags(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	registryTags := map[string]bool{}
	for _, tag := range tagsResp.Tags {
		registryTags[tag] = true
	}
	rid, _ := s.resolveRepo(r.Context(), name)
	var allCandidateTags []string
	if rid > 0 {
		images, _ := s.store.ListImagesByRepo(r.Context(), rid)
		candidates := retentionCandidates(images, req.KeepCount, registryTags)
		for _, c := range candidates {
			allCandidateTags = append(allCandidateTags, c.Tags...)
		}
	}
	var results []tagDeleteResult
	snapshotCount := 0
	if len(allCandidateTags) > 0 {
		results, snapshotCount = s.deleteTagsAware(r, name, allCandidateTags)
	}
	if results == nil {
		results = []tagDeleteResult{}
	}
	_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "retention.run", name, "", "", "ok", fmt.Sprintf("keepCount=%d, deleted=%d", req.KeepCount, len(results)))
	writeJSON(w, http.StatusOK, map[string]any{
		"deleted":       results,
		"snapshotCount": snapshotCount,
	})
}

func (s *Server) handleNamespaces(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		nss, err := s.store.ListNamespaces(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"namespaces": nss})
	case http.MethodPost:
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		ns, err := s.store.UpsertNamespace(r.Context(), req.Name)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, ns)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleNamespaceByName(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/namespaces/")
	if name == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		ns, err := s.store.GetNamespace(r.Context(), name)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		if err := s.store.DeleteNamespace(r.Context(), ns.ID); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "namespace.delete", name, "", "", "ok", "")
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := s.GetCurrentUser(r)
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleMyPermissions(w http.ResponseWriter, r *http.Request) {
	u := s.GetCurrentUser(r)
	if u == nil || u.IsAdmin {
		// admin has all permissions
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	perms, err := s.store.ListUserPermissions(r.Context(), u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, perms)
}

// fetchImageConfig attempts to fetch and parse the image config blob from a manifest
func (s *Server) fetchImageConfig(client *registry.Client, repo string, m registry.ManifestResponse) *registry.ImageConfig {
	if m.Manifest == nil {
		return nil
	}
	manifest, ok := m.Manifest.(map[string]any)
	if !ok {
		return nil
	}
	cfg, ok := manifest["config"].(map[string]any)
	if !ok {
		return nil
	}
	digest, _ := cfg["digest"].(string)
	if digest == "" {
		return nil
	}
	body, contentType, err := client.Blob(context.Background(), repo, digest)
	if err != nil || len(body) == 0 {
		return nil
	}
	var raw struct {
		Created      string          `json:"created"`
		Architecture string          `json:"architecture"`
		OS           string          `json:"os"`
		Config       json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	_ = contentType // unused but available
	ic := &registry.ImageConfig{
		Created:      raw.Created,
		Architecture: raw.Architecture,
		OS:           raw.OS,
	}
	if raw.Config != nil {
		var inner struct {
			Entrypoint   []string          `json:"Entrypoint"`
			Cmd          []string          `json:"Cmd"`
			Env          []string          `json:"Env"`
			ExposedPorts map[string]any    `json:"ExposedPorts"`
			Volumes      map[string]any    `json:"Volumes"`
			Labels       map[string]string `json:"Labels"`
			WorkingDir   string            `json:"WorkingDir"`
		}
		if err := json.Unmarshal(raw.Config, &inner); err == nil {
			ic.Entrypoint = inner.Entrypoint
			ic.Cmd = inner.Cmd
			ic.Env = inner.Env
			ic.WorkingDir = inner.WorkingDir
			ic.Labels = inner.Labels
			if inner.ExposedPorts != nil {
				for p := range inner.ExposedPorts {
					ic.Ports = append(ic.Ports, p)
				}
			}
			if inner.Volumes != nil {
				for v := range inner.Volumes {
					ic.Volumes = append(ic.Volumes, v)
				}
			}
		}
	}
	return ic
}

// detectArtifactType determines the artifact type from content type and manifest structure
func detectArtifactType(contentType string, manifest any) string {
	if manifest == nil {
		return ""
	}
	m, ok := manifest.(map[string]any)
	if !ok {
		return ""
	}
	schemaVersion, _ := m["schemaVersion"].(float64)
	mediaType, _ := m["mediaType"].(string)
	// OCI manifests may omit mediaType in the JSON body; fall back to the
	// HTTP Content-Type header so we can still identify helm charts, SBOMs, etc.
	if mediaType == "" {
		mediaType = contentType
	}

	switch mediaType {
	case "application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.index.v1+json":
		return "manifest-list"
	case "application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json":
		// Determine more specific type from config mediaType
		if cfg, ok := m["config"].(map[string]any); ok {
			if cfgMT, ok := cfg["mediaType"].(string); ok {
				switch cfgMT {
				case "application/vnd.docker.container.image.v1+json":
					return "image"
				case "application/vnd.oci.image.config.v1+json":
					return "image"
				case "application/vnd.cncf.helm.config.v1+json":
					return "helm-chart"
				case "application/vnd.syft+json":
					return "sbom"
				case "application/spdx+json", "application/vnd.spdx+json":
					return "sbom"
				case "application/vnd.cyclonedx+json":
					return "sbom"
				case "application/vnd.dsse+json":
					return "attestation"
				}
			}
		}
		return "image"
	case "application/vnd.docker.distribution.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v1+prettyjws":
		return "image-legacy"
	}
	if schemaVersion > 0 {
		return "unknown"
	}
	return ""
}

// RunRegistryGC processes pending_gc recycle-bin items: deletes the manifest
// from the upstream registry, then removes the local SQLite row.
// When all=true it processes every pending item (manual GC); when false it
// respects recycleGCDays (automatic GC).
func (s *Server) RunRegistryGC(ctx context.Context, all bool) (int, error) {
	s.gcLock.Lock()
	s.gcRunning = true
	s.gcLock.Unlock()
	defer func() {
		s.gcLock.Lock()
		s.gcRunning = false
		s.gcLock.Unlock()
	}()

	days := 0
	if !all {
		days = s.store.GetSettingInt(ctx, "recycleGCDays", 30)
		if days < 0 {
			days = 30
		}
		if days == 0 {
			log.Printf("GC skipped: recycleGCDays=0 (disabled)")
			return 0, nil
		}
	}
	items, err := s.store.ListPendingGC(ctx, days)
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, item := range items {
		if item.Digest == "" {
			_ = s.store.DeleteRecycleItem(ctx, item.ID)
			deleted++
			continue
		}
		if err := s.client.DeleteManifest(ctx, item.Repo, item.Digest); err != nil {
			if strings.Contains(err.Error(), "status=404") {
				// Manifest already gone; safe to clean up local record.
				log.Printf("GC: manifest already deleted repo=%s digest=%s", item.Repo, item.Digest)
			} else {
				log.Printf("GC: DeleteManifest failed repo=%s digest=%s: %v", item.Repo, item.Digest, err)
				continue
			}
		}
		if err := s.store.DeleteRecycleItem(ctx, item.ID); err != nil {
			log.Printf("GC: DeleteRecycleItem failed id=%d: %v", item.ID, err)
			continue
		}
		_ = s.store.AddAudit(ctx, 0, "gc.delete", item.Repo, item.Reference, item.Digest, "ok", "manifest deleted via GC")
		deleted++
	}
	return deleted, nil
}

func (s *Server) handleGCRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	deleted, err := s.RunRegistryGC(r.Context(), true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	blobDeleted, freed, err := s.RunBlobGC(r.Context())
	if err != nil {
		log.Printf("manual blob GC failed: %v", err)
	}
	_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "gc.run", "", "", "", "ok", fmt.Sprintf("deleted %d items, blobDeleted=%d, freed=%d", deleted, blobDeleted, freed))
	writeJSON(w, http.StatusOK, map[string]any{"deletedCount": deleted, "blobDeleted": blobDeleted, "freedBytes": freed})
}

// RunBlobGC executes `registry garbage-collect` to reclaim blob storage.
// It returns the number of blobs deleted and approximate freed bytes.
func (s *Server) RunBlobGC(ctx context.Context) (int, int64, error) {
	configPath := s.cfg.RegistryConfig
	if configPath == "" {
		configPath = "/etc/distribution/config.yml"
	}
	cmd := exec.CommandContext(ctx, "registry", "garbage-collect", configPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, 0, fmt.Errorf("registry garbage-collect failed: %w (output: %s)", err, string(out))
	}
	// Parse output to count deleted blobs and freed space
	deleted := 0
	var freed int64
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "blob deleted") || strings.Contains(line, "manifest deleted") {
			deleted++
		}
		// Attempt to extract size from lines like "... size=12345 ..."
		if idx := strings.Index(line, "size="); idx >= 0 {
			rest := line[idx+5:]
			if end := strings.IndexAny(rest, " \t\"'"); end > 0 {
				rest = rest[:end]
			}
			if n, err := strconv.ParseInt(rest, 10, 64); err == nil {
				freed += n
			}
		}
	}
	return deleted, freed, nil
}
