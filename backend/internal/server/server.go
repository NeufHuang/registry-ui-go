package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// registryTarget is cfg.RegistryURL parsed once at construction, so the
	// /v2/ proxy does not re-parse it on every request.
	registryTarget *url.URL
	mux            *http.ServeMux
	sessionStore   sync.Map
	// gcRunning is read by the /v2/ write gate; gcBusy is the single-run
	// gate that stops two garbage-collect processes from running at once.
	gcRunning atomic.Bool
	gcBusy    atomic.Bool
	restartCh chan struct{}
	// tagSyncs collapses concurrent background tag refreshes per repo.
	tagSyncs sync.Map
}

func New(cfg config.Config, st *store.Store) *Server {
	cfg.RegistryURL = strings.TrimRight(cfg.RegistryURL, "/")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.RegistryTLSSkipVerify {
		transport.TLSClientConfig = cfg.RegistryTLSConfig()
	}
	s := &Server{cfg: cfg, store: st, client: registry.NewClient(cfg), proxyTransport: transport, mux: http.NewServeMux(), restartCh: make(chan struct{}, 1)}
	if target, err := url.Parse(cfg.RegistryURL); err == nil {
		s.registryTarget = target
	}
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
	s.mux.HandleFunc("/api/gc/status", s.handleGCStatus)
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

// userCanWriteRepo returns true if the current user can write to the given repo.
// Admins can write to all repos. Non-admins need CanWrite on a matching namespace.
func (s *Server) userCanWriteRepo(r *http.Request, repo string) bool {
	u := s.GetCurrentUser(r)
	if u == nil || u.IsAdmin {
		return true
	}
	perms, err := s.store.ListUserPermissions(r.Context(), u.ID)
	if err != nil || len(perms) == 0 {
		return false
	}
	for _, p := range perms {
		if p.CanWrite && (repo == p.NamespacePattern || strings.HasPrefix(repo, p.NamespacePattern+"/")) {
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
	repos, err := s.store.ListAllRepoNames(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// apply permissions: filter repositories by user permissions
	u := s.GetCurrentUser(r)
	if u != nil && !u.IsAdmin {
		perms, errPerm := s.store.ListUserPermissions(r.Context(), u.ID)
		if errPerm != nil {
			// Fail closed: a broken permission lookup must never hand the
			// full catalog to a non-admin.
			writeError(w, http.StatusInternalServerError, errPerm)
			return
		}
		filtered := make([]string, 0, len(repos))
		for _, repo := range repos {
			for _, p := range perms {
				if p.CanRead && (repo == p.NamespacePattern || strings.HasPrefix(repo, p.NamespacePattern+"/")) {
					filtered = append(filtered, repo)
					break
				}
			}
		}
		repos = filtered
	}
	// Paginate to match CatalogResponse shape
	n := r.URL.Query().Get("n")
	last := r.URL.Query().Get("last")
	pageSize := 100
	if n != "" {
		if ps, _ := strconv.Atoi(n); ps > 0 {
			pageSize = ps
		}
	}
	start := 0
	if last != "" {
		// An unknown cursor must end the pagination, not restart it: falling
		// back to 0 made the client fetch the first page again and again.
		start = len(repos)
		for i, repo := range repos {
			if repo > last {
				start = i
				break
			}
		}
	}
	end := start + pageSize
	if end > len(repos) {
		end = len(repos)
	}
	resp := map[string]any{
		"repositories": repos[start:end],
	}
	if end < len(repos) {
		resp["nextLast"] = repos[end-1]
	}
	writeJSON(w, http.StatusOK, resp)
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
	// Mutating subroutes (tag-policy PUT, batch-delete, manifest DELETE,
	// retention-run, init) additionally require write permission. The read
	// check above is not enough: it used to let a read-only user delete images
	// and disable immutable-tag protection through the UI API, even though the
	// /v2/ proxy path already enforced canWrite.
	if isMutatingMethod(r.Method) {
		if repoName == "" || !s.userCanWriteRepo(r, repoName) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden", "details": "no write permission for this repository"})
			return
		}
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
			if registry.IsStatus(err, http.StatusNotFound) {
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
		out.Config = s.fetchImageConfig(r.Context(), client, name, out)
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
			// Clean up DB record if no tags remain (or repo already gone from registry).
			if tagsResp, err := client.Tags(r.Context(), name); (err == nil && len(tagsResp.Tags) == 0) || (err != nil && registry.IsStatus(err, http.StatusNotFound)) {
				s.cleanupRepoDB(r.Context(), name)
			}
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
	// Collapse concurrent refreshes of the same repo: without this, a burst of
	// /tags requests started one full N+1 registry walk per request.
	if _, loaded := s.tagSyncs.LoadOrStore(name, struct{}{}); loaded {
		return
	}
	go func() {
		defer s.tagSyncs.Delete(name)
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

// isMutatingMethod reports whether an HTTP method changes server state and
// therefore needs write, rather than read, authorization.
func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// requireAdmin writes a 403 and returns false unless the caller is an
// administrator. When AUTH_MODE=off GetCurrentUser is nil and the endpoint
// stays open, matching the settings/GC surface; an authenticated non-admin is
// always rejected.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if u := s.GetCurrentUser(r); u != nil && !u.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden", "details": "administrator privileges required"})
		return false
	}
	return true
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
	// Get stats from filesystem. Report the directory GC actually operates on
	// (RegistryDataDir, not a hardcoded DataDir/registry guess) so the size
	// shown here matches what blob GC can reclaim.
	registrySize := dirSizeBytes(s.cfg.RegistryDataDir)
	totalSize := dirSizeBytes(s.cfg.DataDir)

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
		} else {
			// Single-segment repo: no repositories row, so persist the value
			// under the per-repo settings key that repoKeepCount reads.
			keep := req.KeepCount
			if keep < 0 {
				keep = 0
			}
			_ = s.store.SetSetting(r.Context(), "retention_keep_count:"+name, strconv.Itoa(keep))
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
	// Single-level repos store their per-repo flag under "push_create_repo:<repo>".
	if v, err := s.store.GetSetting(ctx, "push_create_repo:"+repo); err == nil && v != "" {
		return v == "true"
	}
	// Global default: per the design specification push_create is enabled
	// by default ("v != 'false'") so we pass true as the default.
	return s.store.GetSettingBool(ctx, "push_create_repo", true)
}

// repoKeepCount returns the retention keep count for a repo, checking per-repo
// table first, then the per-repo settings fallback used by single-segment
// repos, then the global setting (default 0).
func (s *Server) repoKeepCount(ctx context.Context, repo string) int {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) == 2 {
		if val, err := s.store.GetRepoRetentionKeepCount(ctx, parts[0], parts[1]); err == nil && val >= 0 {
			return val
		}
	}
	// Single-level repos store their per-repo value under the
	// "retention_keep_count:<repo>" settings key (same pattern as
	// protection_mode / overwrite_action / push_create_repo).
	if v, err := s.store.GetSetting(ctx, "retention_keep_count:"+repo); err == nil && v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	global := s.store.GetSettingInt(ctx, "retention_keep_count", 0)
	if global < 0 {
		global = 0
	}
	return global
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
	// Single-level repos store their per-repo flag under "protection_mode:<repo>".
	if v, err := s.store.GetSetting(ctx, "protection_mode:"+repo); err == nil && v != "" {
		return v
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
	// Single-level repos store their per-repo flag under "overwrite_action:<repo>".
	if v, err := s.store.GetSetting(ctx, "overwrite_action:"+repo); err == nil && v != "" {
		return v
	}
	if v, _ := s.store.GetSetting(ctx, "overwrite_action"); v != "" {
		return v
	}
	return "recycle"
}

// resolveRepo resolves a repo name (e.g. "library/nginx") to a repository ID, creating namespace and repo if needed.
func (s *Server) resolveRepo(ctx context.Context, fullName string) (int64, error) {
	parts := strings.SplitN(fullName, "/", 2)
	nsName := ""
	repoName := fullName
	if len(parts) == 2 {
		nsName = parts[0]
		repoName = parts[1]
	}
	ns, err := s.store.UpsertNamespace(ctx, nsName)
	if err != nil {
		return 0, err
	}
	repo, err := s.store.UpsertRepository(ctx, ns.ID, repoName)
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
		writeJSON(w, http.StatusOK, map[string]any{"namespaces": s.filterVisibleNamespaces(r, nss)})
	case http.MethodPost:
		if !s.requireAdmin(w, r) {
			return
		}
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

// filterVisibleNamespaces hides namespaces a non-admin has no read permission
// on, so the namespace picker cannot be used to enumerate the whole registry.
func (s *Server) filterVisibleNamespaces(r *http.Request, nss []store.Namespace) []store.Namespace {
	u := s.GetCurrentUser(r)
	if u == nil || u.IsAdmin {
		return nss
	}
	perms, err := s.store.ListUserPermissions(r.Context(), u.ID)
	if err != nil {
		return []store.Namespace{}
	}
	out := make([]store.Namespace, 0, len(nss))
	for _, ns := range nss {
		for _, p := range perms {
			if p.CanRead && (ns.Name == p.NamespacePattern || strings.HasPrefix(ns.Name, p.NamespacePattern+"/")) {
				out = append(out, ns)
				break
			}
		}
	}
	return out
}

func (s *Server) handleNamespaceByName(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/namespaces/")
	if name == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if !s.requireAdmin(w, r) {
			return
		}
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
func (s *Server) fetchImageConfig(ctx context.Context, client *registry.Client, repo string, m registry.ManifestResponse) *registry.ImageConfig {
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
	// Bounded so a stalled registry cannot pin the request goroutine forever
	// (this used to run on context.Background with no deadline at all).
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	body, contentType, err := client.Blob(ctx, repo, digest)
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

const (
	// defaultRegistryConfigPath mirrors config.Load's default.
	defaultRegistryConfigPath = "/etc/distribution/config.yml"
	// gcMaxAttempts is how many times a single recycle item may fail before it
	// is parked as gc_failed instead of being retried on every GC run.
	gcMaxAttempts = 5
	// gcDrainDelay lets in-flight push/upload requests finish after the push
	// gate closes and before garbage-collect touches storage.
	gcDrainDelay = 2 * time.Second
	// gcMetadataTimeout and gcBlobTimeout bound the detached GC phases.
	gcMetadataTimeout = 5 * time.Minute
	gcBlobTimeout     = 10 * time.Minute
)

var errGCAlreadyRunning = errors.New("garbage collection already running")

// GCResult is the structured outcome of a GC run. BlobError is reported
// separately from MetadataError so the UI can say "metadata cleaned, storage
// not reclaimed" instead of showing an unconditional success.
type GCResult struct {
	MetadataDeleted int    `json:"deletedCount"`
	BlobDeleted     int    `json:"blobDeleted"`
	FreedBytes      int64  `json:"freedBytes"`
	BlobError       string `json:"blobError,omitempty"`
	MetadataError   string `json:"metadataError,omitempty"`
	Skipped         bool   `json:"skipped,omitempty"`
	Busy            bool   `json:"-"`
}

// beginGC claims the single GC slot and marks GC running for the /v2/ write
// gate. It fails fast when another GC (manual or scheduled) is already active,
// which also prevents two `garbage-collect` processes from touching the same
// storage root concurrently.
func (s *Server) beginGC() error {
	if !s.gcBusy.CompareAndSwap(false, true) {
		return errGCAlreadyRunning
	}
	s.gcRunning.Store(true)
	return nil
}

func (s *Server) endGC() {
	s.gcRunning.Store(false)
	s.gcBusy.Store(false)
}

// gcRetentionDays returns the configured retention window and whether
// automatic/manual retention-based GC is disabled (recycleGCDays=0).
func (s *Server) gcRetentionDays(ctx context.Context) (int, bool) {
	days := s.store.GetSettingInt(ctx, "recycleGCDays", 30)
	if days < 0 {
		days = 30
	}
	if days == 0 {
		return 0, true
	}
	return days, false
}

// RunRegistryGC processes pending_gc recycle-bin items: deletes the manifest
// from the upstream registry, then removes the local SQLite row.
// When all=true it processes every pending item (explicit purge); when false
// it respects recycleGCDays.
func (s *Server) RunRegistryGC(ctx context.Context, all bool) (int, error) {
	if err := s.beginGC(); err != nil {
		return 0, err
	}
	defer s.endGC()
	deleted, _, err := s.runRegistryGC(ctx, all)
	return deleted, err
}

// RunGC executes a complete GC cycle (metadata sweep + blob garbage-collect)
// while holding the push gate for the whole duration. Previously gcRunning was
// cleared as soon as the metadata sweep returned, so pushes were allowed again
// while `garbage-collect` was still running — the exact window in which a
// freshly pushed manifest can be treated as unreferenced and deleted.
func (s *Server) RunGC(ctx context.Context, all bool) GCResult {
	var res GCResult
	if err := s.beginGC(); err != nil {
		res.MetadataError = err.Error()
		res.Busy = true
		return res
	}
	defer s.endGC()

	// Give requests that already passed the gate a moment to complete before
	// storage is walked.
	if err := sleepCtx(ctx, gcDrainDelay); err != nil {
		res.MetadataError = err.Error()
		return res
	}
	deleted, skipped, err := s.runRegistryGC(ctx, all)
	res.MetadataDeleted = deleted
	res.Skipped = skipped
	if err != nil {
		res.MetadataError = err.Error()
	}
	blobDeleted, freed, berr := s.runBlobGC(ctx)
	res.BlobDeleted = blobDeleted
	res.FreedBytes = freed
	if berr != nil {
		res.BlobError = berr.Error()
	}
	return res
}

// runRegistryGC is the gate-free core of the metadata GC.
func (s *Server) runRegistryGC(ctx context.Context, all bool) (int, bool, error) {
	var items []store.RecycleItem
	var err error
	if all {
		items, err = s.store.ListAllPendingGC(ctx)
	} else {
		days, disabled := s.gcRetentionDays(ctx)
		if disabled {
			log.Printf("GC skipped: recycleGCDays=0 (disabled)")
			return 0, true, nil
		}
		items, err = s.store.ListPendingGC(ctx, days)
	}
	if err != nil {
		return 0, false, err
	}
	deleted, err := s.processGCItems(ctx, items)
	return deleted, false, err
}

// processGCItems deletes the manifests behind recycle-bin items and removes
// their local rows. Before deleting by digest it verifies the digest is no
// longer referenced by any live tag, so a stale or untag snapshot can never
// wipe tags that were meant to survive.
func (s *Server) processGCItems(ctx context.Context, items []store.RecycleItem) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	deleted := 0
	liveCache := map[string]map[string]bool{}
	for _, item := range items {
		if item.Digest == "" {
			_ = s.store.DeleteRecycleItem(ctx, item.ID)
			deleted++
			continue
		}
		live, ok := liveCache[item.Repo]
		if !ok {
			var lerr error
			live, lerr = s.liveDigestsForRepo(ctx, item.Repo)
			if lerr != nil {
				if registry.IsStatus(lerr, http.StatusNotFound) {
					// Repository no longer exists: nothing can be referenced.
					live = map[string]bool{}
				} else {
					log.Printf("GC: cannot verify live tags repo=%s: %v", item.Repo, lerr)
					s.recordGCFailure(ctx, item, lerr)
					continue
				}
			}
			liveCache[item.Repo] = live
		}
		if live[item.Digest] {
			// A live tag still points at this digest (stale snapshot, or a
			// proxy DELETE that failed / only untagged). Deleting by digest
			// would remove those tags too; drop the stale record instead.
			log.Printf("GC: digest still referenced by a live tag, dropping stale record repo=%s ref=%s digest=%s", item.Repo, item.Reference, item.Digest)
			if err := s.store.DeleteRecycleItem(ctx, item.ID); err != nil {
				log.Printf("GC: DeleteRecycleItem failed id=%d: %v", item.ID, err)
				continue
			}
			deleted++
			continue
		}
		if err := s.client.DeleteManifest(ctx, item.Repo, item.Digest); err != nil {
			if registry.IsStatus(err, http.StatusNotFound) {
				// Manifest already gone; safe to clean up local record.
				log.Printf("GC: manifest already deleted repo=%s digest=%s", item.Repo, item.Digest)
			} else {
				log.Printf("GC: DeleteManifest failed repo=%s digest=%s: %v", item.Repo, item.Digest, err)
				s.recordGCFailure(ctx, item, err)
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

// recordGCFailure increments an item's failure counter and parks it as
// gc_failed after gcMaxAttempts so a permanently broken record cannot make
// every future GC run hammer the registry with doomed deletes.
func (s *Server) recordGCFailure(ctx context.Context, item store.RecycleItem, cause error) {
	// Only count failures where the registry actually answered. A transport or
	// timeout error just means the registry was unreachable this run; counting
	// it would park otherwise-fine items after a short outage.
	if _, ok := registry.StatusCode(cause); !ok {
		log.Printf("GC: transient failure id=%d (attempt not counted): %v", item.ID, cause)
		return
	}
	failed, err := s.store.MarkRecycleGCFailure(ctx, item.ID, cause.Error(), gcMaxAttempts)
	if err != nil {
		log.Printf("GC: MarkRecycleGCFailure failed id=%d: %v", item.ID, err)
		return
	}
	if failed {
		log.Printf("GC: recycle item id=%d parked as gc_failed after %d attempts: %v", item.ID, gcMaxAttempts, cause)
	}
}

// liveDigestsForRepo returns the set of manifest digests currently referenced
// by at least one tag in the repository.
func (s *Server) liveDigestsForRepo(ctx context.Context, repo string) (map[string]bool, error) {
	tags, err := s.client.Tags(ctx, repo)
	if err != nil {
		return nil, err
	}
	live := make(map[string]bool, len(tags.Tags))
	for _, tag := range tags.Tags {
		d, _, derr := s.client.Digest(ctx, repo, tag)
		if derr != nil || d == "" {
			continue
		}
		live[d] = true
	}
	return live, nil
}

// gcRequestAll reports whether the caller explicitly asked to purge the whole
// recycle bin (query ?all=true or JSON body {"all":true}). Without it, GC
// honours recycleGCDays.
func gcRequestAll(r *http.Request) bool {
	v := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("all")))
	if v == "true" || v == "1" {
		return true
	}
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			All bool `json:"all"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&body); err == nil {
			return body.All
		}
	}
	return false
}

func (s *Server) handleGCRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	// Admin only: GC permanently deletes recycle-bin records and blocks all
	// pushes while it runs. When AUTH_MODE=off GetCurrentUser is nil and the
	// endpoint stays open, matching the rest of the settings surface.
	if u := s.GetCurrentUser(r); u != nil && !u.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden", "details": "garbage collection requires an administrator account"})
		return
	}
	all := gcRequestAll(r)
	// Detached context: a long GC must not be cancelled because the browser
	// closed the tab (that used to kill the garbage-collect child process).
	ctx, cancel := context.WithTimeout(context.Background(), gcMetadataTimeout+gcBlobTimeout)
	defer cancel()
	res := s.RunGC(ctx, all)
	if res.MetadataError != "" {
		status := http.StatusInternalServerError
		if res.Busy {
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]any{"error": res.MetadataError})
		return
	}
	detail := fmt.Sprintf("deleted=%d blobDeleted=%d freed=%d all=%t", res.MetadataDeleted, res.BlobDeleted, res.FreedBytes, all)
	if res.BlobError != "" {
		detail += " blobError=" + res.BlobError
	}
	_ = s.store.AddAudit(ctx, s.currentUserID(r), "gc.run", "", "", "", "ok", detail)
	writeJSON(w, http.StatusOK, res)
}

// handleGCStatus reports whether a GC run is currently in progress. It is a
// lightweight poll target so clients do not have to hang on the long-running
// POST /api/gc/run request just to know when GC finished.
func (s *Server) handleGCStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"running": s.gcRunning.Load()})
}

// RunBlobGC executes `registry garbage-collect` to reclaim blob storage,
// behind the single-run gate. It returns the number of blobs deleted and
// approximate freed bytes.
func (s *Server) RunBlobGC(ctx context.Context) (int, int64, error) {
	if err := s.beginGC(); err != nil {
		return 0, 0, err
	}
	defer s.endGC()
	return s.runBlobGC(ctx)
}

// runBlobGC is the gate-free core that shells out to the registry binary.
func (s *Server) runBlobGC(ctx context.Context) (int, int64, error) {
	configPath := s.cfg.RegistryConfig
	if configPath == "" {
		configPath = defaultRegistryConfigPath
	}
	// Preflight: fail with an actionable reason instead of spawning a command
	// that is guaranteed to fail (or, worse, to scan the wrong storage root).
	if _, err := exec.LookPath("registry"); err != nil {
		return 0, 0, fmt.Errorf("registry binary not available in PATH: %w", err)
	}
	if _, err := os.Stat(configPath); err != nil {
		return 0, 0, fmt.Errorf("registry config %s is not readable: %w", configPath, err)
	}
	if root := registryRootDirectory(configPath); root != "" && s.cfg.RegistryDataDir != "" {
		if !sameDirectory(root, s.cfg.RegistryDataDir) {
			return 0, 0, fmt.Errorf("refusing blob GC: config %s rootdirectory=%q does not match REGISTRY_DATA_DIR=%q; run garbage-collect inside the registry container instead", configPath, root, s.cfg.RegistryDataDir)
		}
	}
	before := dirSizeBytes(s.cfg.RegistryDataDir)
	cmd := exec.CommandContext(ctx, "registry", "garbage-collect", configPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, 0, fmt.Errorf("registry garbage-collect failed: %w (output: %s)", err, truncateOutput(string(out)))
	}
	deleted := countGCDeletions(string(out))
	after := dirSizeBytes(s.cfg.RegistryDataDir)
	freed := before - after
	if freed < 0 {
		freed = 0
	}
	s.cleanupEmptyRepoDirs()
	return deleted, freed, nil
}

// registryRootDirectory extracts storage.filesystem.rootdirectory from a
// distribution config file with a deliberately tiny line scanner (the project
// has no YAML dependency). Returns "" when the key is absent or unreadable.
func registryRootDirectory(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if !strings.HasPrefix(l, "rootdirectory:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(l, "rootdirectory:"))
		if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		v = strings.Trim(v, `"'`)
		if v == "" {
			return ""
		}
		if abs, err := filepath.Abs(v); err == nil {
			return abs
		}
		return v
	}
	return ""
}

// sameDirectory compares two directory paths, resolving symlinks when the
// direct comparison fails (e.g. a bind mount).
func sameDirectory(a, b string) bool {
	aa, err := filepath.Abs(a)
	if err != nil {
		aa = filepath.Clean(a)
	}
	bb, err := filepath.Abs(b)
	if err != nil {
		bb = filepath.Clean(b)
	}
	if aa == bb {
		return true
	}
	ra, erra := filepath.EvalSymlinks(aa)
	rb, errb := filepath.EvalSymlinks(bb)
	return erra == nil && errb == nil && ra == rb
}

// dirSizeBytes sums the size of every regular file below root.
func dirSizeBytes(root string) int64 {
	if root == "" {
		return 0
	}
	var total int64
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		if info, e := d.Info(); e == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

// countGCDeletions counts blobs/manifests reported as deleted by
// `registry garbage-collect`. Its output format is logrus-based and has no
// size= field, which is why freed bytes are measured by directory delta
// instead of parsed from stdout.
func countGCDeletions(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Deleting blob") || strings.Contains(line, "Deleting manifest") {
			n++
		}
	}
	return n
}

func truncateOutput(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 2000 {
		return s[len(s)-2000:]
	}
	return s
}

// sleepCtx waits for d or until ctx is done, whichever comes first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// cleanupEmptyRepoDirs scans the registry filesystem for empty repository
// directories and removes them. Called after garbage-collect.
func (s *Server) cleanupEmptyRepoDirs() {
	if s.cfg.RegistryDataDir == "" {
		return
	}
	base := filepath.Join(s.cfg.RegistryDataDir, "docker", "registry", "v2", "repositories")
	if info, err := os.Stat(base); err != nil || !info.IsDir() {
		// Non-filesystem driver, or a different layout (registry v3 storage
		// backends). Do not guess: leave directory maintenance to the
		// registry itself.
		log.Printf("cleanupEmptyRepoDirs: %s not present, skipping", base)
		return
	}
	// Collect directories first, then remove deepest-first: deleting a parent
	// while WalkDir still has children queued makes the walk report errors.
	var dirs []string
	_ = filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && path != base {
			dirs = append(dirs, path)
		}
		return nil
	})
	for i := len(dirs) - 1; i >= 0; i-- {
		entries, err := os.ReadDir(dirs[i])
		if err != nil || len(entries) > 0 {
			continue
		}
		if err := os.Remove(dirs[i]); err == nil {
			log.Printf("cleanupEmptyRepoDirs: removed empty dir %s", dirs[i])
		}
	}
}

// cleanupRepoDB removes the repository record from SQLite after all tags
// have been deleted. Filesystem cleanup is left to garbage collection.
func (s *Server) cleanupRepoDB(ctx context.Context, repo string) {
	// Validate repo name to prevent path traversal.
	if repo == "" || strings.Contains(repo, "..") {
		return
	}
	// Find and delete DB record without creating anything (resolveRepo upserts).
	var rid int64
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) == 2 {
		if r, err := s.store.GetRepositoryByNamespacedName(ctx, parts[0], parts[1]); err == nil {
			rid = r.ID
		}
	} else {
		// Single-segment repo (root namespace): look for namespace "".
		if r, err := s.store.GetRepositoryByNamespacedName(ctx, "", parts[0]); err == nil {
			rid = r.ID
		}
	}
	if rid > 0 {
		if err := s.store.DeleteRepository(ctx, rid); err != nil {
			log.Printf("cleanupRepoDB: failed to delete repo %s from DB: %v", repo, err)
		} else {
			log.Printf("cleanupRepoDB: deleted repo %s (id=%d) from DB", repo, rid)
		}
	}
}
