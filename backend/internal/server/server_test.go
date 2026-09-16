package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neuf/registry-ui/backend/internal/config"
	"github.com/neuf/registry-ui/backend/internal/store"
)

func TestExtractV2RepoPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/v2/", ""},
		{"/v2/_catalog", ""},
		{"/v2/_catalog/", ""},
		{"/v2/library/nginx/manifests/latest", "library/nginx"},
		{"/v2/library/nginx/tags/list", "library/nginx"},
		{"/v2/library/nginx/blobs/sha256:abc", "library/nginx"},
		{"/v2/a/b/c/manifests/v1", "a/b/c"},
		{"/v2/single/tags/list", "single"},
		{"/api/foo", ""},
	}
	for _, c := range cases {
		if got := extractV2RepoPath(c.path); got != c.want {
			t.Errorf("extractV2RepoPath(%q)=%q want %q", c.path, got, c.want)
		}
	}
}

func TestExtractRepoNameFromPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"library/nginx/tags", "library/nginx"},
		{"library/sub/repo/manifests/v1", "library/sub/repo"},
		{"a/b/stats", "a/b"},
		{"a/b/tag-policy", "a/b"},
		{"a/b/manifests/batch-delete", "a/b"},
		{"a/b/retention-preview", "a/b"},
		{"noslash", ""},
	}
	for _, c := range cases {
		if got := extractRepoNameFromPath(c.path); got != c.want {
			t.Errorf("extractRepoNameFromPath(%q)=%q want %q", c.path, got, c.want)
		}
	}
}

func TestMatchImmutableTagPattern(t *testing.T) {
	cases := []struct {
		pattern, tag string
		want         bool
	}{
		{"v*", "v1.0", true},
		{"v*", "latest", false},
		{"release-*", "release-1.0", true},
		{"release-*", "release", false},
		{"release-*", "release-", true},
		{"v?.?", "v1.0", true},
		{"v?.?", "v1.10", false},
		{"prod", "prod", true},
		{"prod", "prods", false},
		{"latest", "latest", true},
		// Regex metacharacters in pattern must be treated literally.
		{"v1.0", "v1x0", false},
	}
	for _, c := range cases {
		if got := matchImmutableTagPattern(c.pattern, c.tag); got != c.want {
			t.Errorf("matchImmutableTagPattern(%q,%q)=%v want %v", c.pattern, c.tag, got, c.want)
		}
	}
}

func TestWebhookMatchesEvent(t *testing.T) {
	cases := []struct {
		events, event string
		want          bool
	}{
		{"push,delete,restore", "push", true},
		{"push, delete , restore", "delete", true},
		{"push,delete", "restore", false},
		{"push", "pus", false},
		{"", "push", false},
	}
	for _, c := range cases {
		if got := webhookMatchesEvent(c.events, c.event); got != c.want {
			t.Errorf("webhookMatchesEvent(%q,%q)=%v want %v", c.events, c.event, got, c.want)
		}
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !constantTimeEqual("abc", "abc") {
		t.Error("equal strings should compare true")
	}
	if constantTimeEqual("abc", "abd") {
		t.Error("different strings should compare false")
	}
	if constantTimeEqual("abc", "abcd") {
		t.Error("different-length strings should compare false")
	}
}

func TestValidateWebhookURL(t *testing.T) {
	s := &Server{cfg: config.Config{}}
	bad := []string{
		"ftp://example.com",
		"http://127.0.0.1/hook",
		"http://localhost/hook",
		"http://10.0.0.5/hook",
		"http://192.168.1.1/hook",
		"http://169.254.169.254/latest/meta-data",
		"not a url with spaces::",
		"http://",
	}
	for _, u := range bad {
		if err := s.validateWebhookURL(u); err == nil {
			t.Errorf("validateWebhookURL(%q) should fail", u)
		}
	}
	// Public address should pass.
	if err := s.validateWebhookURL("https://8.8.8.8/hook"); err != nil {
		t.Errorf("validateWebhookURL public IP should pass, got %v", err)
	}
	// Escape hatch allows private addresses.
	s2 := &Server{cfg: config.Config{AllowWebhookPrivateIP: true}}
	if err := s2.validateWebhookURL("http://127.0.0.1/hook"); err != nil {
		t.Errorf("with AllowWebhookPrivateIP, private should pass, got %v", err)
	}
}

func TestValidateCSRF(t *testing.T) {
	// Matching cookie and header -> ok.
	r := httptest.NewRequest(http.MethodPost, "/api/x", nil)
	r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "tok123"})
	r.Header.Set("X-CSRF-Token", "tok123")
	if !validateCSRF(r) {
		t.Error("matching CSRF token should validate")
	}
	// Mismatch -> fail.
	r2 := httptest.NewRequest(http.MethodPost, "/api/x", nil)
	r2.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "tok123"})
	r2.Header.Set("X-CSRF-Token", "other")
	if validateCSRF(r2) {
		t.Error("mismatched CSRF token should fail")
	}
	// Missing header -> fail.
	r3 := httptest.NewRequest(http.MethodPost, "/api/x", nil)
	r3.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "tok123"})
	if validateCSRF(r3) {
		t.Error("missing CSRF header should fail")
	}
}

func TestSecureCookie(t *testing.T) {
	s := &Server{cfg: config.Config{}}
	if s.secureCookie(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Error("plain HTTP should not be secure")
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if !s.secureCookie(r) {
		t.Error("X-Forwarded-Proto=https should be secure")
	}
}

func TestDetectArtifactType(t *testing.T) {
	helm := map[string]any{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config":    map[string]any{"mediaType": "application/vnd.cncf.helm.config.v1+json"},
	}
	if got := detectArtifactType("", helm); got != "helm-chart" {
		t.Errorf("helm config => %q want helm-chart", got)
	}
	index := map[string]any{"mediaType": "application/vnd.oci.image.index.v1+json"}
	if got := detectArtifactType("", index); got != "manifest-list" {
		t.Errorf("index => %q want manifest-list", got)
	}
}

func TestSurvivingTags(t *testing.T) {
	// v1 and v1.0 share digest A; latest is digest B.
	tagDigest := map[string]string{
		"v1":     "A",
		"v1.0":   "A",
		"latest": "B",
	}
	digestOf := func(tag string) string { return tagDigest[tag] }
	allTags := []string{"v1", "v1.0", "latest"}

	cases := []struct {
		name     string
		remove   []string
		digest   string
		wantLeft []string
	}{
		{"untag one sibling", []string{"v1"}, "A", []string{"v1.0"}},
		{"remove all siblings", []string{"v1", "v1.0"}, "A", nil},
		{"remove only tag of digest", []string{"latest"}, "B", nil},
	}
	for _, c := range cases {
		removeSet := map[string]bool{}
		for _, tg := range c.remove {
			removeSet[tg] = true
		}
		got := survivingTags(allTags, removeSet, digestOf, c.digest)
		if len(got) != len(c.wantLeft) {
			t.Errorf("%s: got %v want %v", c.name, got, c.wantLeft)
			continue
		}
		for i := range got {
			if got[i] != c.wantLeft[i] {
				t.Errorf("%s: got %v want %v", c.name, got, c.wantLeft)
				break
			}
		}
	}
}

func TestGCLockBlocksPush(t *testing.T) {
	cfg := config.Config{RegistryURL: "http://localhost:5000"}
	srv := New(cfg, nil)

	// Simulate GC running
	srv.gcRunning.Store(true)

	// Test PUT request (push) is blocked - use a path that won't trigger stats
	req := httptest.NewRequest(http.MethodPut, "/v2/library/nginx/blobs/uploads/", nil)
	rr := httptest.NewRecorder()
	srv.newV2Proxy().ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("PUT during GC: got status %d want %d", rr.Code, http.StatusServiceUnavailable)
	}
	if rr.Header().Get("Retry-After") != "30" {
		t.Errorf("PUT during GC: missing Retry-After header")
	}

	// Test GET request (pull) is allowed
	req2 := httptest.NewRequest(http.MethodGet, "/v2/library/nginx/blobs/sha256:abc", nil)
	rr2 := httptest.NewRecorder()
	srv.newV2Proxy().ServeHTTP(rr2, req2)

	// Should not be 503 (it will fail with bad gateway since no real registry, but not 503)
	if rr2.Code == http.StatusServiceUnavailable {
		t.Errorf("GET during GC: should not be blocked, got %d", rr2.Code)
	}

	// Release GC lock
	srv.gcRunning.Store(false)

	// Test PUT after GC is allowed (will fail with bad gateway but not 503)
	req3 := httptest.NewRequest(http.MethodPut, "/v2/library/nginx/blobs/uploads/", nil)
	rr3 := httptest.NewRecorder()
	srv.newV2Proxy().ServeHTTP(rr3, req3)

	if rr3.Code == http.StatusServiceUnavailable {
		t.Errorf("PUT after GC: should not be blocked, got %d", rr3.Code)
	}
}

// TestImmutableTagAllowsFirstPush verifies that matching an immutable-tag
// pattern on a tag that does not yet exist does NOT block the push.
func TestImmutableTagAllowsFirstPush(t *testing.T) {
	ctx := context.Background()

	// Mock registry: tag does NOT exist yet (HEAD returns 404)
	mockReg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockReg.Close()

	// Create temp store
	dbPath := t.TempDir() + "/test.db"
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Create namespace and repo
	ns, err := st.UpsertNamespace(ctx, "testns")
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.UpsertRepository(ctx, ns.ID, "testrepo")
	if err != nil {
		t.Fatal(err)
	}
	// Set repo to immutable mode
	if err := st.SetRepositoryProtectionMode(ctx, "testns", "testrepo", store.ProtectionModeImmutable); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{RegistryURL: mockReg.URL}
	srv := New(cfg, st)

	// First push: tag "v1" doesn't exist yet — should pass
	req := httptest.NewRequest(http.MethodPut, "/v2/testns/testrepo/manifests/v1", nil)
	rr := httptest.NewRecorder()
	srv.newV2Proxy().ServeHTTP(rr, req)

	// 409 Conflict means blocked by immutable rule — FAIL
	// We expect no 409 (either 200 or 502 from proxy is fine)
	if rr.Code == http.StatusConflict {
		t.Errorf("first push should NOT be blocked by immutable rules, got 409 Conflict")
	}
	if rr.Code == http.StatusForbidden {
		t.Errorf("first push should not be 403 Forbidden")
	}
}

// TestImmutableTagBlocksOverwrite verifies that overwriting an existing tag
// matching an immutable pattern IS blocked.
func TestImmutableTagBlocksOverwrite(t *testing.T) {
	ctx := context.Background()

	// Mock registry: tag EXISTS (HEAD returns 200 + digest header)
	mockReg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/") {
			w.Header().Set("Docker-Content-Digest", "sha256:abcdef1234567890")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockReg.Close()

	dbPath := t.TempDir() + "/test.db"
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ns, err := st.UpsertNamespace(ctx, "testns")
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.UpsertRepository(ctx, ns.ID, "testrepo")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetRepositoryProtectionMode(ctx, "testns", "testrepo", store.ProtectionModeImmutable); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{RegistryURL: mockReg.URL}
	srv := New(cfg, st)

	req := httptest.NewRequest(http.MethodPut, "/v2/testns/testrepo/manifests/v1", nil)
	rr := httptest.NewRecorder()
	srv.newV2Proxy().ServeHTTP(rr, req)

	// Tag exists and matches immutable pattern — should be 409
	if rr.Code != http.StatusConflict {
		t.Errorf("overwrite of immutable tag should return 409, got %d", rr.Code)
	}
}

// TestUserCanWriteRepo verifies the userCanWriteRepo function logic
func TestUserCanWriteRepo(t *testing.T) {
	ctx := context.Background()

	dbPath := t.TempDir() + "/test.db"
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Create namespace
	_, err = st.UpsertNamespace(ctx, "testns")
	if err != nil {
		t.Fatal(err)
	}

	// Create two users: one read-only, one read-write
	roUser, err := st.CreateUser(ctx, "readonly", "hash", false, false)
	if err != nil {
		t.Fatal(err)
	}
	rwUser, err := st.CreateUser(ctx, "readwrite", "hash", false, false)
	if err != nil {
		t.Fatal(err)
	}
	adminUser, err := st.CreateUser(ctx, "testadmin", "hash", true, false)
	if err != nil {
		t.Fatal(err)
	}

	// Give roUser read-only permission, rwUser read-write
	_, err = st.UpsertUserPermission(ctx, store.UserPermission{
		UserID:           roUser.ID,
		NamespacePattern: "testns",
		CanRead:          true,
		CanWrite:         false,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.UpsertUserPermission(ctx, store.UserPermission{
		UserID:           rwUser.ID,
		NamespacePattern: "testns",
		CanRead:          true,
		CanWrite:         true,
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := New(config.Config{RegistryURL: "http://localhost:5000"}, st)

	tests := []struct {
		name string
		user store.User
		repo string
		want bool
	}{
		{"admin can write any repo", adminUser, "testns/testrepo", true},
		{"admin can write unknown ns", adminUser, "otherns/testrepo", true},
		{"read-only user cannot write", roUser, "testns/testrepo", false},
		{"read-only cannot write other ns", roUser, "otherns/testrepo", false},
		{"read-write user can write", rwUser, "testns/testrepo", true},
		{"read-write cannot write other ns", rwUser, "otherns/testrepo", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/v2/irrelevant", nil)
			req = req.WithContext(context.WithValue(req.Context(), ctxUserKey{}, tc.user))

			got := srv.userCanWriteRepo(req, tc.repo)
			if got != tc.want {
				t.Errorf("userCanWriteRepo(%q, %q) = %v, want %v", tc.user.Username, tc.repo, got, tc.want)
			}
		})
	}
}

// TestPushCreateSingleSegmentRepo verifies that a single-segment repo
// (root namespace) is also checked against the push_create restriction.
func TestImmutableTagRulesMode(t *testing.T) {
	// The checkImmutableTag function with forceImmutable=false (rules mode)
	ctx := context.Background()

	dbPath := t.TempDir() + "/test.db"
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Create an immutable tag rule matching "v*"
	_, err = st.CreateImmutableTagRule(ctx, store.ImmutableTagRule{Pattern: "v*", Description: "test"})
	if err != nil {
		t.Fatal(err)
	}

	ns, err := st.UpsertNamespace(ctx, "testns")
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.UpsertRepository(ctx, ns.ID, "testrepo")
	if err != nil {
		t.Fatal(err)
	}

	// Mock registry: tag v1 exists (overwrite scenario)
	mockReg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/v1") {
			w.Header().Set("Docker-Content-Digest", "sha256:abcdef1234567890")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockReg.Close()

	cfg := config.Config{RegistryURL: mockReg.URL}
	srv := New(cfg, st)

	// Overwrite v1 — should be blocked by rules-mode immutable tag check
	req := httptest.NewRequest(http.MethodPut, "/v2/testns/testrepo/manifests/v1", nil)
	rr := httptest.NewRecorder()
	srv.newV2Proxy().ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("overwrite of tag matching rules-mode pattern should return 409, got %d", rr.Code)
	}
}

// TestPushCreateSingleSegmentRepo verifies that single-segment repos
// (no namespace, e.g. "alpine") are also checked against push_create.
func TestPushCreateSingleSegmentRepo(t *testing.T) {
	ctx := context.Background()

	dbPath := t.TempDir() + "/test.db"
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Disable push_create globally
	if err := st.SetSetting(ctx, "push_create_repo", "false"); err != nil {
		t.Fatal(err)
	}

	// Mock registry (any response is fine, the check happens before proxying)
	mockReg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockReg.Close()

	cfg := config.Config{RegistryURL: mockReg.URL}
	srv := New(cfg, st)

	// Push to single-segment repo "alpine" that doesn't exist in DB
	req := httptest.NewRequest(http.MethodPut, "/v2/alpine/manifests/latest", nil)
	rr := httptest.NewRecorder()
	srv.newV2Proxy().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("push to non-existent single-segment repo with push_create disabled should return 403, got %d", rr.Code)
	}

	// Now create the repo in DB and verify push succeeds (reaches mock with 200 or 502 proxy error)
	ns, err := st.UpsertNamespace(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.UpsertRepository(ctx, ns.ID, "alpine")
	if err != nil {
		t.Fatal(err)
	}

	req2 := httptest.NewRequest(http.MethodPut, "/v2/alpine/manifests/latest", nil)
	rr2 := httptest.NewRecorder()
	srv.newV2Proxy().ServeHTTP(rr2, req2)

	if rr2.Code == http.StatusForbidden {
		t.Errorf("push to existing single-segment repo should not be blocked, got 403")
	}
}

// TestV2WritePermissionInWithAuth verifies that WITH the withAuth middleware,
// a read-only user receives 403 for mutating V2 requests while admin is allowed.
func TestV2WritePermissionInWithAuth(t *testing.T) {
	ctx := context.Background()

	passHash, err := store.HashPassword("testpass")
	if err != nil {
		t.Fatal(err)
	}

	dbPath := t.TempDir() + "/test.db"
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Create namespace and repo
	ns, err := st.UpsertNamespace(ctx, "testns")
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.UpsertRepository(ctx, ns.ID, "testrepo")
	if err != nil {
		t.Fatal(err)
	}

	// Create read-only user
	_, err = st.CreateUser(ctx, "roatest", passHash, false, false)
	if err != nil {
		t.Fatal(err)
	}
	roUser, err := st.GetUserByUsername(ctx, "roatest")
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.UpsertUserPermission(ctx, store.UserPermission{
		UserID:           roUser.ID,
		NamespacePattern: "testns",
		CanRead:          true,
		CanWrite:         false,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create read-write user
	_, err = st.CreateUser(ctx, "rwtest", passHash, false, false)
	if err != nil {
		t.Fatal(err)
	}
	rwUser, err := st.GetUserByUsername(ctx, "rwtest")
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.UpsertUserPermission(ctx, store.UserPermission{
		UserID:           rwUser.ID,
		NamespacePattern: "testns",
		CanRead:          true,
		CanWrite:         true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mock registry handling any request
	mockReg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Content-Digest", "sha256:abcdef1234567890")
		w.WriteHeader(http.StatusOK)
	}))
	defer mockReg.Close()

	cfg := config.Config{
		RegistryURL: mockReg.URL,
		AuthMode:    "basic",
		V2AuthMode:  "same",
	}
	srv := New(cfg, st)

	handler := srv.withAuth(srv.newV2Proxy())

	t.Run("read-only user gets 403 on PUT manifest", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/v2/testns/testrepo/manifests/v1", nil)
		req.SetBasicAuth("roatest", "testpass")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("read-only user PUT manifest: expected 403, got %d. Body: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("read-write user is allowed on PUT manifest", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/v2/testns/testrepo/manifests/v1", nil)
		req.SetBasicAuth("rwtest", "testpass")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		// Should NOT be 403 (read-write user has permission)
		if rr.Code == http.StatusForbidden {
			t.Errorf("read-write user PUT manifest: should not be 403. Body: %s", rr.Body.String())
		}
	})

	t.Run("read-only user is allowed on GET manifest", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v2/testns/testrepo/manifests/v1", nil)
		req.SetBasicAuth("roatest", "testpass")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		// GET should pass read check and not check write
		if rr.Code == http.StatusForbidden {
			t.Errorf("read-only user GET manifest: should not be 403. Body: %s", rr.Body.String())
		}
	})
}

func TestRegistryRootDirectoryParsing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	write := func(content string) {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("version: 0.1\nstorage:\n  filesystem:\n    rootdirectory: /data/registry\n  delete:\n    enabled: true\n")
	if got := registryRootDirectory(path); got != "/data/registry" {
		t.Errorf("plain rootdirectory => %q want /data/registry", got)
	}
	write("storage:\n  filesystem:\n    rootdirectory: \"/srv/reg\" # inline comment\n")
	if got := registryRootDirectory(path); got != "/srv/reg" {
		t.Errorf("quoted+commented rootdirectory => %q want /srv/reg", got)
	}
	write("storage:\n  inmemory: {}\n")
	if got := registryRootDirectory(path); got != "" {
		t.Errorf("missing rootdirectory => %q want empty", got)
	}
}

func TestSameDirectory(t *testing.T) {
	base := t.TempDir()
	sub := filepath.Join(base, "registry")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if !sameDirectory(sub, sub) {
		t.Error("identical paths should match")
	}
	if !sameDirectory(sub, filepath.Join(base, "registry")+string(filepath.Separator)) {
		t.Error("trailing separator should match")
	}
	if sameDirectory(sub, filepath.Join(base, "other")) {
		t.Error("different paths should not match")
	}
}

func TestCountGCDeletions(t *testing.T) {
	out := "time=\"t\" level=info msg=\"Deleting blob: /docker/registry/v2/blobs/sha256/aa/aabb\"\n" +
		"time=\"t\" level=info msg=\"Deleting manifest: /docker/registry/v2/repositories/foo\"\n" +
		"time=\"t\" level=info msg=\"something unrelated\"\n"
	if n := countGCDeletions(out); n != 2 {
		t.Errorf("countGCDeletions => %d want 2", n)
	}
}

func TestGCRequestAll(t *testing.T) {
	if !gcRequestAll(httptest.NewRequest(http.MethodPost, "/api/gc/run?all=true", nil)) {
		t.Error("?all=true should request a full purge")
	}
	bodyReq := httptest.NewRequest(http.MethodPost, "/api/gc/run", strings.NewReader(`{"all":true}`))
	bodyReq.Header.Set("Content-Type", "application/json")
	if !gcRequestAll(bodyReq) {
		t.Error("JSON body all=true should request a full purge")
	}
	if gcRequestAll(httptest.NewRequest(http.MethodPost, "/api/gc/run", nil)) {
		t.Error("default request must not request a full purge")
	}
}

func TestHandleGCRunRequiresAdmin(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := New(config.Config{RegistryURL: "http://127.0.0.1:1"}, st)

	req := httptest.NewRequest(http.MethodPost, "/api/gc/run", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxUserKey{}, store.User{ID: 2, Username: "bob"}))
	rr := httptest.NewRecorder()
	srv.handleGCRun(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("non-admin GC => %d want 403", rr.Code)
	}
}

func TestEnforcePasswordChange(t *testing.T) {
	srv := &Server{}
	pending := store.User{ID: 1, Username: "admin", MustChangePassword: true}
	withUser := func(path string, u store.User) *http.Request {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		return r.WithContext(context.WithValue(r.Context(), ctxUserKey{}, u))
	}
	for _, path := range []string{"/api/user", "/api/me", "/api/user/password", "/api/logout"} {
		if !srv.enforcePasswordChange(httptest.NewRecorder(), withUser(path, pending)) {
			t.Errorf("%s should be exempt from forced password change", path)
		}
	}
	rr := httptest.NewRecorder()
	if srv.enforcePasswordChange(rr, withUser("/api/repositories", pending)) {
		t.Error("other endpoints must be blocked until the password changes")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("blocked request => %d want 403", rr.Code)
	}
	if !srv.enforcePasswordChange(httptest.NewRecorder(), withUser("/api/repositories", store.User{ID: 2})) {
		t.Error("normal users must not be blocked")
	}
	if !srv.enforcePasswordChange(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/repositories", nil)) {
		t.Error("anonymous/auth-disabled requests must not be blocked")
	}
}

// newGCMockRegistry serves tags/digests so the liveness guard can be exercised
// without a real distribution registry.
func newGCMockRegistry(tags map[string]string, deleted *[]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tags/list"):
			tagNames := make([]string, 0, len(tags))
			for tag := range tags {
				tagNames = append(tagNames, tag)
			}
			body := `{"name":"foo/bar","tags":[`
			for i, tag := range tagNames {
				if i > 0 {
					body += ","
				}
				body += `"` + tag + `"`
			}
			body += `]}`
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/"):
			ref := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			if d, ok := tags[ref]; ok {
				w.Header().Set("Docker-Content-Digest", d)
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodDelete:
			*deleted = append(*deleted, r.URL.Path)
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
}

func TestProcessGCItemsSkipsLiveDigest(t *testing.T) {
	ctx := context.Background()
	var deleted []string
	mock := newGCMockRegistry(map[string]string{"v1": "sha256:live"}, &deleted)
	defer mock.Close()

	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := New(config.Config{RegistryURL: mock.URL, EnableDelete: true}, st)

	if err := st.AddRecycleItem(ctx, store.RecycleItem{Repo: "foo/bar", Reference: "v1", Digest: "sha256:live", ManifestBody: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	items, err := st.ListAllPendingGC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := srv.processGCItems(ctx, items); err != nil || n != 1 {
		t.Fatalf("processGCItems => (%d, %v) want (1, nil)", n, err)
	}
	if len(deleted) != 0 {
		t.Errorf("must not DeleteManifest a digest still referenced by a live tag, deleted=%v", deleted)
	}
	remaining, _ := st.ListAllPendingGC(ctx)
	if len(remaining) != 0 {
		t.Errorf("stale record should be dropped, %d left", len(remaining))
	}
}

func TestProcessGCItemsDeletesUnreferencedDigest(t *testing.T) {
	ctx := context.Background()
	var deleted []string
	mock := newGCMockRegistry(map[string]string{"v2": "sha256:other"}, &deleted)
	defer mock.Close()

	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := New(config.Config{RegistryURL: mock.URL, EnableDelete: true}, st)

	if err := st.AddRecycleItem(ctx, store.RecycleItem{Repo: "foo/bar", Reference: "v1", Digest: "sha256:dead", ManifestBody: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	items, _ := st.ListAllPendingGC(ctx)
	if n, err := srv.processGCItems(ctx, items); err != nil || n != 1 {
		t.Fatalf("processGCItems => (%d, %v) want (1, nil)", n, err)
	}
	if len(deleted) != 1 || !strings.Contains(deleted[0], "sha256:dead") {
		t.Errorf("expected one DELETE for the unreferenced digest, got %v", deleted)
	}
	remaining, _ := st.ListAllPendingGC(ctx)
	if len(remaining) != 0 {
		t.Errorf("record should be removed, %d left", len(remaining))
	}
}
