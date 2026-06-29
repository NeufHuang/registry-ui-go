package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neuf/registry-ui/backend/internal/config"
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
	srv.gcLock.Lock()
	srv.gcRunning = true
	srv.gcLock.Unlock()

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
	srv.gcLock.Lock()
	srv.gcRunning = false
	srv.gcLock.Unlock()

	// Test PUT after GC is allowed (will fail with bad gateway but not 503)
	req3 := httptest.NewRequest(http.MethodPut, "/v2/library/nginx/blobs/uploads/", nil)
	rr3 := httptest.NewRecorder()
	srv.newV2Proxy().ServeHTTP(rr3, req3)

	if rr3.Code == http.StatusServiceUnavailable {
		t.Errorf("PUT after GC: should not be blocked, got %d", rr3.Code)
	}
}
