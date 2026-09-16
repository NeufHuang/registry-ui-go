package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/neuf/registry-ui/backend/internal/config"
	"github.com/neuf/registry-ui/backend/internal/store"
)

// newAuthzTestServer builds a server with a read-only user ("ro", read on
// "lib") and a read-write user ("rw", read+write on "lib"), plus a registry
// stub. AUTH_MODE=basic so the UI-API authorization layer is exercised.
type authzFixture struct {
	srv     *Server
	handler http.Handler
	store   *store.Store
}

func newAuthzFixture(t *testing.T) authzFixture {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ns, err := st.UpsertNamespace(ctx, "lib")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertRepository(ctx, ns.ID, "nginx"); err != nil {
		t.Fatal(err)
	}
	secretNs, err := st.UpsertNamespace(ctx, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertRepository(ctx, secretNs.ID, "priv"); err != nil {
		t.Fatal(err)
	}

	roHash, _ := store.HashPassword("readpass")
	ro, err := st.CreateUser(ctx, "ro", roHash, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertUserPermission(ctx, store.UserPermission{UserID: ro.ID, NamespacePattern: "lib", CanRead: true, CanWrite: false}); err != nil {
		t.Fatal(err)
	}
	rwHash, _ := store.HashPassword("writepass")
	rw, err := st.CreateUser(ctx, "rw", rwHash, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertUserPermission(ctx, store.UserPermission{UserID: rw.ID, NamespacePattern: "lib", CanRead: true, CanWrite: true}); err != nil {
		t.Fatal(err)
	}

	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "_catalog"):
			w.Write([]byte(`{"repositories":["lib/nginx","secret/priv"]}`))
		case strings.Contains(r.URL.Path, "tags/list"):
			w.Write([]byte(`{"tags":["v1"]}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(reg.Close)

	srv := New(config.Config{RegistryURL: reg.URL, AuthMode: "basic", V2AuthMode: "ui"}, st)
	return authzFixture{srv: srv, handler: srv.Handler(), store: st}
}

// call performs a request authenticated with user/pass. A CSRF cookie+header is
// always attached so the authorization layer, not the CSRF layer, decides.
func (f authzFixture) call(t *testing.T, user, pass, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.SetBasicAuth(user, pass)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "tok"})
	req.Header.Set("X-CSRF-Token", "tok")
	rr := httptest.NewRecorder()
	f.handler.ServeHTTP(rr, req)
	return rr
}

// TestReadOnlyUserCannotMutateUIAPI is the regression test for the
// authorization gap: the UI API only checked read permission, so a read-only
// user could delete images, disable immutable-tag protection and manage
// namespaces.
func TestReadOnlyUserCannotMutateUIAPI(t *testing.T) {
	f := newAuthzFixture(t)

	denied := []struct{ method, path, body string }{
		{http.MethodPut, "/api/repositories/lib/nginx/tag-policy", `{"protectionMode":"overwrite"}`},
		{http.MethodPost, "/api/repositories/lib/nginx/manifests/batch-delete", `{"tags":["v1"]}`},
		{http.MethodDelete, "/api/repositories/lib/nginx/manifests/v1", ``},
		{http.MethodPost, "/api/repositories/lib/nginx/retention-run", `{"keepCount":1}`},
		{http.MethodPost, "/api/repositories/lib/nginx/init", ``},
		{http.MethodPut, "/api/repo-description/lib/nginx/description", `{"description":"x"}`},
		{http.MethodPost, "/api/namespaces", `{"name":"evil"}`},
		{http.MethodDelete, "/api/namespaces/lib", ``},
		{http.MethodGet, "/api/export", ``},
		{http.MethodGet, "/api/repo-stats", ``},
	}
	for _, tc := range denied {
		rr := f.call(t, "ro", "readpass", tc.method, tc.path, tc.body)
		if rr.Code != http.StatusForbidden {
			t.Errorf("read-only %s %s = %d, want 403 (body=%s)", tc.method, tc.path, rr.Code, strings.TrimSpace(rr.Body.String()))
		}
	}
}

// TestReadWriteUserCanStillMutate guards against over-restricting the fix.
func TestReadWriteUserCanStillMutate(t *testing.T) {
	f := newAuthzFixture(t)
	rr := f.call(t, "rw", "writepass", http.MethodPut, "/api/repositories/lib/nginx/tag-policy", `{"protectionMode":"overwrite"}`)
	if rr.Code != http.StatusOK {
		t.Errorf("read-write PUT tag-policy = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	rr = f.call(t, "rw", "writepass", http.MethodPut, "/api/repo-description/lib/nginx/description", `{"description":"hello"}`)
	if rr.Code != http.StatusOK {
		t.Errorf("read-write PUT repo-description = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	// ... but not on a namespace it has no permission for.
	rr = f.call(t, "rw", "writepass", http.MethodPut, "/api/repo-description/secret/priv/description", `{"description":"x"}`)
	if rr.Code != http.StatusForbidden {
		t.Errorf("read-write PUT other namespace description = %d, want 403", rr.Code)
	}
}

// TestRepositoryListHidesUnreadableRepos verifies a user with zero permissions
// no longer receives the full catalog (the old code fail-opened).
func TestRepositoryListHidesUnreadableRepos(t *testing.T) {
	f := newAuthzFixture(t)

	rr := f.call(t, "ro", "readpass", http.MethodGet, "/api/repositories", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/repositories = %d", rr.Code)
	}
	var body struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, repo := range body.Repositories {
		if strings.HasPrefix(repo, "secret/") {
			t.Errorf("repo list leaked %q to a user without permission", repo)
		}
	}

	// Namespaces are filtered too.
	rr = f.call(t, "ro", "readpass", http.MethodGet, "/api/namespaces", "")
	var nsBody struct {
		Namespaces []struct {
			Name string `json:"name"`
		} `json:"namespaces"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &nsBody); err != nil {
		t.Fatal(err)
	}
	for _, ns := range nsBody.Namespaces {
		if ns.Name == "secret" {
			t.Error("namespace list leaked \"secret\" to a user without permission")
		}
	}
}

// TestRepositoryPaginationUnknownCursor ensures an unknown `last` ends the
// pagination instead of restarting at page 1 (which made clients loop).
func TestRepositoryPaginationUnknownCursor(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	ns, err := st.UpsertNamespace(ctx, "ns")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"aaa", "bbb", "ccc", "ddd"} {
		if _, err := st.UpsertRepository(ctx, ns.ID, name); err != nil {
			t.Fatal(err)
		}
	}
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer reg.Close()
	h := New(config.Config{RegistryURL: reg.URL, AuthMode: "off"}, st).Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/repositories?n=2&last=zzz-missing", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var body struct {
		Repositories []string `json:"repositories"`
		NextLast     string   `json:"nextLast"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Repositories) != 0 || body.NextLast != "" {
		t.Errorf("unknown cursor returned %v nextLast=%q, want an empty final page", body.Repositories, body.NextLast)
	}

	// A valid cursor still pages forward.
	req = httptest.NewRequest(http.MethodGet, "/api/repositories?n=2", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Repositories) != 2 || body.NextLast == "" {
		t.Fatalf("first page = %v nextLast=%q, want 2 repos and a cursor", body.Repositories, body.NextLast)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/repositories?n=2&last="+body.NextLast, nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var page2 struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &page2); err != nil {
		t.Fatal(err)
	}
	if len(page2.Repositories) == 0 || page2.Repositories[0] == body.Repositories[0] {
		t.Errorf("second page %v restarted the listing", page2.Repositories)
	}
}

// TestStaticSPAFallbackServesHTML covers the text/plain index.html fallback and
// the new ETag handling.
func TestStaticSPAFallbackServesHTML(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := New(config.Config{AuthMode: "off"}, st).Handler()

	req := httptest.NewRequest(http.MethodGet, "/some/spa/route", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("SPA fallback status = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("SPA fallback Content-Type = %q, want text/html", ct)
	}
	etag := rr.Header().Get("ETag")
	if etag == "" {
		t.Fatal("SPA fallback has no ETag")
	}

	req = httptest.NewRequest(http.MethodGet, "/some/spa/route", nil)
	req.Header.Set("If-None-Match", etag)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotModified {
		t.Errorf("If-None-Match status = %d, want 304", rr.Code)
	}

	// A missing asset is a real 404, not an HTML shell with a JS content type.
	req = httptest.NewRequest(http.MethodGet, "/does-not-exist.js", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("missing asset status = %d, want 404", rr.Code)
	}
}

// TestBearerTokenSkipsCSRF verifies the documented "use a Bearer token for any
// API" flow works for state-changing requests.
func TestBearerTokenSkipsCSRF(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	admin, err := st.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateUserPassword(ctx, admin.ID, "testpass"); err != nil {
		t.Fatal(err)
	}
	hexTok := strings.Repeat("cd", 32)
	prefix := hexTok[:12]
	sum := sha256.Sum256([]byte(hexTok))
	if _, err := st.CreateAPIToken(ctx, store.APIToken{UserID: admin.ID, Name: "ci", TokenHash: hex.EncodeToString(sum[:]), TokenPrefix: prefix}); err != nil {
		t.Fatal(err)
	}
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer reg.Close()
	h := New(config.Config{RegistryURL: reg.URL, AuthMode: "basic", V2AuthMode: "ui"}, st).Handler()

	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"theme":"light"}`))
	req.Header.Set("Authorization", "Bearer ru_"+prefix+"_"+hexTok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Bearer-only PUT /api/settings = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
}

// TestRecycleMutationsRequireWrite covers the recycle bin: listing is a read,
// but restoring (re-push) and discarding (last recoverable copy) are writes.
func TestRecycleMutationsRequireWrite(t *testing.T) {
	f := newAuthzFixture(t)
	ctx := context.Background()
	if err := f.store.AddRecycleItem(ctx, store.RecycleItem{
		Repo: "lib/nginx", Reference: "v1", Digest: "sha256:deadbeef",
		ContentType: "application/vnd.oci.image.manifest.v1+json", ManifestBody: []byte(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	items, err := f.store.ListRecycleItems(ctx, false, 10)
	if err != nil || len(items) == 0 {
		t.Fatalf("recycle list: %v (%d items)", err, len(items))
	}
	id := items[0].ID

	if rr := f.call(t, "ro", "readpass", http.MethodPost, "/api/recycle/"+itoa(id)+"/restore", ""); rr.Code != http.StatusForbidden {
		t.Errorf("read-only restore = %d, want 403", rr.Code)
	}
	if rr := f.call(t, "ro", "readpass", http.MethodDelete, "/api/recycle/"+itoa(id), ""); rr.Code != http.StatusForbidden {
		t.Errorf("read-only recycle delete = %d, want 403", rr.Code)
	}
	// The list itself stays readable.
	if rr := f.call(t, "ro", "readpass", http.MethodGet, "/api/recycle", ""); rr.Code != http.StatusOK {
		t.Errorf("read-only recycle list = %d, want 200", rr.Code)
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// TestRepoPathWithReservedSegments covers repositories whose own name contains
// a reserved sub-path segment: authorization must resolve the full repo name,
// not the parent namespace.
func TestRepoPathWithReservedSegments(t *testing.T) {
	cases := []struct{ path, want string }{
		{"team/tags/tags", "team/tags"},
		{"team/stats/stats", "team/stats"},
		{"a/manifests/b/manifests/v1", "a/manifests/b"},
		{"a/tags/list/manifests/v1", "a/tags/list"},
		{"lib/nginx/tags", "lib/nginx"},
		{"lib/nginx/manifests/v1", "lib/nginx"},
	}
	for _, c := range cases {
		if got := extractRepoNameFromPath(c.path); got != c.want {
			t.Errorf("extractRepoNameFromPath(%q) = %q, want %q", c.path, got, c.want)
		}
	}
	v2Cases := []struct{ path, want string }{
		{"/v2/a/manifests/b/manifests/v1", "a/manifests/b"},
		{"/v2/team/tags/tags/list", "team/tags"},
		{"/v2/library/nginx/manifests/latest", "library/nginx"},
	}
	for _, c := range v2Cases {
		if got := extractV2RepoPath(c.path); got != c.want {
			t.Errorf("extractV2RepoPath(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// TestCreateUserHonoursEnabled covers the previously ignored `enabled` field.
func TestCreateUserHonoursEnabled(t *testing.T) {
	f := newAuthzFixture(t)
	admin, err := f.store.GetUserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.UpdateUserPassword(context.Background(), admin.ID, "testpass"); err != nil {
		t.Fatal(err)
	}

	rr := f.call(t, "admin", "testpass", http.MethodPost, "/api/admin/users", `{"username":"sleepy","password":"secret1","isAdmin":false,"enabled":false}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /api/admin/users = %d, body=%s", rr.Code, rr.Body.String())
	}
	var created store.User
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Enabled {
		t.Error("created user is enabled, want disabled")
	}
	got, err := f.store.GetUserByUsername(context.Background(), "sleepy")
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled {
		t.Error("persisted user is enabled, want disabled")
	}
}
