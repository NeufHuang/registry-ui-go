package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neuf/registry-ui/backend/internal/config"
	"github.com/neuf/registry-ui/backend/internal/store"
)

// TestV2PingAuth verifies the /v2/ challenge (401 + Bearer realm) that lets
// Docker learn about the token endpoint, that presented credentials are still
// verified, and that authenticated content requests are not refused.
func TestV2PingAuth(t *testing.T) {
	ctx := context.Background()

	dbPath := t.TempDir() + "/test.db"
	st, err := store.Open(dbPath)
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

	mockReg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockReg.Close()

	cfg := config.Config{
		RegistryURL: mockReg.URL,
		AuthMode:    "basic",
		V2AuthMode:  "ui",
	}
	srv := New(cfg, st)
	handler := srv.Handler()

	t.Run("ping without auth returns 401 with a Bearer challenge", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("anonymous ping: got %d want 401", rr.Code)
		}
		// Bearer (token flow), never Basic: a client with no stored
		// credentials treats a Basic challenge as unsatisfiable and aborts
		// the pull with "no basic auth credentials" before requesting any
		// content — even from a repo that allows anonymous pull.
		got := rr.Header().Get("WWW-Authenticate")
		if !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("anonymous ping: WWW-Authenticate = %q, want a Bearer challenge", got)
		}
		if !strings.Contains(got, "/v2/token") {
			t.Errorf("anonymous ping: WWW-Authenticate = %q, want a realm pointing at /v2/token", got)
		}
	})

	t.Run("ping with valid basic auth returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
		req.SetBasicAuth("admin", "testpass")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("authenticated ping: got %d want 200", rr.Code)
		}
	})

	t.Run("ping with invalid basic auth returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
		req.SetBasicAuth("admin", "wrong-password")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("ping with bad credentials: got %d want 401", rr.Code)
		}
	})

	t.Run("blob HEAD with valid basic auth is not 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "/v2/library/alpine/blobs/sha256:abc", nil)
		req.SetBasicAuth("admin", "testpass")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code == http.StatusUnauthorized {
			t.Errorf("blob HEAD with valid creds: got 401, push would fail")
		}
	})

	t.Run("blob HEAD without auth returns 401 when not anonymous", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "/v2/library/alpine/blobs/sha256:abc", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("blob HEAD without auth for non-anon repo: got %d want 401", rr.Code)
		}
		if rr.Header().Get("WWW-Authenticate") == "" {
			t.Error("blob HEAD 401: missing WWW-Authenticate challenge")
		}
	})
}

// TestV2PingAnonymousPull verifies that anonymous pull works when
// allow_anonymous_pull is enabled (either globally or per-repo).
func TestV2PingAnonymousPull(t *testing.T) {
	ctx := context.Background()

	dbPath := t.TempDir() + "/test.db"
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Enable global anonymous pull
	if err := st.SetSetting(ctx, "allow_anonymous_pull", "true"); err != nil {
		t.Fatal(err)
	}

	admin, err := st.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateUserPassword(ctx, admin.ID, "testpass"); err != nil {
		t.Fatal(err)
	}

	mockReg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockReg.Close()

	cfg := config.Config{
		RegistryURL: mockReg.URL,
		AuthMode:    "basic",
		V2AuthMode:  "ui",
	}
	srv := New(cfg, st)
	handler := srv.Handler()

	t.Run("ping challenges anonymous clients even with anonymous pull on", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("anonymous ping: got %d want 401", rr.Code)
		}
		// ...but the same client can still pull content anonymously.
		req2 := httptest.NewRequest(http.MethodGet, "/v2/zhuiju/zhuiju/manifests/latest", nil)
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code == http.StatusUnauthorized {
			t.Errorf("anonymous manifest GET with global anon enabled: got 401, want passthrough")
		}
	})

	t.Run("anonymous blob GET for anon-enabled repo is allowed", func(t *testing.T) {
		ns, err := st.UpsertNamespace(ctx, "library")
		if err != nil {
			t.Fatal(err)
		}
		_, err = st.UpsertRepository(ctx, ns.ID, "alpine")
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SetRepositoryAnonymousPull(ctx, "library", "alpine", true); err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest(http.MethodGet, "/v2/library/alpine/blobs/sha256:abc", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code == http.StatusUnauthorized {
			t.Errorf("anonymous blob GET for anon-enabled repo: got 401, want passthrough")
		}
	})

	t.Run("anonymous manifest GET uses global allow_anonymous_pull", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v2/zhuiju/zhuiju/manifests/latest", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code == http.StatusUnauthorized {
			t.Errorf("anonymous manifest GET with global anon enabled: got 401, want passthrough")
		}
	})

	t.Run("anon-enabled repo still validates a presented credential", func(t *testing.T) {
		// No credential: anonymous pull must keep working.
		req := httptest.NewRequest(http.MethodGet, "/v2/library/alpine/manifests/latest", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code == http.StatusUnauthorized {
			t.Errorf("anonymous manifest GET: got 401, want passthrough")
		}

		// A credential that IS presented must never be silently ignored: that
		// is what let `docker login` answer "Login Succeeded" for a wrong
		// password and then fail the pull with "unauthorized".
		req2 := httptest.NewRequest(http.MethodGet, "/v2/library/alpine/manifests/latest", nil)
		req2.SetBasicAuth("admin", "wrong-password")
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusUnauthorized {
			t.Errorf("manifest GET with a bad credential on an anon repo: got %d want 401", rr2.Code)
		}

		// The same request with valid credentials is accepted.
		req3 := httptest.NewRequest(http.MethodGet, "/v2/library/alpine/manifests/latest", nil)
		req3.SetBasicAuth("admin", "testpass")
		rr3 := httptest.NewRecorder()
		handler.ServeHTTP(rr3, req3)
		if rr3.Code == http.StatusUnauthorized {
			t.Errorf("manifest GET with valid credentials: got 401, want passthrough")
		}
	})

	t.Run("single-level repo anonymous pull uses per-repo settings key", func(t *testing.T) {
		// Single-level repos (root namespace, e.g. "python") have no
		// namespace separator; their per-repo flag lives under
		// "allow_anonymous_pull:<repo>". Save via the tag-policy API then
		// verify the flag is read back and honored by the v2 proxy.
		if err := st.SetSetting(ctx, "allow_anonymous_pull", "false"); err != nil {
			t.Fatal(err)
		}
		if err := st.SetSetting(ctx, "allow_anonymous_pull:python", "true"); err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest(http.MethodGet, "/v2/python/manifests/latest", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code == http.StatusUnauthorized {
			t.Errorf("anonymous manifest GET for single-level repo with per-repo anon: got 401, want passthrough")
		}

		// A different single-level repo without the flag must stay protected.
		if err := st.SetSetting(ctx, "allow_anonymous_pull:python", "false"); err != nil {
			t.Fatal(err)
		}
		req2 := httptest.NewRequest(http.MethodGet, "/v2/python/manifests/latest", nil)
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusUnauthorized {
			t.Errorf("single-level repo with anon disabled: got %d, want 401", rr2.Code)
		}
	})
}

// TestV2ErrorEnvelopeFormat verifies that /v2/ error responses use the OCI
// Distribution Spec error envelope so the Docker CLI can parse the error code.
func TestV2ErrorEnvelopeFormat(t *testing.T) {
	ctx := context.Background()

	dbPath := t.TempDir() + "/test.db"
	st, err := store.Open(dbPath)
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

	mockReg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockReg.Close()

	cfg := config.Config{
		RegistryURL: mockReg.URL,
		AuthMode:    "basic",
		V2AuthMode:  "ui",
	}
	srv := New(cfg, st)
	handler := srv.Handler()

	// Unauthenticated blob HEAD should return 401 with OCI error envelope
	req := httptest.NewRequest(http.MethodHead, "/v2/test/manifests/latest", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if !strings.Contains(body, `"errors"`) {
		t.Errorf("401 body missing OCI errors envelope: %s", body)
	}
	if !strings.Contains(body, `"UNAUTHORIZED"`) {
		t.Errorf("401 body missing UNAUTHORIZED code: %s", body)
	}
}

// TestV2TokenFlow covers the OCI token flow that replaced the bare Basic
// challenge on /v2/: /v2/token mints tokens (verifying credentials whenever
// they are presented) and /v2/* accepts them for anonymous and authenticated
// clients alike.
func TestV2TokenFlow(t *testing.T) {
	ctx := context.Background()

	dbPath := t.TempDir() + "/test.db"
	st, err := store.Open(dbPath)
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

	// One repo that allows anonymous pull, one that does not.
	ns, err := st.UpsertNamespace(ctx, "library")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertRepository(ctx, ns.ID, "alpine"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRepositoryAnonymousPull(ctx, "library", "alpine", true); err != nil {
		t.Fatal(err)
	}
	privNS, err := st.UpsertNamespace(ctx, "private")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertRepository(ctx, privNS.ID, "app"); err != nil {
		t.Fatal(err)
	}

	// A non-admin that may only read from library/.
	passHash, err := store.HashPassword("ropass")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, "reader", passHash, false, false); err != nil {
		t.Fatal(err)
	}
	reader, err := st.GetUserByUsername(ctx, "reader")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertUserPermission(ctx, store.UserPermission{
		UserID:           reader.ID,
		NamespacePattern: "library",
		CanRead:          true,
		CanWrite:         false,
	}); err != nil {
		t.Fatal(err)
	}

	// Upstream registry that records the Authorization header it receives, so
	// the test can prove our bearer token never leaks to the backend registry.
	var upstreamAuth atomic.Value
	upstreamAuth.Store("")
	mockReg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer mockReg.Close()

	srv := New(config.Config{RegistryURL: mockReg.URL, AuthMode: "basic", V2AuthMode: "ui"}, st)
	handler := srv.Handler()

	mintToken := func(t *testing.T, user, pass string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/v2/token", nil)
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("mint token as user=%q: got %d, body=%s", user, rr.Code, rr.Body.String())
		}
		var body struct {
			Token     string `json:"token"`
			ExpiresIn int    `json:"expires_in"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("mint token as user=%q: unreadable body %q: %v", user, rr.Body.String(), err)
		}
		if body.Token == "" {
			t.Fatalf("mint token as user=%q: empty token", user)
		}
		if body.ExpiresIn <= 0 {
			t.Errorf("mint token as user=%q: expires_in=%d, want > 0", user, body.ExpiresIn)
		}
		return body.Token
	}

	request := func(method, path, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	anonToken := mintToken(t, "", "")
	adminToken := mintToken(t, "admin", "testpass")
	readerToken := mintToken(t, "reader", "ropass")

	t.Run("wrong password never mints a token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v2/token", nil)
		req.SetBasicAuth("admin", "wrong-password")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("token with wrong password: got %d, want 401", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "UNAUTHORIZED") {
			t.Errorf("token 401 body missing OCI UNAUTHORIZED: %s", rr.Body.String())
		}
	})

	t.Run("admin token reads a private repo", func(t *testing.T) {
		if rr := request(http.MethodGet, "/v2/private/app/manifests/v1", adminToken); rr.Code == http.StatusUnauthorized {
			t.Errorf("admin token on private repo: got 401, want passthrough (body=%s)", rr.Body.String())
		}
	})

	t.Run("anonymous token pulls an anonymous repo", func(t *testing.T) {
		if rr := request(http.MethodGet, "/v2/library/alpine/manifests/v1", anonToken); rr.Code == http.StatusUnauthorized {
			t.Errorf("anonymous token on anonymous repo: got 401, want passthrough (body=%s)", rr.Body.String())
		}
	})

	t.Run("anonymous token is refused on a private repo", func(t *testing.T) {
		if rr := request(http.MethodGet, "/v2/private/app/manifests/v1", anonToken); rr.Code != http.StatusUnauthorized {
			t.Errorf("anonymous token on private repo: got %d, want 401", rr.Code)
		}
	})

	t.Run("anonymous token cannot push", func(t *testing.T) {
		if rr := request(http.MethodPut, "/v2/library/alpine/manifests/v1", anonToken); rr.Code != http.StatusUnauthorized {
			t.Errorf("anonymous token PUT: got %d, want 401", rr.Code)
		}
	})

	t.Run("token honors namespace permissions", func(t *testing.T) {
		if rr := request(http.MethodGet, "/v2/library/alpine/manifests/v1", readerToken); rr.Code == http.StatusForbidden || rr.Code == http.StatusUnauthorized {
			t.Errorf("reader token reading allowed repo: got %d, want passthrough (body=%s)", rr.Code, rr.Body.String())
		}
		if rr := request(http.MethodGet, "/v2/private/app/manifests/v1", readerToken); rr.Code != http.StatusForbidden {
			t.Errorf("reader token reading private repo: got %d, want 403", rr.Code)
		}
		if rr := request(http.MethodPut, "/v2/library/alpine/manifests/v1", readerToken); rr.Code != http.StatusForbidden {
			t.Errorf("reader token pushing: got %d, want 403", rr.Code)
		}
	})

	t.Run("tampered token is rejected", func(t *testing.T) {
		raw := []byte(anonToken)
		if raw[0] == 'A' {
			raw[0] = 'B'
		} else {
			raw[0] = 'A'
		}
		if rr := request(http.MethodGet, "/v2/library/alpine/manifests/v1", string(raw)); rr.Code != http.StatusUnauthorized {
			t.Errorf("tampered token: got %d, want 401", rr.Code)
		}
	})

	t.Run("expired token is rejected", func(t *testing.T) {
		stale := srv.mintV2Token(0, "", -time.Second)
		if rr := request(http.MethodGet, "/v2/library/alpine/manifests/v1", stale); rr.Code != http.StatusUnauthorized {
			t.Errorf("expired token: got %d, want 401", rr.Code)
		}
	})

	t.Run("upstream registry never sees our bearer token", func(t *testing.T) {
		upstreamAuth.Store("")
		if rr := request(http.MethodGet, "/v2/library/alpine/manifests/v1", adminToken); rr.Code == http.StatusUnauthorized {
			t.Fatalf("admin token read: got 401 (body=%s)", rr.Body.String())
		}
		if got := upstreamAuth.Load().(string); strings.HasPrefix(got, "Bearer ") {
			t.Errorf("upstream received our bearer token: %q", got)
		}
	})
}

// TestV2ChallengeUsesExternalURL verifies that EXTERNAL_URL pins the token
// realm, so a reverse proxy that does not forward Host / X-Forwarded-Proto
// cannot send the client to an unreachable address.
func TestV2ChallengeUsesExternalURL(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	mockReg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockReg.Close()

	cfg := config.Config{
		RegistryURL: mockReg.URL,
		AuthMode:    "basic",
		V2AuthMode:  "ui",
		// Trailing slash must be tolerated.
		ExternalURL: "https://registry.example.com:9999/",
	}
	handler := New(cfg, st).Handler()

	req := httptest.NewRequest(http.MethodGet, "/v2/", nil) // Host: example.com
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("ping: got %d, want 401", rr.Code)
	}
	want := `Bearer realm="https://registry.example.com:9999/v2/token",service="registry-ui"`
	if got := rr.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}

	// Without EXTERNAL_URL the origin falls back to the request itself.
	cfg.ExternalURL = ""
	handler = New(cfg, st).Handler()
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	want = `Bearer realm="http://example.com/v2/token",service="registry-ui"`
	if got := rr.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate (no EXTERNAL_URL) = %q, want %q", got, want)
	}
}
