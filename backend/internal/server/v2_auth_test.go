package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neuf/registry-ui/backend/internal/config"
	"github.com/neuf/registry-ui/backend/internal/store"
)

// TestV2PingAuth verifies that the /v2/ ping always returns 200 (per OCI
// Distribution Spec), and that authenticated requests work properly for push.
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

	t.Run("ping without auth returns 200 (OCI spec)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("anonymous ping: got %d want 200", rr.Code)
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

	t.Run("ping returns 200 (always)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("ping: got %d want 200", rr.Code)
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
