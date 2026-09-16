package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neuf/registry-ui/backend/internal/config"
)

func TestStatusErrorClassification(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`))
	}))
	defer srv.Close()

	client := NewClient(config.Config{RegistryURL: srv.URL, EnableDelete: true})
	err := client.DeleteManifest(context.Background(), "foo/bar", "sha256:dead")
	if err == nil {
		t.Fatal("expected an error for a 404 response")
	}
	if !IsStatus(err, http.StatusNotFound) {
		t.Errorf("IsStatus(err, 404) = false, want true (%v)", err)
	}
	if IsStatus(err, http.StatusInternalServerError) {
		t.Error("IsStatus(err, 500) should be false")
	}
	code, ok := StatusCode(err)
	if !ok || code != http.StatusNotFound {
		t.Errorf("StatusCode = (%d, %v), want (404, true)", code, ok)
	}

	// A transport failure must not be reported as a registry status, otherwise
	// a short outage would be counted as a permanent GC failure.
	dead := NewClient(config.Config{RegistryURL: "http://127.0.0.1:1", EnableDelete: true})
	terr := dead.DeleteManifest(context.Background(), "foo/bar", "sha256:dead")
	if terr == nil {
		t.Fatal("expected a transport error")
	}
	if _, ok := StatusCode(terr); ok {
		t.Errorf("transport error must not carry an HTTP status: %v", terr)
	}
}
