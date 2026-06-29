package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/neuf/registry-ui/backend/internal/config"
	"github.com/neuf/registry-ui/backend/internal/store"
)

// makeTestCertKey generates a throwaway self-signed cert/key pair for tests.
func makeTestCertKey(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"test.local", "registry.lan"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestParseCertInfo(t *testing.T) {
	certPEM, _ := makeTestCertKey(t)
	info, err := parseCertInfo(certPEM)
	if err != nil {
		t.Fatalf("parseCertInfo: %v", err)
	}
	if info.Expired {
		t.Error("freshly minted cert should not be expired")
	}
	foundDNS := false
	for _, d := range info.DNSNames {
		if d == "registry.lan" {
			foundDNS = true
		}
	}
	if !foundDNS {
		t.Errorf("expected SAN registry.lan, got %v", info.DNSNames)
	}
	foundIP := false
	for _, ip := range info.IPAddresses {
		if ip == "127.0.0.1" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Errorf("expected SAN IP 127.0.0.1, got %v", info.IPAddresses)
	}
}

func TestParseCertInfoRejectsGarbage(t *testing.T) {
	if _, err := parseCertInfo([]byte("not a pem")); err == nil {
		t.Error("expected error for non-PEM input")
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := config.Config{CertDir: t.TempDir()}
	return New(cfg, st)
}

func TestHandleRestartMethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	rr := httptest.NewRecorder()
	srv.handleRestart(rr, httptest.NewRequest(http.MethodGet, "/api/restart", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/restart: got %d want 405", rr.Code)
	}
}

func TestHandleRestartTLSPrecheckFails(t *testing.T) {
	srv := newTestServer(t)
	// Enable TLS but provide no cert -> precheck must reject and not signal.
	if err := srv.store.SetSetting(context.Background(), "tls_enabled", "true"); err != nil {
		t.Fatalf("set setting: %v", err)
	}
	rr := httptest.NewRecorder()
	srv.handleRestart(rr, httptest.NewRequest(http.MethodPost, "/api/restart", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("restart with missing cert: got %d want 400", rr.Code)
	}
	select {
	case <-srv.RestartRequested():
		t.Error("restart should not be signalled when TLS precheck fails")
	case <-time.After(500 * time.Millisecond):
		// expected: no signal
	}
}

func TestHandleRestartSignals(t *testing.T) {
	srv := newTestServer(t)
	// TLS disabled -> no precheck, restart proceeds.
	rr := httptest.NewRecorder()
	srv.handleRestart(rr, httptest.NewRequest(http.MethodPost, "/api/restart", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("restart: got %d want 200", rr.Code)
	}
	select {
	case <-srv.RestartRequested():
		// expected
	case <-time.After(2 * time.Second):
		t.Error("expected restart signal within 2s")
	}
}
