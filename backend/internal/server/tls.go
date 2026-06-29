package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxCertUploadBytes = 64 << 10 // 64 KiB per PEM blob

// certPath and keyPath return the on-disk locations of the UI-managed TLS
// certificate and private key. They live in CERT_DIR, which is never served
// over HTTP, so the private key stays isolated.
func (s *Server) CertPath() string { return filepath.Join(s.cfg.CertDir, "cert.pem") }
func (s *Server) KeyPath() string  { return filepath.Join(s.cfg.CertDir, "key.pem") }

// TLSEnabled reports whether the operator turned on TLS via the UI toggle.
func (s *Server) TLSEnabled() bool {
	return s.store.GetSettingBool(context.Background(), "tls_enabled", false)
}

// TLSReady reports whether TLS should actually be served: the toggle is on
// and a valid certificate/key pair exists on disk.
func (s *Server) TLSReady() bool {
	if !s.TLSEnabled() {
		return false
	}
	if _, err := tls.LoadX509KeyPair(s.CertPath(), s.KeyPath()); err != nil {
		return false
	}
	return true
}

// certInfo is the public (no private key) description of a certificate.
type certInfo struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	DNSNames    []string  `json:"dnsNames"`
	IPAddresses []string  `json:"ipAddresses"`
	Expired     bool      `json:"expired"`
}

// parseCertInfo extracts non-sensitive metadata from a leaf certificate PEM.
func parseCertInfo(certPEM []byte) (*certInfo, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return &certInfo{
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		DNSNames:    cert.DNSNames,
		IPAddresses: ips,
		Expired:     time.Now().After(cert.NotAfter),
	}, nil
}

// handleRestart triggers an in-place restart of the server process (admin
// only). Before signalling, when TLS is enabled it re-validates the on-disk
// cert/key pair so a broken certificate can never lock the operator out: a
// failed precheck rejects the restart and keeps the current process alive.
func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if u := s.GetCurrentUser(r); u != nil && !u.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	if s.TLSEnabled() {
		if _, err := tls.LoadX509KeyPair(s.CertPath(), s.KeyPath()); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "TLS is enabled but the certificate is missing or invalid; fix it before restarting", "code": "tlsCertInvalid", "details": err.Error()})
			return
		}
	}
	_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "system.restart", "", "", "", "ok", "")
	writeJSON(w, http.StatusOK, map[string]any{"restarting": true})
	// Fire the restart slightly after the response is flushed so the client
	// reliably receives the 200 before connections are drained.
	time.AfterFunc(300*time.Millisecond, func() {
		select {
		case s.restartCh <- struct{}{}:
		default:
		}
	})
}
//
//	GET    -> current TLS status + certificate metadata (never the key)
//	POST   -> upload/replace cert+key (admin only); validated, stored atomically
//	DELETE -> remove cert+key and disable TLS (admin only)
func (s *Server) handleTLSCert(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.tlsCertStatus(w, r)
	case http.MethodPost:
		s.tlsCertUpload(w, r)
	case http.MethodDelete:
		s.tlsCertDelete(w, r)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) tlsCertStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"enabled": s.store.GetSettingBool(r.Context(), "tls_enabled", false),
		"hasCert": false,
	}
	certPEM, err := os.ReadFile(s.CertPath())
	if err == nil {
		if info, perr := parseCertInfo(certPEM); perr == nil {
			resp["hasCert"] = true
			resp["cert"] = info
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) tlsCertUpload(w http.ResponseWriter, r *http.Request) {
	if u := s.GetCurrentUser(r); u != nil && !u.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	certPEM, keyPEM, err := readCertKey(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "tlsInvalidInput"})
		return
	}
	// Validate that the cert and key form a usable pair.
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "certificate and private key do not match or are invalid", "code": "tlsInvalidPair", "details": err.Error()})
		return
	}
	info, err := parseCertInfo(certPEM)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "tlsInvalidPair"})
		return
	}
	if err := os.MkdirAll(s.cfg.CertDir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := atomicWrite(s.CertPath(), certPEM, 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := atomicWrite(s.KeyPath(), keyPEM, 0o600); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "tls.cert.upload", "", "", "", "ok", "subject="+info.Subject)
	writeJSON(w, http.StatusOK, map[string]any{"saved": true, "restartRequired": true, "cert": info})
}

func (s *Server) tlsCertDelete(w http.ResponseWriter, r *http.Request) {
	if u := s.GetCurrentUser(r); u != nil && !u.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	_ = os.Remove(s.CertPath())
	_ = os.Remove(s.KeyPath())
	if err := s.store.SetSetting(r.Context(), "tls_enabled", "false"); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "tls.cert.delete", "", "", "", "ok", "")
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "restartRequired": true})
}

// readCertKey extracts the certificate and key PEM blobs from either a
// multipart upload (fields "cert"/"key") or a JSON body ({cert, key}).
func readCertKey(r *http.Request) (cert, key []byte, err error) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		if err = r.ParseMultipartForm(2 * maxCertUploadBytes); err != nil {
			return nil, nil, fmt.Errorf("invalid multipart form: %w", err)
		}
		cert, err = readFormFile(r, "cert")
		if err != nil {
			return nil, nil, err
		}
		key, err = readFormFile(r, "key")
		if err != nil {
			return nil, nil, err
		}
		return cert, key, nil
	}
	var body struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 4*maxCertUploadBytes))
	if err = dec.Decode(&body); err != nil {
		return nil, nil, fmt.Errorf("invalid request body: %w", err)
	}
	cert = []byte(strings.TrimSpace(body.Cert))
	key = []byte(strings.TrimSpace(body.Key))
	if len(cert) == 0 || len(key) == 0 {
		return nil, nil, fmt.Errorf("both cert and key are required")
	}
	return cert, key, nil
}

func readFormFile(r *http.Request, field string) ([]byte, error) {
	f, _, err := r.FormFile(field)
	if err != nil {
		return nil, fmt.Errorf("%s file is required: %w", field, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxCertUploadBytes))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s file is empty", field)
	}
	return data, nil
}

// atomicWrite writes data to a temp file in the same directory and renames it
// into place, so a concurrent reader never sees a half-written file.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
