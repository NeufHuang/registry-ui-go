package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/neuf/registry-ui/backend/internal/config"
)

// StatusError is returned when the registry answers with a non-2xx status.
// It lets callers distinguish e.g. 404 (already gone) from transient
// failures without pattern-matching on the error string.
type StatusError struct {
	Op     string
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s: status=%d body=%s", e.Op, e.Status, truncate([]byte(e.Body)))
}

// IsStatus reports whether err (or anything it wraps) is a *StatusError
// with the given HTTP status code.
func IsStatus(err error, status int) bool {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status == status
	}
	return false
}

// StatusCode returns the HTTP status carried by err, if the registry actually
// answered. A missing status means the failure was a transport/timeout error
// rather than a registry-side rejection.
func StatusCode(err error) (int, bool) {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status, true
	}
	return 0, false
}

const ManifestAccept = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.v1+json"

type Client struct {
	cfg        config.Config
	httpClient *http.Client
}

func NewClient(cfg config.Config) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = cfg.RegistryTLSConfig()
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
}

func (c *Client) Health(ctx context.Context) (int, http.Header, []byte, error) {
	return c.do(ctx, http.MethodGet, "/v2/", "", nil)
}

func (c *Client) Catalog(ctx context.Context, n, last string) (CatalogResponse, error) {
	path := "/v2/_catalog"
	q := url.Values{}
	if n != "" {
		q.Set("n", n)
	}
	if last != "" {
		q.Set("last", last)
	}
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	status, header, body, err := c.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return CatalogResponse{}, err
	}
	if status < 200 || status >= 300 {
		return CatalogResponse{}, &StatusError{Op: "registry catalog failed", Status: status, Body: string(body)}
	}
	var out CatalogResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return out, err
	}
	out.Link = header.Get("Link")
	out.NextLast = parseNextLast(out.Link)
	return out, nil
}

func (c *Client) Tags(ctx context.Context, name string) (TagsResponse, error) {
	status, _, body, err := c.do(ctx, http.MethodGet, "/v2/"+escapeRepo(name)+"/tags/list", "", nil)
	if err != nil {
		return TagsResponse{}, err
	}
	if status < 200 || status >= 300 {
		return TagsResponse{}, &StatusError{Op: "registry tags failed", Status: status, Body: string(body)}
	}
	var out TagsResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return out, err
	}
	if out.Tags == nil {
		out.Tags = []string{}
	}
	return out, nil
}

func (c *Client) Manifest(ctx context.Context, name, ref string) (ManifestResponse, error) {
	raw, err := c.ManifestRaw(ctx, name, ref)
	if err != nil {
		return ManifestResponse{}, err
	}
	return ManifestResponse{Name: name, Reference: ref, Digest: raw.Digest, ContentType: raw.ContentType, Manifest: raw.Payload}, nil
}

func (c *Client) ManifestRaw(ctx context.Context, name, ref string) (RawManifest, error) {
	status, header, body, err := c.do(ctx, http.MethodGet, "/v2/"+escapeRepo(name)+"/manifests/"+url.PathEscape(ref), ManifestAccept, nil)
	if err != nil {
		return RawManifest{}, err
	}
	if status < 200 || status >= 300 {
		return RawManifest{}, &StatusError{Op: "registry manifest failed", Status: status, Body: string(body)}
	}
	var payload interface{}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		payload = json.RawMessage(body)
	}
	return RawManifest{Name: name, Reference: ref, Digest: header.Get("Docker-Content-Digest"), ContentType: header.Get("Content-Type"), Body: body, Payload: payload}, nil
}

func (c *Client) Digest(ctx context.Context, name, ref string) (string, string, error) {
	status, header, body, err := c.do(ctx, http.MethodHead, "/v2/"+escapeRepo(name)+"/manifests/"+url.PathEscape(ref), ManifestAccept, nil)
	if err != nil {
		return "", "", err
	}
	if status < 200 || status >= 300 {
		return "", "", &StatusError{Op: "registry digest lookup failed", Status: status, Body: string(body)}
	}
	return header.Get("Docker-Content-Digest"), header.Get("Content-Type"), nil
}

func (c *Client) DeleteManifest(ctx context.Context, name, digest string) error {
	if !c.cfg.EnableDelete {
		return fmt.Errorf("delete disabled by ENABLE_DELETE=false")
	}
	status, _, body, err := c.do(ctx, http.MethodDelete, "/v2/"+escapeRepo(name)+"/manifests/"+url.PathEscape(digest), ManifestAccept, nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return &StatusError{Op: "registry delete failed", Status: status, Body: string(body)}
	}
	return nil
}

func (c *Client) Blob(ctx context.Context, name, digest string) ([]byte, string, error) {
	status, header, body, err := c.do(ctx, http.MethodGet, "/v2/"+escapeRepo(name)+"/blobs/"+url.PathEscape(digest), "", nil)
	if err != nil {
		return nil, "", err
	}
	if status < 200 || status >= 300 {
		return nil, "", &StatusError{Op: "registry blob fetch failed", Status: status, Body: string(body)}
	}
	return body, header.Get("Content-Type"), nil
}

func (c *Client) PutManifest(ctx context.Context, name, ref, contentType string, body []byte) error {
	if contentType == "" {
		contentType = "application/vnd.docker.distribution.manifest.v2+json"
	}
	status, _, respBody, err := c.do(ctx, http.MethodPut, "/v2/"+escapeRepo(name)+"/manifests/"+url.PathEscape(ref), contentType, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return &StatusError{Op: "registry manifest restore failed", Status: status, Body: string(respBody)}
	}
	return nil
}

// maxResponseBytes bounds how much of a registry response is buffered in
// memory. Manifest and image-config payloads are small; without a cap a
// misbehaving upstream could exhaust memory in a single request.
const maxResponseBytes = 64 << 20

func (c *Client) do(ctx context.Context, method, path, accept string, body io.Reader) (int, http.Header, []byte, error) {
	if c.cfg.RegistryURL == "" {
		return 0, nil, nil, fmt.Errorf("REGISTRY_URL is required")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.RegistryURL+path, body)
	if err != nil {
		return 0, nil, nil, err
	}
	if accept != "" {
		if method == http.MethodPut {
			req.Header.Set("Content-Type", accept)
		} else {
			req.Header.Set("Accept", accept)
		}
	}
	c.applyAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%s %s: read response: %w", method, path, err)
	}
	if int64(len(data)) > maxResponseBytes {
		return 0, nil, nil, fmt.Errorf("%s %s: response exceeds %d bytes", method, path, maxResponseBytes)
	}
	return resp.StatusCode, resp.Header.Clone(), data, nil
}

func (c *Client) ApplyAuth(req *http.Request) { c.applyAuth(req) }

func (c *Client) applyAuth(req *http.Request) {
	if c.cfg.RegistryBearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.RegistryBearerToken)
		return
	}
	if c.cfg.RegistryUsername != "" || c.cfg.RegistryPassword != "" {
		req.SetBasicAuth(c.cfg.RegistryUsername, c.cfg.RegistryPassword)
	}
}

func escapeRepo(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

func parseNextLast(link string) string {
	// Registry pagination Link example: </v2/_catalog?last=repo&n=100>; rel="next"
	if link == "" || !strings.Contains(link, "rel=\"next\"") {
		return ""
	}
	start := strings.Index(link, "<")
	end := strings.Index(link, ">")
	if start < 0 || end <= start {
		return ""
	}
	u, err := url.Parse(link[start+1 : end])
	if err != nil {
		return ""
	}
	return u.Query().Get("last")
}

func truncate(b []byte) string {
	s := string(b)
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}
