package config

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ServerAddr string
	AuthMode   string
	V2AuthMode string
	// ExternalURL is the absolute origin clients use to reach this server,
	// e.g. "https://registry.example.com:9999". Empty means "derive it from
	// each request" (TLS or X-Forwarded-Proto + Host).
	ExternalURL           string
	RegistryURL           string
	RegistryUsername      string
	RegistryPassword      string
	RegistryBearerToken   string
	RegistryTLSSkipVerify bool
	EnableDelete          bool
	AllowWebhookPrivateIP bool
	DataDir               string
	SQLitePath            string
	UploadDir             string
	CertDir               string
	RegistryDataDir       string
	RegistryConfig        string
}

func Load() (Config, error) {
	cfg := Config{
		ServerAddr:   getenv("SERVER_ADDR", ":8080"),
		AuthMode:     strings.ToLower(getenv("AUTH_MODE", "off")),
		V2AuthMode:   strings.ToLower(getenv("V2_AUTH_MODE", "registry")),
		RegistryURL:  strings.TrimRight(os.Getenv("REGISTRY_URL"), "/"),
		EnableDelete: getenvBool("ENABLE_DELETE", true),
		DataDir:      getenv("DATA_DIR", "./data"),
	}
	cfg.RegistryUsername = os.Getenv("REGISTRY_USERNAME")
	cfg.RegistryPassword = os.Getenv("REGISTRY_PASSWORD")
	cfg.RegistryBearerToken = os.Getenv("REGISTRY_BEARER_TOKEN")
	cfg.RegistryTLSSkipVerify = getenvBool("REGISTRY_TLS_SKIP_VERIFY", false)
	cfg.AllowWebhookPrivateIP = getenvBool("ALLOW_WEBHOOK_PRIVATE_IP", false)
	cfg.SQLitePath = getenv("SQLITE_PATH", cfg.DataDir+"/db/registry-ui.db")
	cfg.UploadDir = getenv("UPLOAD_DIR", cfg.DataDir+"/uploads")
	cfg.CertDir = getenv("CERT_DIR", cfg.DataDir+"/certs")
	cfg.RegistryDataDir = getenv("REGISTRY_DATA_DIR", cfg.DataDir+"/registry")
	cfg.RegistryConfig = getenv("REGISTRY_CONFIG", "/etc/distribution/config.yml")

	if cfg.RegistryURL != "" {
		if _, err := url.ParseRequestURI(cfg.RegistryURL); err != nil {
			return cfg, err
		}
	}
	// EXTERNAL_URL overrides the origin used for absolute URLs that clients
	// must be able to reach — first of all the OCI token realm
	// ("WWW-Authenticate: Bearer realm=…/v2/token") and the blob-upload
	// Location header. Behind a reverse proxy that does not forward
	// X-Forwarded-Proto/Host those would otherwise be built from the
	// upstream address and the token exchange would fail.
	cfg.ExternalURL = strings.TrimRight(strings.TrimSpace(os.Getenv("EXTERNAL_URL")), "/")
	if cfg.ExternalURL != "" {
		u, err := url.ParseRequestURI(cfg.ExternalURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return cfg, fmt.Errorf("EXTERNAL_URL must be an absolute http(s) URL with a host, got %q", cfg.ExternalURL)
		}
	}
	return cfg, nil
}

func (c Config) RegistryTLSConfig() *tls.Config {
	if !c.RegistryTLSSkipVerify {
		return nil
	}
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // Explicit opt-in for private registries with self-signed certs.
}

func (c Config) HasRegistryAuth() bool {
	return c.RegistryBearerToken != "" || c.RegistryUsername != "" || c.RegistryPassword != ""
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
