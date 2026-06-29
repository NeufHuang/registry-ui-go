package config

import (
	"crypto/tls"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ServerAddr            string
	AuthMode              string
	V2AuthMode            string
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
