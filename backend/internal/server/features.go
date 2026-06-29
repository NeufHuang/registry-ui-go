package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/neuf/registry-ui/backend/internal/store"
)

// ---- Immutable Tag Rules ----

func (s *Server) handleImmutableRules(w http.ResponseWriter, r *http.Request) {
	u := s.GetCurrentUser(r)
	if u == nil || !u.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		rules, err := s.store.ListImmutableTagRules(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
	case http.MethodPost:
		var req struct {
			Pattern     string `json:"pattern"`
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.Pattern == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "pattern is required"})
			return
		}
		rule, err := s.store.CreateImmutableTagRule(r.Context(), store.ImmutableTagRule{Pattern: req.Pattern, Description: req.Description})
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, rule)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleImmutableRuleByID(w http.ResponseWriter, r *http.Request) {
	u := s.GetCurrentUser(r)
	if u == nil || !u.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/immutable-rules/")
	id, ok := parseID(idStr)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	if err := s.store.DeleteImmutableTagRule(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "immutable-rule.delete", "", "", "", "ok", fmt.Sprintf("rule_id=%d", id))
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func matchImmutableTagPattern(pattern, tag string) bool {
	// Convert glob-like pattern to regex: * matches anything, ? matches single char
	reStr := "^"
	for _, ch := range pattern {
		switch ch {
		case '*':
			reStr += ".*"
		case '?':
			reStr += "."
		case '.', '+', '(', ')', '[', ']', '{', '}', '^', '$', '|', '\\':
			reStr += "\\" + string(ch)
		default:
			reStr += string(ch)
		}
	}
	reStr += "$"
	matched, _ := regexp.MatchString(reStr, tag)
	return matched
}

func (s *Server) checkImmutableTag(ctx context.Context, repo, ref string, forceImmutable bool) (bool, string) {
	if ref == "" || strings.Contains(ref, ":") {
		return false, ""
	}
	if forceImmutable {
		return true, "repo-immutable"
	}
	// Check global immutable tag rules
	rules, err := s.store.ListImmutableTagRules(ctx)
	if err != nil {
		return false, ""
	}
	for _, rule := range rules {
		if matchImmutableTagPattern(rule.Pattern, ref) {
			return true, rule.Pattern
		}
	}
	return false, ""
}

// ---- Repo Descriptions ----

func (s *Server) handleRepoDescription(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/repo-description/")
	repo := strings.TrimSuffix(path, "/description")
	if repo == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		desc, err := s.store.GetRepoDescription(r.Context(), repo)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"repo": repo, "description": desc})
	case http.MethodPut:
		var req struct {
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.store.SetRepoDescription(r.Context(), repo, req.Description); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		_ = s.store.AddAudit(r.Context(), s.currentUserID(r), "repo.description", repo, "", "", "ok", "description updated")
		writeJSON(w, http.StatusOK, map[string]any{"saved": true})
	default:
		methodNotAllowed(w)
	}
}

// ---- API Tokens ----

func (s *Server) handleTokenByID(w http.ResponseWriter, r *http.Request) {
	u := s.GetCurrentUser(r)
	if u == nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/tokens/")
	id, ok := parseID(idStr)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	// Ownership check: a token may be deleted by its owner or by any admin.
	tok, err := s.store.GetAPITokenByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if tok.UserID != u.ID && !u.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	if err := s.store.DeleteAPIToken(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.store.AddAudit(r.Context(), u.ID, "token.delete", "", "", "", "ok", fmt.Sprintf("token_id=%d name=%s owner_id=%d", id, tok.Name, tok.UserID))
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request) {
	u := s.GetCurrentUser(r)
	if u == nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		tokens, err := s.store.ListAPITokens(r.Context(), u.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
	case http.MethodPost:
		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			ExpiresIn   int    `json:"expiresIn"` // hours, 0 = no expiry
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name is required"})
			return
		}
		// Generate token: prefix + random hex
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		tokenHex := hex.EncodeToString(b)
		prefix := tokenHex[:12]
		hash := sha256Hex(tokenHex)
		var expiresAt *time.Time
		if req.ExpiresIn > 0 {
			t := time.Now().Add(time.Duration(req.ExpiresIn) * time.Hour)
			expiresAt = &t
		}
		apiToken := store.APIToken{
			UserID:      u.ID,
			Name:        req.Name,
			TokenHash:   hash,
			TokenPrefix: prefix,
			Description: req.Description,
			ExpiresAt:   expiresAt,
		}
		created, err := s.store.CreateAPIToken(r.Context(), apiToken)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = s.store.AddAudit(r.Context(), u.ID, "token.create", "", "", "", "ok", fmt.Sprintf("token_id=%d name=%s prefix=%s", created.ID, created.Name, prefix))
		// Return full token only on creation
		writeJSON(w, http.StatusCreated, map[string]any{
			"token":     created,
			"fullToken": fmt.Sprintf("ru_%s_%s", prefix, tokenHex),
		})
	default:
		methodNotAllowed(w)
	}
}

// Export

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format != "csv" && format != "json" {
		format = "json"
	}
	client := s.client
	catalog, err := client.Catalog(r.Context(), "", "")
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	type ExportRow struct {
		Repo        string `json:"repo"`
		Tag         string `json:"tag"`
		Digest      string `json:"digest"`
		ContentType string `json:"contentType"`
		Size        int64  `json:"size,omitempty"`
	}
	var rows []ExportRow
	for _, repo := range catalog.Repositories {
		tagsResp, err := client.Tags(r.Context(), repo)
		if err != nil {
			continue
		}
		for _, tag := range tagsResp.Tags {
			m, err := client.Manifest(r.Context(), repo, tag)
			if err != nil {
				continue
			}
			size := computeManifestSize(m.Manifest)
			rows = append(rows, ExportRow{Repo: repo, Tag: tag, Digest: m.Digest, ContentType: m.ContentType, Size: size})
		}
	}
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=registry-export.csv")
		writer := csv.NewWriter(w)
		_ = writer.Write([]string{"repo", "tag", "digest", "contentType", "size"})
		for _, row := range rows {
			_ = writer.Write([]string{row.Repo, row.Tag, row.Digest, row.ContentType, strconv.FormatInt(row.Size, 10)})
		}
		writer.Flush()
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=registry-export.json")
	writeJSON(w, http.StatusOK, map[string]any{"exportedAt": time.Now().UTC(), "items": rows})
}

// ---- Repo Stats ----

func (s *Server) handleRepoStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	stats, err := s.store.ListRepoStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stats": stats})
}

// ---- Webhooks ----

func (s *Server) handleWebhooks(w http.ResponseWriter, r *http.Request) {
	u := s.GetCurrentUser(r)
	if u == nil || !u.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		hooks, err := s.store.ListWebhooks(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"webhooks": hooks})
	case http.MethodPost:
		var req struct {
			URL          string `json:"url"`
			SecretHeader string `json:"secretHeader"`
			Events       string `json:"events"`
			Enabled      bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.URL == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "url is required"})
			return
		}
		if err := s.validateWebhookURL(req.URL); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid webhook url", "details": err.Error()})
			return
		}
		if req.Events == "" {
			req.Events = "push,delete,untag,restore"
		}
		hook, err := s.store.CreateWebhook(r.Context(), store.Webhook{
			URL: req.URL, SecretHeader: req.SecretHeader,
			Events: req.Events, Enabled: req.Enabled,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, hook)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleWebhookByID(w http.ResponseWriter, r *http.Request) {
	u := s.GetCurrentUser(r)
	if u == nil || !u.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/webhooks/")
	parts := strings.Split(path, "/")
	id, ok := parseID(parts[0])
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req struct {
			URL          string `json:"url"`
			SecretHeader string `json:"secretHeader"`
			Events       string `json:"events"`
			Enabled      bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.URL == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "url is required"})
			return
		}
		if err := s.validateWebhookURL(req.URL); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid webhook url", "details": err.Error()})
			return
		}
		err := s.store.UpdateWebhook(r.Context(), store.Webhook{
			ID: id, URL: req.URL, SecretHeader: req.SecretHeader,
			Events: req.Events, Enabled: req.Enabled,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"updated": true})
	case http.MethodDelete:
		if err := s.store.DeleteWebhook(r.Context(), id); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
	default:
		methodNotAllowed(w)
	}
}

// FireWebhookEvent sends async POST to all enabled webhooks matching the event
var fireWebhookClient = &http.Client{Timeout: 10 * time.Second}

func (s *Server) fireWebhookEvent(event, repo, ref, digest string) {
	// Use a simple goroutine with background context
	go func() {
		hooks, err := s.store.ListWebhooks(context.Background())
		if err != nil {
			return
		}
		for _, hook := range hooks {
			if !hook.Enabled {
				continue
			}
			if !webhookMatchesEvent(hook.Events, event) {
				continue
			}
			// Re-validate at delivery time so legacy/imported rows that
			// point at internal addresses are not used as an SSRF vector.
			if err := s.validateWebhookURL(hook.URL); err != nil {
				log.Printf("webhook %s skipped (event=%s): %v", hook.URL, event, err)
				continue
			}
			body, _ := json.Marshal(map[string]string{
				"event":  event,
				"repo":   repo,
				"ref":    ref,
				"digest": digest,
				"time":   time.Now().UTC().Format(time.RFC3339),
			})
			req, err := http.NewRequest(http.MethodPost, hook.URL, bytes.NewReader(body))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			if hook.SecretHeader != "" {
				parts := strings.SplitN(hook.SecretHeader, ":", 2)
				if len(parts) == 2 {
					req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
				}
			}
			resp, err := fireWebhookClient.Do(req)
			if err != nil {
				log.Printf("webhook %s delivery failed (event=%s repo=%s): %v", hook.URL, event, repo, err)
				continue
			}
			resp.Body.Close()
		}
	}()
}

// webhookMatchesEvent reports whether the comma-separated events list contains
// the given event as an exact element (after trimming spaces). This avoids the
// substring false-positives that strings.Contains would allow if event names
// ever shared prefixes.
func webhookMatchesEvent(events, event string) bool {
	for _, e := range strings.Split(events, ",") {
		if strings.TrimSpace(e) == event {
			return true
		}
	}
	return false
}

// validateWebhookURL guards against SSRF: webhook targets are admin-supplied
// but the server makes outbound requests to them, so an attacker with admin
// access (or a misconfiguration) could probe internal services. We require an
// http/https scheme and, unless ALLOW_WEBHOOK_PRIVATE_IP is set, reject hosts
// that resolve to loopback, link-local, or private address ranges.
func (s *Server) validateWebhookURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url scheme must be http or https")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("url host is required")
	}
	if s.cfg.AllowWebhookPrivateIP {
		return nil
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		resolved, rerr := net.LookupIP(host)
		if rerr != nil {
			return fmt.Errorf("cannot resolve host %q: %w", host, rerr)
		}
		ips = resolved
	}
	for _, ip := range ips {
		if isInternalIP(ip) {
			return fmt.Errorf("url resolves to a non-public address (%s); set ALLOW_WEBHOOK_PRIVATE_IP=true to allow", ip)
		}
	}
	return nil
}

// isInternalIP reports whether ip is in a range that should not be reachable
// from an externally-configured webhook (loopback, link-local, private,
// unspecified, or unique-local IPv6).
func isInternalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	return false
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
