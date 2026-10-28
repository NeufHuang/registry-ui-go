package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/neuf/registry-ui/backend/internal/registry"
	"github.com/neuf/registry-ui/backend/internal/store"
)

const csrfCookieName = "csrf_token"

const sessionCookieName = "registry_ui_session"

const sessionTTL = 7 * 24 * time.Hour

// sessionEntry is the in-memory session value. expiresAt allows lazy
// expiry and lets the background cleaner evict stale sessions so the
// session store does not grow without bound.
type sessionEntry struct {
	username  string
	expiresAt time.Time
}

func (s *Server) authEnabled() bool {
	return s.cfg.AuthMode == "basic"
}

// secureCookie reports whether the Secure flag should be set on cookies.
// Cookies marked Secure are not sent by browsers over plain HTTP, which
// would break login on a plain-HTTP deployment. We therefore only mark
// cookies Secure when the request actually arrived over HTTPS (direct TLS
// or via a proxy that sets X-Forwarded-Proto=https).
func (s *Server) secureCookie(r *http.Request) bool {
	if r != nil {
		if r.TLS != nil {
			return true
		}
		if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			return true
		}
	}
	return false
}

// externalOrigin returns the absolute origin (scheme://host[:port]) clients
// use to reach this server, for URLs a client has to be able to follow on its
// own: the OCI token realm and the blob-upload Location header.
//
// EXTERNAL_URL wins when configured. It exists for reverse proxies that do
// not forward X-Forwarded-Proto/Host: without it the origin would be derived
// from the upstream request (http://127.0.0.1:8080, or a host without the
// published port) and the client would fetch the token from an address it
// cannot reach.
func (s *Server) externalOrigin(r *http.Request) string {
	if base := strings.TrimRight(strings.TrimSpace(s.cfg.ExternalURL), "/"); base != "" {
		return base
	}
	scheme := "http"
	if s.secureCookie(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// createSession creates a new session and sets cookie
func (s *Server) createSession(w http.ResponseWriter, r *http.Request, username string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	sessionID := hex.EncodeToString(b)
	secure := s.secureCookie(r)
	// Set session cookie (7 days)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	// Set CSRF token cookie
	s.setCSRFCookie(w, r)
	// Store session in memory with an expiry so the store can be cleaned.
	s.sessionStore.Store(sessionID, sessionEntry{username: username, expiresAt: time.Now().Add(sessionTTL)})
	return sessionID
}

// getSession returns username from session cookie
func (s *Server) getSession(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	v, ok := s.sessionStore.Load(cookie.Value)
	if !ok {
		// The browser presented a cookie this process does not know: it was
		// issued by another instance, or the store was cleared (restart).
		// Without this line an unexplained "logged out again" leaves no
		// server-side trace at all.
		s.logSessionDrop(shortID(cookie.Value),
			fmt.Sprintf("cookie=%s… unknown session id: not in this process's store (restart, another instance, or never issued here)", shortID(cookie.Value)))
		return ""
	}
	entry, ok := v.(sessionEntry)
	if !ok {
		s.sessionStore.Delete(cookie.Value)
		s.logSessionDrop(shortID(cookie.Value), fmt.Sprintf("cookie=%s… malformed session entry", shortID(cookie.Value)))
		return ""
	}
	if now := time.Now(); now.After(entry.expiresAt) {
		created := entry.expiresAt.Add(-sessionTTL)
		s.sessionStore.Delete(cookie.Value)
		s.logSessionDrop(shortID(cookie.Value), fmt.Sprintf(
			"cookie=%s… expired: user=%q age=%s ttl=%s (created %s)",
			shortID(cookie.Value), entry.username, now.Sub(created).Round(time.Minute), sessionTTL, created.Format(time.RFC3339)))
		return ""
	}
	return entry.username
}

// shortID truncates a session cookie id for log lines: the full value is a
// live credential, and the prefix is enough to correlate requests.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// logSessionDrop records why a session cookie was refused. Output is
// throttled to one line per key per 10 minutes so a dead cookie left in a
// browser cannot flood the log; the throttle map itself is pruned by
// cleanupSessions.
func (s *Server) logSessionDrop(key, reason string) {
	now := time.Now()
	if v, ok := s.sessionDropLogs.Load(key); ok {
		if last, ok := v.(time.Time); ok && now.Sub(last) < 10*time.Minute {
			return
		}
	}
	s.sessionDropLogs.Store(key, now)
	log.Printf("auth: session dropped: %s", reason)
}

// cleanupSessions periodically evicts expired session entries so the
// in-memory store stays bounded even under heavy churn.
func (s *Server) cleanupSessions() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.sessionStore.Range(func(key, value any) bool {
			if entry, ok := value.(sessionEntry); !ok || now.After(entry.expiresAt) {
				s.sessionStore.Delete(key)
			}
			return true
		})
		s.sessionDropLogs.Range(func(key, value any) bool {
			if t, ok := value.(time.Time); ok && now.Sub(t) > time.Hour {
				s.sessionDropLogs.Delete(key)
			}
			return true
		})
	}
}

// clearSession removes the session cookie
func (s *Server) clearSession(w http.ResponseWriter, r *http.Request) {
	secure := s.secureCookie(r)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (s *Server) requireUIAuth(w http.ResponseWriter, r *http.Request) bool {
	if !s.authEnabled() {
		return true
	}

	// Check session cookie first
	if sessionUser := s.getSession(r); sessionUser != "" {
		u, err := s.store.GetUserByUsername(r.Context(), sessionUser)
		if err == nil && u.Enabled {
			*r = *r.WithContext(context.WithValue(r.Context(), ctxUserKey{}, u))
			return true
		}
		// Session user not found or disabled, clear and fall back
		if err != nil {
			s.logSessionDrop(sessionUser, fmt.Sprintf("session user %q unusable: lookup failed: %v", sessionUser, err))
		} else {
			s.logSessionDrop(sessionUser, fmt.Sprintf("session user %q unusable: account disabled", sessionUser))
		}
		s.clearSession(w, r)
	}

	user, pass, ok := r.BasicAuth()
	if !ok {
		s.challenge(w, r)
		return false
	}
	// check db user
	u, err := s.store.GetUserByUsername(r.Context(), user)
	if err != nil || !u.Enabled {
		s.challenge(w, r)
		return false
	}
	// Compare password hash (supports bcrypt and legacy SHA256)
	if store.VerifyPasswordHash(u.PasswordHash, pass) {
		s.maybeUpgradePassword(r.Context(), u, pass)
		// Only browser-facing requests get a session cookie. Docker CLI
		// and API clients hit /v2/* (and send Basic Auth on every
		// request); minting a session per request would leak entries
		// into the in-memory session store without bound.
		if !strings.HasPrefix(r.URL.Path, "/v2/") {
			s.createSession(w, r, user)
		}
		*r = *r.WithContext(context.WithValue(r.Context(), ctxUserKey{}, u))
		return true
	}
	s.challenge(w, r)
	return false
}

type ctxUserKey struct{}

// GetCurrentUser extracts user from request context
func (s *Server) GetCurrentUser(r *http.Request) *store.User {
	u, ok := r.Context().Value(ctxUserKey{}).(store.User)
	if !ok {
		return nil
	}
	return &u
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authEnabled() {
			next.ServeHTTP(w, r)
			return
		}

		// Allow login page, the OCI token endpoint and static assets without auth
		if r.URL.Path == "/login" || r.URL.Path == "/login.html" || r.URL.Path == "/api/login" ||
			r.URL.Path == "/v2/token" ||
			strings.HasPrefix(r.URL.Path, "/uploads/") ||
			strings.HasSuffix(r.URL.Path, ".css") ||
			strings.HasSuffix(r.URL.Path, ".js") ||
			strings.HasSuffix(r.URL.Path, ".html") ||
			strings.HasSuffix(r.URL.Path, ".svg") ||
			strings.HasSuffix(r.URL.Path, ".png") {
			next.ServeHTTP(w, r)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/v2/") {
			switch s.v2AuthMode() {
			case "ui", "basic", "same":
				// The credential presented on the request decides which of three
				// very different paths is taken:
				//
				//   none   → anonymous pull: the manifest/blob endpoints of repos
				//            whose anonymous_pull flag is enabled are served as-is,
				//            so `docker pull` works without `docker login`. Every
				//            other path goes through requireUIAuth, which also
				//            covers browsers that only hold a session cookie.
				//   Bearer → the OCI token flow (see v2_token.go). An anonymous
				//            token receives exactly what a credential-less request
				//            receives; a user token is a real identity and is
				//            checked against namespace permissions below.
				//   other  → Basic (or anything else) is *always* verified. A
				//            presented credential that gets silently ignored was
				//            what let `docker login` answer "Login Succeeded" for a
				//            wrong password and made a stale stored credential look
				//            like "logged in, yet the pull is unauthorized".
				authz := r.Header.Get("Authorization")
				switch {
				case authz == "":
					if s.anonymousV2Pull(r) {
						next.ServeHTTP(w, r)
						return
					}
					if !s.requireUIAuth(w, r) {
						return
					}
				case strings.HasPrefix(authz, "Bearer "):
					switch s.authenticateV2Bearer(w, r, strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))) {
					case v2AuthRejected:
						// 401 + challenge already written.
						return
					case v2AuthAnonymous:
						if s.anonymousV2Pull(r) {
							next.ServeHTTP(w, r)
							return
						}
						// The ping carries no repository, so an authenticated
						// anonymous client is answered with plain 200 instead of
						// a challenge — otherwise a client that re-pings with the
						// token it just obtained would be challenged forever.
						// Repository listings and tags still require a user.
						if r.URL.Path == "/v2/" || r.URL.Path == "/v2" {
							next.ServeHTTP(w, r)
							return
						}
						s.challenge(w, r)
						return
					case v2AuthUser:
						// Authenticated: fall through to the checks below.
					}
				default:
					if !s.requireUIAuth(w, r) {
						return
					}
				}
				// After auth, enforce namespace authorization (skip /v2/ root and /v2/_catalog)
				if repoPath := extractV2RepoPath(r.URL.Path); repoPath != "" {
					if !s.userCanAccessRepo(r, repoPath) {
						writeJSON(w, http.StatusForbidden, registry.DistributionErrorResponse{Errors: []registry.DistributionError{{Code: "DENIED", Message: "no permission to access this repository"}}})
						return
					}
					// Check write permission for mutating V2 API requests (push, delete)
					if r.Method == http.MethodPut || r.Method == http.MethodPost || r.Method == http.MethodPatch || r.Method == http.MethodDelete {
						if !s.userCanWriteRepo(r, repoPath) {
							writeJSON(w, http.StatusForbidden, registry.DistributionErrorResponse{Errors: []registry.DistributionError{{Code: "DENIED", Message: "no write permission for this repository"}}})
							return
						}
					}
				}
			case "registry", "proxy", "off":
				// Leave Docker Registry API auth behavior to the configured registry/proxy.
			default:
				if !s.requireUIAuth(w, r) {
					return
				}
			}
			if !s.enforcePasswordChange(w, r) {
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Check API token first (Bearer token)
		if s.checkAPITokenAuth(w, r) {
			if !s.enforcePasswordChange(w, r) {
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// All other paths require auth
		if !s.requireUIAuth(w, r) {
			return
		}
		if !s.enforcePasswordChange(w, r) {
			return
		}

		next.ServeHTTP(w, r)
	})
}

// mustChangePasswordExempt lists the only endpoints a user with a pending
// forced password change may call. Everything else under /api/ and /v2/
// returns 403 until the password is rotated. The flag is no longer set by
// the default-admin seed (rotation is not forced), so this list only matters
// when a row is set explicitly.
func mustChangePasswordExempt(path string) bool {
	switch path {
	case "/api/login", "/api/logout", "/api/user", "/api/me", "/api/user/password":
		return true
	}
	return false
}

// isEndpointPath reports whether path is served by an API/registry handler
// rather than by the embedded UI (pages, deep links and static assets).
func isEndpointPath(path string) bool {
	return strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/v2/")
}

// enforcePasswordChange rejects requests from a user whose password still
// carries the must-change flag. Returns false (and writes the response) when
// blocked.
//
// Only endpoints are gated. The UI shell and its assets must stay reachable:
// the change-password form lives inside the shell, so answering the browser's
// post-login redirect to "/" with this JSON body left a fresh deployment
// showing {"error":"password_change_required"} with no way to rotate the
// password. The forced change is still enforced client-side (the profile
// modal cannot be dismissed) and server-side for every /api/ and /v2/ call.
//
// Since the default admin is seeded with the flag cleared, this gate normally
// stays dormant; it remains as a safety net for explicitly flagged rows.
func (s *Server) enforcePasswordChange(w http.ResponseWriter, r *http.Request) bool {
	u := s.GetCurrentUser(r)
	if u == nil || !u.MustChangePassword {
		return true
	}
	if mustChangePasswordExempt(r.URL.Path) || !isEndpointPath(r.URL.Path) {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":   "password_change_required",
		"details": "the default password must be changed before using other endpoints",
	})
	return false
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	// Docker CLI expects 401 + WWW-Authenticate for /v2/ paths, and parses the
	// error code from the OCI Distribution Spec error envelope.
	//
	// The scheme advertised here must be Bearer (token flow), not Basic: a
	// Docker client that has no stored credentials treats a Basic challenge as
	// unsatisfiable and refuses to send any further request to this endpoint
	// ("no basic auth credentials"), which would break anonymous pull. See
	// v2_token.go for the full rationale.
	if r.URL.Path == "/v2" || strings.HasPrefix(r.URL.Path, "/v2/") {
		w.Header().Set("WWW-Authenticate", s.v2Challenge(r))
		writeJSON(w, http.StatusUnauthorized, registry.DistributionErrorResponse{
			Errors: []registry.DistributionError{{Code: "UNAUTHORIZED", Message: "authentication required"}},
		})
		return
	}
	// Browser requests redirect to login page
	http.Redirect(w, r, "/login.html", http.StatusSeeOther)
}

func (s *Server) v2AuthMode() string {
	mode := strings.ToLower(strings.TrimSpace(s.cfg.V2AuthMode))
	if mode == "" {
		return "registry"
	}
	return mode
}

func (s *Server) isAnonymousPullAllowed(ctx context.Context, repo string) bool {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) == 2 {
		if allowed, err := s.store.IsRepoAnonymousPullAllowed(ctx, parts[0], parts[1]); err == nil {
			return allowed
		}
	}
	// Single-level repos (root namespace, e.g. "python") have no namespace
	// separator, so their per-repo flag lives in the settings table under
	// the "allow_anonymous_pull:<repo>" key. Check it before falling back
	// to the global default.
	if v, err := s.store.GetSetting(ctx, "allow_anonymous_pull:"+repo); err == nil && v != "" {
		return v == "true"
	}
	// Global default: anonymous pull is off by default.
	return s.store.GetSettingBool(ctx, "allow_anonymous_pull", false)
}

// checkAPITokenAuth validates a Bearer token from the Authorization header
// against the api_tokens table. Returns true if the token is valid.
func (s *Server) checkAPITokenAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	if len(token) < 16 {
		return false
	}
	// Token format: ru_PREFIX_HEX
	parts := strings.SplitN(token, "_", 3)
	if len(parts) != 3 || parts[0] != "ru" {
		return false
	}
	prefix := parts[1]
	stored, err := s.store.GetAPITokenByPrefix(r.Context(), prefix)
	if err != nil {
		return false
	}
	// Check expiry
	if stored.ExpiresAt != nil && time.Now().After(*stored.ExpiresAt) {
		return false
	}
	// Verify hash. The stored hash is computed over the random hex segment
	// only (parts[2]), so we must hash the same segment here rather than the
	// full "ru_PREFIX_HEX" token string. Use a constant-time comparison to
	// avoid leaking hash bytes through timing.
	hash := sha256Hex(parts[2])
	if !constantTimeEqual(hash, stored.TokenHash) {
		return false
	}
	// Look up user
	u, err := s.store.GetUserByID(r.Context(), stored.UserID)
	if err != nil || !u.Enabled {
		return false
	}
	// Touch last_used_at
	_ = s.store.TouchAPIToken(r.Context(), stored.ID)
	*r = *r.WithContext(context.WithValue(r.Context(), ctxUserKey{}, u))
	return true
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// maybeUpgradePassword transparently re-hashes a user's password from the
// legacy SHA256 format to bcrypt after a successful verification. The
// plaintext is only available at login time, so this is the natural place
// to retire legacy hashes. Failures are logged but never block the login.
func (s *Server) maybeUpgradePassword(ctx context.Context, u store.User, plaintext string) {
	if !store.NeedsPasswordUpgrade(u.PasswordHash) {
		return
	}
	newHash, err := store.UpgradePassword(u.PasswordHash, plaintext)
	if err != nil {
		log.Printf("password upgrade for user %q failed: %v", u.Username, err)
		return
	}
	if err := s.store.SetUserPasswordHash(ctx, u.ID, newHash); err != nil {
		log.Printf("persist upgraded password for user %q failed: %v", u.Username, err)
	}
}

// setCSRFCookie sets the CSRF token cookie
func (s *Server) setCSRFCookie(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

// validateCSRF checks the X-CSRF-Token header against the csrf_token cookie
func validateCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return false
	}
	headerToken := r.Header.Get("X-CSRF-Token")
	if headerToken == "" {
		return false
	}
	return constantTimeEqual(cookie.Value, headerToken)
}

// requireCSRF is a middleware that validates CSRF token for state-changing requests
func (s *Server) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip CSRF for safe methods
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		// Skip CSRF for login and v2 proxy
		if r.URL.Path == "/api/login" || strings.HasPrefix(r.URL.Path, "/v2/") {
			next.ServeHTTP(w, r)
			return
		}
		// Bearer API tokens are not ambient credentials: a cross-site request
		// cannot attach an Authorization header, so CSRF does not apply. Without
		// this exemption the documented "use a Bearer token to call any API"
		// was impossible for POST/PUT/DELETE.
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			next.ServeHTTP(w, r)
			return
		}
		// With AUTH_MODE=off there is no authenticated identity to ride: the
		// UI is anonymous, so a forged cross-site request carries exactly the
		// authority of a direct one and CSRF protects nothing. Worse, no
		// csrf_token cookie is ever issued in that mode (createSession, which
		// runs on login only, is the sole issuer), so enforcing CSRF rejected
		// every save from the browser with "CSRF token validation failed".
		if !s.authEnabled() {
			next.ServeHTTP(w, r)
			return
		}
		if !validateCSRF(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "CSRF token validation failed, please refresh the page"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
