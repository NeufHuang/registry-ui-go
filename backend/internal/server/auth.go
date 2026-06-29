package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
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
		return ""
	}
	entry, ok := v.(sessionEntry)
	if !ok {
		s.sessionStore.Delete(cookie.Value)
		return ""
	}
	if time.Now().After(entry.expiresAt) {
		s.sessionStore.Delete(cookie.Value)
		return ""
	}
	return entry.username
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

		// Allow login page and static assets without auth
		if r.URL.Path == "/login" || r.URL.Path == "/login.html" || r.URL.Path == "/api/login" ||
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
				// Allow anonymous pull for repos with anonymous_pull enabled
				if (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.Contains(r.URL.Path, "/manifests/") {
					parts := strings.Split(r.URL.Path, "/manifests/")
					if len(parts) == 2 {
						repoPath := strings.TrimPrefix(parts[0], "/v2/")
						if s.isAnonymousPullAllowed(r.Context(), repoPath) {
							next.ServeHTTP(w, r)
							return
						}
					}
				}
				if !s.requireUIAuth(w, r) {
					return
				}
				// After auth, enforce namespace authorization (skip /v2/ root and /v2/_catalog)
				if repoPath := extractV2RepoPath(r.URL.Path); repoPath != "" {
					if !s.userCanAccessRepo(r, repoPath) {
						writeJSON(w, http.StatusForbidden, registry.ErrorResponse{Error: "forbidden", Details: "no permission to access this repository"})
						return
					}
				}
			case "registry", "proxy", "off":
				// Leave Docker Registry API auth behavior to the configured registry/proxy.
			default:
				if !s.requireUIAuth(w, r) {
					return
				}
			}
			next.ServeHTTP(w, r)
			return
		}

		// Check API token first (Bearer token)
		if s.checkAPITokenAuth(w, r) {
			next.ServeHTTP(w, r)
			return
		}

		// All other paths require auth
		if !s.requireUIAuth(w, r) {
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	// Docker CLI expects 401 + WWW-Authenticate for /v2/ paths
	if strings.HasPrefix(r.URL.Path, "/v2/") {
		w.Header().Set("WWW-Authenticate", `Basic realm="Registry UI"`)
		writeJSON(w, http.StatusUnauthorized, registry.ErrorResponse{Error: "unauthorized"})
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
		if !validateCSRF(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "CSRF token validation failed, please refresh the page"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
