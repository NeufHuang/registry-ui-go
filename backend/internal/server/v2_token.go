package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/neuf/registry-ui/backend/internal/registry"
	"github.com/neuf/registry-ui/backend/internal/store"
)

// The /v2/ endpoint authenticates with the OCI token flow (Bearer), not with
// a bare Basic challenge:
//
//	GET /v2/                -> 401 + WWW-Authenticate: Bearer realm="…/v2/token"
//	GET /v2/token           -> 200 {token: …}   (with Basic creds: verified; without: anonymous)
//	GET /v2/…/manifests/…   -> 200 when sent with Authorization: Bearer <token>
//
// Both schemes alone are broken for this server, which is why the token
// endpoint exists:
//
//   - Basic challenge only: a Docker client that has no stored credentials
//     records the challenge from the ping and then refuses to send *any*
//     further request to that endpoint (moby returns ErrNoBasicAuthCredentials
//     — the "no basic auth credentials" error — before hitting the network).
//     Anonymous pull would fail even for repos that are explicitly allowed to
//     be pulled anonymously.
//   - No challenge at all (ping answered 200): the client never attaches
//     credentials, so `docker login` reports "Login Succeeded" for any
//     password, and private pulls break because the client does not know it
//     should authenticate.
//
// A Bearer challenge is satisfiable both ways: the token realm sees the
// client's credentials (so `docker login` really verifies the password) and
// also answers credential-less requests (so anonymous pull keeps working).

const (
	// v2TokenTTL bounds how long an issued registry token stays valid. A
	// client mints a fresh token on every operation (each pull/push starts
	// with a ping), so this only has to cover one operation — including a
	// long layer upload — while keeping a leaked token short-lived.
	v2TokenTTL = 24 * time.Hour
	// v2TokenService is echoed in the challenge's service parameter. It is
	// informational: verification never depends on it.
	v2TokenService = "registry-ui"
)

// v2AuthOutcome is the result of authenticating a Bearer token on /v2/*.
type v2AuthOutcome int

const (
	// v2AuthRejected means the response (401 + challenge) was already written.
	v2AuthRejected v2AuthOutcome = iota
	// v2AuthAnonymous means a valid token that carries no identity; the
	// caller applies the anonymous-pull rules.
	v2AuthAnonymous
	// v2AuthUser means a valid token and the request context now carries
	// that user; the caller applies the usual namespace authorization.
	v2AuthUser
)

// newV2TokenSecret returns a per-process signing key. Tokens are minted per
// operation and never persisted by clients, so a restart simply makes the
// next ping mint a new one.
func newV2TokenSecret() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Should never happen; a zero key still keeps tokens consistent
		// for the lifetime of this process.
		log.Printf("v2 token: CSPRNG failed, falling back to a zero signing key: %v", err)
	}
	return b
}

// mintV2Token returns "<payload>.<hmac>" where payload is the base64url of
// "userID \x00 username \x00 expiryUnix".
func (s *Server) mintV2Token(userID int64, username string, ttl time.Duration) string {
	payload := fmt.Sprintf("%d\x00%s\x00%d", userID, username, time.Now().Add(ttl).Unix())
	mac := hmac.New(sha256.New, s.v2TokenSecret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// validateV2Token checks signature and expiry, returning the username the
// token was minted for ("" for an anonymous token).
func (s *Server) validateV2Token(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, s.v2TokenSecret)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return "", false
	}
	fields := strings.SplitN(string(payload), "\x00", 3)
	if len(fields) != 3 {
		return "", false
	}
	exp, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return "", false
	}
	if time.Now().Unix() >= exp {
		return "", false
	}
	return fields[1], true
}

// v2Challenge builds the WWW-Authenticate header for /v2/*. It advertises the
// Bearer scheme only: adding a Basic challenge alongside it would make Docker
// clients that lack stored credentials abort the pull (see the file comment).
// The realm uses externalOrigin so EXTERNAL_URL can pin it behind a proxy.
func (s *Server) v2Challenge(r *http.Request) string {
	return fmt.Sprintf(`Bearer realm="%s/v2/token",service="%s"`, s.externalOrigin(r), v2TokenService)
}

// handleV2Token issues a registry token. Credentials are optional: when Basic
// credentials are presented they are always verified (a wrong password must
// never mint a token, or `docker login` would succeed with any password), and
// without credentials an anonymous token is issued.
func (s *Server) handleV2Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	var (
		userID   int64
		username string
	)
	if user, pass, ok := r.BasicAuth(); ok {
		u, err := s.store.GetUserByUsername(r.Context(), user)
		if err != nil || !u.Enabled || !store.VerifyPasswordHash(u.PasswordHash, pass) {
			_ = s.store.AddAudit(r.Context(), 0, "login", "", "", "", "error", "v2 token rejected for user="+user)
			writeJSON(w, http.StatusUnauthorized, registry.DistributionErrorResponse{
				Errors: []registry.DistributionError{{Code: "UNAUTHORIZED", Message: "invalid credentials", Detail: "username or password is incorrect"}},
			})
			return
		}
		s.maybeUpgradePassword(r.Context(), u, pass)
		userID, username = u.ID, u.Username
	}
	token := s.mintV2Token(userID, username, v2TokenTTL)
	writeJSON(w, http.StatusOK, map[string]any{
		"token":        token,
		"access_token": token,
		"expires_in":   int(v2TokenTTL.Seconds()),
		"issued_at":    time.Now().UTC().Format(time.RFC3339),
	})
}

// authenticateV2Bearer validates an Authorization: Bearer token on a /v2/*
// request. On v2AuthRejected the 401 response has been written.
func (s *Server) authenticateV2Bearer(w http.ResponseWriter, r *http.Request, token string) v2AuthOutcome {
	// API tokens (ru_…) are explicit bearer credentials, so they authenticate
	// registry traffic too — otherwise the documented "use a Bearer token for
	// any API" silently excluded /v2/*.
	if strings.HasPrefix(token, "ru_") {
		if s.checkAPITokenAuth(w, r) {
			return v2AuthUser
		}
		s.challenge(w, r)
		return v2AuthRejected
	}
	username, ok := s.validateV2Token(token)
	if !ok {
		s.challenge(w, r)
		return v2AuthRejected
	}
	if username == "" {
		return v2AuthAnonymous
	}
	u, err := s.store.GetUserByUsername(r.Context(), username)
	if err != nil || !u.Enabled {
		// The account was deleted or disabled after the token was minted.
		s.challenge(w, r)
		return v2AuthRejected
	}
	*r = *r.WithContext(context.WithValue(r.Context(), ctxUserKey{}, u))
	return v2AuthUser
}

// anonymousV2Pull reports whether a request without any identity may be
// served: GET/HEAD on the manifest/blob endpoints of a repository whose
// anonymous_pull flag is enabled.
func (s *Server) anonymousV2Pull(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	repoPath := v2PullResourceRepoPath(r.URL.Path)
	return repoPath != "" && s.isAnonymousPullAllowed(r.Context(), repoPath)
}
