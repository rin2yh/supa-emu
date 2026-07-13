package handler

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/rin2yh/supa-emu/internal/auth/store"
)

// Manual identity linking, served over GoTrue's
// GET /auth/v1/user/identities/authorize endpoint (supabase-js
// auth.linkIdentity({ provider, options: { redirectTo, skipBrowserRedirect } })).
//
// linkIdentity begins an OAuth "link" flow: an already-signed-in user is sent to
// an external provider (e.g. GitHub) to attach that provider's identity to the
// existing account. supabase-js issues this request with the PKCE parameters
// (code_challenge / code_challenge_method) and, when skipBrowserRedirect is set,
// skip_http_redirect=true so the browser can be redirected manually.
//
// As with the passkey / MFA emulators, the emulator does not perform the real
// OAuth round trip or verify PKCE. It only reproduces GoTrue's HTTP contract:
// authenticate the caller, then hand back an authorize URL (200 with
// { "url": ... } when skip_http_redirect is set, otherwise a 302 redirect).
//
// The URL points at the emulator's own local /auth/v1/authorize entry point
// (the same one signInWithOAuth uses) rather than the real provider, so a link
// flow stays local and consistent with login instead of bouncing an E2E run out
// to github.com. The callback that would actually attach the identity is out of
// scope; only the authorize (link start) contract is emulated here.

// LinkIdentityAuthorize starts a manual identity-link OAuth flow for the
// authenticated user (GET /auth/v1/user/identities/authorize). Requires a Bearer
// token; the 401 classification (no_authorization / bad_jwt / session_not_found)
// is shared with GetUser via requireUser.
//
// Query parameters (as issued by supabase-js linkIdentity):
//   - provider              external provider key, e.g. "github" (required)
//   - redirect_to           post-callback destination echoed into the URL
//   - code_challenge        PKCE challenge, passed through unverified
//   - code_challenge_method PKCE method (s256), passed through unverified
//   - skip_http_redirect    when truthy, return 200 { "url": ... } instead of 302
func LinkIdentityAuthorize(c *Context) {
	if _, _, ok := requireUser(c); !ok {
		return
	}

	provider := strings.TrimSpace(c.Query("provider"))
	if provider == "" {
		c.ErrorCode(http.StatusUnprocessableEntity, "validation_failed", "provider is required")
		return
	}

	authorizeURL := buildAuthorizeURL(c.tokens.issuer, provider, c.Query("redirect_to"),
		c.Query("code_challenge"), c.Query("code_challenge_method"))

	// supabase-js sends skip_http_redirect=true when skipBrowserRedirect is set so
	// it can perform the navigation itself; GoTrue then answers 200 with the URL in
	// the body instead of a 302. Any other value keeps the browser-redirect (302).
	if isTruthy(c.Query("skip_http_redirect")) {
		c.JSON(http.StatusOK, map[string]any{"url": authorizeURL})
		return
	}
	c.Redirect(http.StatusFound, authorizeURL)
}

// UnlinkIdentity removes a linked provider identity from the authenticated user
// (DELETE /auth/v1/user/identities/{identity_id}, supabase-js
// unlinkIdentity(identity)). supabase-js targets the route with
// identity.identity_id, so that is the value matched against the user's
// identities. Requires a Bearer token; the 401 classification is shared with
// GetUser via requireUser.
//
// GoTrue refuses to remove a user's only identity (a user must retain at least
// one), reported here as 422 single_identity_not_deletable. A path id that does
// not match any of the user's identities returns 404 identity_not_found. On
// success it returns an empty 204, matching GoTrue.
func UnlinkIdentity(c *Context) {
	u, _, ok := requireUser(c)
	if !ok {
		return
	}
	identityID := strings.TrimSpace(c.Path("identity_id"))
	if identityID == "" {
		c.ErrorCode(http.StatusUnprocessableEntity, "validation_failed", "identity_id is required")
		return
	}

	if _, err := c.store.RemoveIdentity(u.ID, identityID); err != nil {
		switch {
		case errors.Is(err, store.ErrLastIdentity):
			c.ErrorCode(http.StatusUnprocessableEntity, "single_identity_not_deletable",
				"User must have at least 1 identity after unlinking")
		case errors.Is(err, store.ErrIdentityNotFound):
			c.ErrorCode(http.StatusNotFound, "identity_not_found", "Identity not found")
		case errors.Is(err, store.ErrUserNotFound):
			c.ErrorCode(http.StatusUnauthorized, "session_not_found",
				"AuthSessionMissingError: Auth session missing!")
		default:
			c.Error(http.StatusInternalServerError, err.Error())
		}
		return
	}
	c.NoContent()
}

// buildAuthorizeURL constructs the local authorize URL echoed back to the client:
// the emulator's own /auth/v1/authorize (derived from the configured issuer, so
// it tracks -addr / -jwt-issuer) with the provider carried as a query parameter,
// matching signInWithOAuth. Every provider resolves to the same local endpoint;
// the emulator does not complete the OAuth exchange, so a fresh opaque state is
// minted per call and the PKCE parameters are passed through verbatim — the
// values only need to be well-formed, not honored.
func buildAuthorizeURL(issuer, provider, redirectTo, codeChallenge, codeChallengeMethod string) string {
	q := url.Values{}
	q.Set("provider", provider)
	q.Set("client_id", "supa-emu")
	q.Set("response_type", "code")
	q.Set("state", uuid.NewString())
	if redirectTo != "" {
		q.Set("redirect_to", redirectTo)
	}
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
	}
	if codeChallengeMethod != "" {
		q.Set("code_challenge_method", codeChallengeMethod)
	}
	// TrimSuffix guards against a configured issuer with a trailing slash, which
	// would otherwise yield "…//authorize".
	return strings.TrimSuffix(issuer, "/") + "/authorize?" + q.Encode()
}

// isTruthy reports whether a query flag should be treated as set. supabase-js
// sends the literal "true", but GoTrue accepts the usual truthy spellings, so the
// emulator is lenient to match.
func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}
