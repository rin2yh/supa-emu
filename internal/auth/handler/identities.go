package handler

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
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
// authenticate the caller, then hand back a provider authorize URL (200 with
// { "url": ... } when skip_http_redirect is set, otherwise a 302 redirect).

// providerAuthorizeEndpoints maps a supported external provider to its real
// OAuth authorize endpoint. The emulator does not drive the flow, so the base is
// only used to make the returned URL recognizable (a real GitHub authorize URL
// for provider=github); unknown providers fall back to a local dummy endpoint.
var providerAuthorizeEndpoints = map[string]string{
	"github":    "https://github.com/login/oauth/authorize",
	"google":    "https://accounts.google.com/o/oauth2/v2/auth",
	"gitlab":    "https://gitlab.com/oauth/authorize",
	"bitbucket": "https://bitbucket.org/site/oauth2/authorize",
	"azure":     "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
}

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
		c.ErrorCode(http.StatusBadRequest, "validation_failed", "provider is required")
		return
	}

	authorizeURL := buildAuthorizeURL(provider, c.Query("redirect_to"),
		c.Query("code_challenge"), c.Query("code_challenge_method"))

	// supabase-js sends skip_http_redirect=true when skipBrowserRedirect is set so
	// it can perform the navigation itself; GoTrue then answers 200 with the URL in
	// the body instead of a 302. Any other value keeps the browser-redirect (302).
	if isTruthy(c.Query("skip_http_redirect")) {
		c.JSON(http.StatusOK, map[string]any{"url": authorizeURL})
		return
	}

	c.Header().Set("Location", authorizeURL)
	c.JSON(http.StatusFound, nil)
}

// buildAuthorizeURL constructs the provider authorize URL echoed back to the
// client. The emulator does not complete the OAuth exchange, so a fresh opaque
// state is minted per call and the PKCE parameters are passed through verbatim;
// the values only need to be well-formed, not honored.
func buildAuthorizeURL(provider, redirectTo, codeChallenge, codeChallengeMethod string) string {
	base, ok := providerAuthorizeEndpoints[provider]
	if !ok {
		// Unknown providers still get a syntactically valid, provider-scoped URL so
		// clients can assert on it without the emulator hard-coding every provider.
		base = "http://127.0.0.1:54321/auth/v1/authorize/" + url.PathEscape(provider)
	}

	q := url.Values{}
	q.Set("client_id", "supa-emu")
	q.Set("response_type", "code")
	q.Set("provider", provider)
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
	return base + "?" + q.Encode()
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
