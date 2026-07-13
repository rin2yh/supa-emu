package handler

import (
	"net/http"
	"net/url"
	"strings"
)

// OAuth sign-in round trip, emulated end to end inside the process so an
// integration test can complete signInWithOAuth -> callback ->
// exchangeCodeForSession without ever reaching the real provider.
//
// GET /auth/v1/authorize is the entry point (the URL signInWithOAuth builds and
// the local target LinkIdentityAuthorize hands back). Instead of bouncing the
// browser to github.com, the emulator fabricates a provider identity, mints a
// single-use authorization code, and redirects straight to redirect_to?code=...
// — the app's callback. POST /auth/v1/token?grant_type=pkce then swaps that code
// for a session (exchangeCodeForSession). PKCE is not verified: any code_verifier
// is accepted, matching the passkey / MFA emulators which likewise skip signature
// checks.

// Authorize starts (and, in the emulator, immediately completes) an OAuth
// sign-in (GET /auth/v1/authorize). It requires provider and redirect_to,
// fabricates a user carrying that provider's identity, and redirects to the
// callback with a fresh authorization code.
//
// Query parameters (as issued by signInWithOAuth):
//   - provider       external provider key, e.g. "github" (required)
//   - redirect_to    the app callback the code is delivered to (required)
//   - code_challenge PKCE challenge, retained but not verified
//   - login_hint     optional email; when set the user is found-or-created by it
//     so a test can drive a deterministic OAuth account
func Authorize(c *Context) {
	provider := strings.TrimSpace(c.Query("provider"))
	if provider == "" {
		c.ErrorCode(http.StatusUnprocessableEntity, "validation_failed", "provider is required")
		return
	}
	redirectTo := strings.TrimSpace(c.Query("redirect_to"))
	if redirectTo == "" {
		c.ErrorCode(http.StatusUnprocessableEntity, "validation_failed", "redirect_to is required")
		return
	}
	target, err := url.Parse(redirectTo)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") {
		c.ErrorCode(http.StatusBadRequest, "validation_failed", "redirect_to is not a valid URL")
		return
	}

	u, err := c.store.CreateOAuthUser(provider, c.Query("login_hint"))
	if err != nil {
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}
	ac, err := c.store.CreateAuthCode(u.ID)
	if err != nil {
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}

	// Deliver the code on the callback query, preserving any params the caller
	// already put on redirect_to (GoTrue appends, it does not replace).
	q := target.Query()
	q.Set("code", ac.Code)
	target.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, target.String())
}

type pkceGrantRequest struct {
	AuthCode     string `json:"auth_code"`
	CodeVerifier string `json:"code_verifier"`
}

// tokenPKCE exchanges an authorization code for a session
// (POST /auth/v1/token?grant_type=pkce, supabase-js exchangeCodeForSession). The
// code_verifier is accepted but not checked. On success it issues a session whose
// amr records the "oauth" method and returns the standard token response.
func tokenPKCE(c *Context) {
	var req pkceGrantRequest
	if err := c.ReadJSON(&req); err != nil {
		c.OAuth(http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	if strings.TrimSpace(req.AuthCode) == "" {
		c.OAuth(http.StatusBadRequest, "invalid_request", "auth_code is required")
		return
	}

	ac, err := c.store.ConsumeAuthCode(req.AuthCode)
	if err != nil {
		c.OAuth(http.StatusBadRequest, "invalid_grant", "invalid flow state, no valid flow state found")
		return
	}

	// Stamp last_sign_in_at like a password/passkey login. A code whose user has
	// since been deleted makes this fail, collapsing to the same client-visible
	// "flow can no longer be completed" as a missing code.
	fresh, ok := c.store.UpdateLastSignIn(ac.UserID)
	if !ok {
		c.OAuth(http.StatusBadRequest, "invalid_grant", "invalid flow state, no valid flow state found")
		return
	}

	tr, err := c.tokens.IssueWithMethod(fresh, "oauth")
	if err != nil {
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, tr)
}
