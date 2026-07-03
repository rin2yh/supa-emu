package handler

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/rin2yh/supa-emu/internal/auth/store"
)

// Passkey (WebAuthn) MFA, served over GoTrue's /auth/v1/factors endpoints.
//
// Because this is an emulator, WebAuthn attestation / assertion signatures are
// not verified: the credential is accepted as-is. The goal is to match the HTTP
// contract of the flow (enroll -> challenge -> verify -> unenroll) and the AAL
// upgrade with supabase-js auth.mfa.* / getAuthenticatorAssuranceLevel.

// requireUser verifies the Bearer token and returns the authenticated user and
// claims. On failure it has already written the error response and returns
// ok=false. It shares GetUser's error_code classification
// (no_authorization / bad_jwt / session_not_found).
func requireUser(c *Context) (*store.User, *Claims, bool) {
	token := c.Bearer()
	if token == "" {
		c.ErrorCode(http.StatusUnauthorized, "no_authorization",
			"No Authorization header included in request")
		return nil, nil, false
	}
	claims, err := c.tokens.Verify(token)
	if err != nil {
		c.ErrorCode(http.StatusUnauthorized, "bad_jwt", "invalid JWT: "+err.Error())
		return nil, nil, false
	}
	u, ok := c.store.FindUserByID(claims.Subject)
	if !ok {
		c.ErrorCode(http.StatusUnauthorized, "session_not_found",
			"AuthSessionMissingError: Auth session missing!")
		return nil, nil, false
	}
	return u, claims, true
}

type enrollFactorRequest struct {
	FactorType   string `json:"factor_type"`
	FriendlyName string `json:"friendly_name"`
}

// EnrollFactor registers a passkey (POST /auth/v1/factors).
// The factor is created unverified and returned with WebAuthn credential
// creation options.
func EnrollFactor(c *Context) {
	u, _, ok := requireUser(c)
	if !ok {
		return
	}
	var req enrollFactorRequest
	if err := c.ReadJSON(&req); err != nil {
		c.Error(http.StatusBadRequest, "invalid request body")
		return
	}
	// This emulator only implements passkey (webauthn); treat an empty value as webauthn.
	factorType := strings.TrimSpace(req.FactorType)
	if factorType == "" {
		factorType = store.FactorTypeWebAuthn
	}
	if factorType != store.FactorTypeWebAuthn {
		c.ErrorCode(http.StatusUnprocessableEntity, "mfa_factor_type_not_supported",
			"Only the webauthn (passkey) factor type is supported by this emulator")
		return
	}

	f, err := c.store.EnrollFactor(u.ID, store.FactorTypeWebAuthn, strings.TrimSpace(req.FriendlyName))
	if err != nil {
		switch {
		case errors.Is(err, store.ErrFactorNameConflict):
			c.ErrorCode(http.StatusUnprocessableEntity, "mfa_factor_name_conflict",
				"A factor with the friendly name "+req.FriendlyName+" for this user already exists")
		case errors.Is(err, store.ErrUserNotFound):
			c.ErrorCode(http.StatusUnauthorized, "session_not_found",
				"AuthSessionMissingError: Auth session missing!")
		default:
			c.Error(http.StatusInternalServerError, err.Error())
		}
		return
	}

	c.JSON(http.StatusOK, map[string]any{
		"id":            f.ID,
		"type":          f.FactorType,
		"friendly_name": f.FriendlyName,
		"web_authn": map[string]any{
			"credential_creation_options": c.credentialCreationOptions(u, base64.RawURLEncoding.EncodeToString([]byte(f.ID))),
		},
	})
}

// ChallengeFactor issues a verification challenge for a factor
// (POST /auth/v1/factors/{factorId}/challenge). It returns creation options for
// registration when the factor is unverified, and request options for
// authentication when it is verified.
func ChallengeFactor(c *Context) {
	u, _, ok := requireUser(c)
	if !ok {
		return
	}
	factorID := c.Path("factorId")
	f, ok := c.store.GetFactor(factorID)
	if !ok || f.UserID != u.ID {
		c.ErrorCode(http.StatusNotFound, "mfa_factor_not_found", "MFA factor not found")
		return
	}

	ch, err := c.store.CreateChallenge(factorID)
	if err != nil {
		if errors.Is(err, store.ErrFactorNotFound) {
			c.ErrorCode(http.StatusNotFound, "mfa_factor_not_found", "MFA factor not found")
			return
		}
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}

	webAuthn := map[string]any{}
	if f.Status == store.FactorStatusVerified {
		webAuthn["credential_request_options"] = c.credentialRequestOptions(ch.Value)
	} else {
		webAuthn["credential_creation_options"] = c.credentialCreationOptions(u, ch.Value)
	}
	c.JSON(http.StatusOK, map[string]any{
		"id":         ch.ID,
		"type":       f.FactorType,
		"expires_at": ch.ExpiresAt.Unix(),
		"web_authn":  webAuthn,
	})
}

type verifyFactorRequest struct {
	ChallengeID string `json:"challenge_id"`
	// The WebAuthn registration/authentication response. The emulator does not
	// verify signatures, so any JSON is accepted.
	CredentialResponse any `json:"credential_response"`
}

// VerifyFactor consumes a challenge and verifies a passkey
// (POST /auth/v1/factors/{factorId}/verify). On success it promotes the factor
// to verified and returns a new access_token / refresh_token with the current
// session upgraded to aal2.
func VerifyFactor(c *Context) {
	u, claims, ok := requireUser(c)
	if !ok {
		return
	}
	factorID := c.Path("factorId")
	f, ok := c.store.GetFactor(factorID)
	if !ok || f.UserID != u.ID {
		c.ErrorCode(http.StatusNotFound, "mfa_factor_not_found", "MFA factor not found")
		return
	}

	var req verifyFactorRequest
	if err := c.ReadJSON(&req); err != nil {
		c.Error(http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ChallengeID == "" {
		c.ErrorCode(http.StatusUnprocessableEntity, "validation_failed", "challenge_id is required")
		return
	}

	if _, err := c.store.ConsumeChallenge(factorID, req.ChallengeID); err != nil {
		switch {
		case errors.Is(err, store.ErrChallengeExpired):
			c.ErrorCode(http.StatusUnprocessableEntity, "mfa_challenge_expired",
				"MFA challenge has expired, verify against another challenge or create a new challenge.")
		default:
			c.ErrorCode(http.StatusNotFound, "mfa_challenge_not_found", "MFA challenge not found")
		}
		return
	}

	// The emulator does not verify credential_response signatures, so accept it and proceed.
	if _, err := c.store.VerifyFactor(factorID); err != nil {
		if errors.Is(err, store.ErrFactorNotFound) {
			c.ErrorCode(http.StatusNotFound, "mfa_factor_not_found", "MFA factor not found")
			return
		}
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}

	// Upgrade the current session to aal2 and return a new pair by rotating the
	// refresh_token within the same session.
	if claims.SessionID == "" {
		c.ErrorCode(http.StatusUnauthorized, "session_not_found",
			"AuthSessionMissingError: Auth session missing!")
		return
	}
	if _, upOK := c.store.UpgradeSessionAAL(claims.SessionID, store.FactorTypeWebAuthn); !upOK {
		c.ErrorCode(http.StatusUnauthorized, "session_not_found",
			"AuthSessionMissingError: Auth session missing!")
		return
	}
	rt, err := c.store.IssueRefreshToken(u.ID, claims.SessionID)
	if err != nil {
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}
	// Re-read the user so the response reflects the now-verified factor.
	fresh, ok := c.store.FindUserByID(u.ID)
	if !ok {
		c.ErrorCode(http.StatusUnauthorized, "session_not_found",
			"AuthSessionMissingError: Auth session missing!")
		return
	}
	tr, err := c.tokens.Build(fresh, claims.SessionID, rt.Token)
	if err != nil {
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, tr)
}

// UnenrollFactor deletes a passkey (DELETE /auth/v1/factors/{factorId}).
func UnenrollFactor(c *Context) {
	u, _, ok := requireUser(c)
	if !ok {
		return
	}
	factorID := c.Path("factorId")
	if err := c.store.DeleteFactor(u.ID, factorID); err != nil {
		c.ErrorCode(http.StatusNotFound, "mfa_factor_not_found", "MFA factor not found")
		return
	}
	c.JSON(http.StatusOK, map[string]any{"id": factorID})
}

// credentialCreationOptions builds JSON equivalent to a WebAuthn registration
// ceremony's PublicKeyCredentialCreationOptions. It is not verified by the
// emulator but is returned in a structurally valid shape.
func (c *Context) credentialCreationOptions(u *store.User, challenge string) map[string]any {
	return map[string]any{
		"publicKey": map[string]any{
			"challenge": challenge,
			"rp": map[string]any{
				"id":   c.webauthn.RPID,
				"name": c.webauthn.RPName,
			},
			"user": map[string]any{
				"id":          base64.RawURLEncoding.EncodeToString([]byte(u.ID)),
				"name":        u.Email,
				"displayName": u.Email,
			},
			"pubKeyCredParams": []map[string]any{
				{"type": "public-key", "alg": -7},
				{"type": "public-key", "alg": -257},
			},
			"timeout":     60000,
			"attestation": "none",
			"authenticatorSelection": map[string]any{
				"residentKey":      "required",
				"userVerification": "preferred",
			},
		},
	}
}

// credentialRequestOptions builds JSON equivalent to a WebAuthn authentication
// ceremony's PublicKeyCredentialRequestOptions.
func (c *Context) credentialRequestOptions(challenge string) map[string]any {
	return map[string]any{
		"publicKey": map[string]any{
			"challenge":        challenge,
			"rpId":             c.webauthn.RPID,
			"timeout":          60000,
			"userVerification": "preferred",
		},
	}
}
