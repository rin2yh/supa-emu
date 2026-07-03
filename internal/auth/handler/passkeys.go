package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/rin2yh/supa-emu/internal/auth/store"
)

// Passwordless passkeys, served over GoTrue's /auth/v1/passkeys/* endpoints
// (supabase-js auth.passkey.*). Unlike the /auth/v1/factors MFA flow — which
// adds a second factor to an existing session and promotes it to aal2 — a
// passkey here IS the login: authentication issues a brand new session from an
// unauthenticated request.
//
// As with the MFA emulator, WebAuthn signatures are not verified. Authentication
// instead matches the presented credential id against a credential persisted at
// registration, so a client must register before it can authenticate.

// webauthnCredential is the subset of the browser's serialized WebAuthn
// credential the emulator needs: its credential id.
type webauthnCredential struct {
	ID string `json:"id"`
}

type passkeyRegistrationOptionsRequest struct {
	FriendlyName string `json:"friendly_name"`
}

// PasskeyRegistrationOptions starts a registration ceremony for the logged-in
// user (POST /auth/v1/passkeys/registration/options). Requires a Bearer token.
func PasskeyRegistrationOptions(c *Context) {
	u, _, ok := requireUser(c)
	if !ok {
		return
	}
	var req passkeyRegistrationOptionsRequest
	_ = c.ReadJSON(&req) // body is optional (friendly_name only)

	ch, err := c.store.CreatePasskeyChallenge(u.ID, store.PasskeyPurposeRegistration, strings.TrimSpace(req.FriendlyName))
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			c.ErrorCode(http.StatusUnauthorized, "session_not_found",
				"AuthSessionMissingError: Auth session missing!")
			return
		}
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]any{
		"challenge_id": ch.ID,
		"options":      c.passkeyCreationOptions(u, ch.Value, c.store.ListUserPasskeys(u.ID)),
		"expires_at":   ch.ExpiresAt.Unix(),
	})
}

type passkeyRegistrationVerifyRequest struct {
	ChallengeID  string             `json:"challenge_id"`
	Credential   webauthnCredential `json:"credential"`
	FriendlyName string             `json:"friendly_name"`
}

// PasskeyRegistrationVerify persists the newly created credential
// (POST /auth/v1/passkeys/registration/verify). Requires a Bearer token.
func PasskeyRegistrationVerify(c *Context) {
	u, _, ok := requireUser(c)
	if !ok {
		return
	}
	var req passkeyRegistrationVerifyRequest
	if err := c.ReadJSON(&req); err != nil {
		c.Error(http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ChallengeID == "" {
		c.ErrorCode(http.StatusUnprocessableEntity, "validation_failed", "challenge_id is required")
		return
	}
	credID := req.Credential.ID
	if credID == "" {
		c.ErrorCode(http.StatusUnprocessableEntity, "validation_failed", "credential is required")
		return
	}

	ch, err := c.store.ConsumePasskeyChallenge(req.ChallengeID, store.PasskeyPurposeRegistration)
	if err != nil {
		writePasskeyChallengeError(c, err)
		return
	}
	// The registration challenge is bound to the user that requested it.
	if ch.UserID != u.ID {
		c.ErrorCode(http.StatusNotFound, "passkey_challenge_not_found", "passkey challenge not found")
		return
	}

	friendly := strings.TrimSpace(req.FriendlyName)
	if friendly == "" {
		friendly = ch.FriendlyName
	}
	pk, err := c.store.AddPasskey(u.ID, friendly, credID)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrPasskeyExists):
			c.ErrorCode(http.StatusUnprocessableEntity, "passkey_already_exists",
				"this passkey is already registered")
		case errors.Is(err, store.ErrUserNotFound):
			c.ErrorCode(http.StatusUnauthorized, "session_not_found",
				"AuthSessionMissingError: Auth session missing!")
		default:
			c.Error(http.StatusInternalServerError, err.Error())
		}
		return
	}

	body := map[string]any{
		"id":         pk.ID,
		"created_at": pk.CreatedAt,
	}
	if pk.FriendlyName != "" {
		body["friendly_name"] = pk.FriendlyName
	}
	c.JSON(http.StatusOK, body)
}

// PasskeyAuthenticationOptions starts a discoverable authentication ceremony
// (POST /auth/v1/passkeys/authentication/options). No Bearer token required —
// this is the entry point for a passwordless login.
func PasskeyAuthenticationOptions(c *Context) {
	ch, err := c.store.CreatePasskeyChallenge("", store.PasskeyPurposeAuthentication, "")
	if err != nil {
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]any{
		"challenge_id": ch.ID,
		"options":      c.passkeyRequestOptions(ch.Value),
		"expires_at":   ch.ExpiresAt.Unix(),
	})
}

type passkeyAuthenticationVerifyRequest struct {
	ChallengeID string             `json:"challenge_id"`
	Credential  webauthnCredential `json:"credential"`
}

// PasskeyAuthenticationVerify resolves the presented credential to its owner and
// issues a brand new session (POST /auth/v1/passkeys/authentication/verify).
// No Bearer token required; on success it returns {session, user}.
func PasskeyAuthenticationVerify(c *Context) {
	var req passkeyAuthenticationVerifyRequest
	if err := c.ReadJSON(&req); err != nil {
		c.Error(http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ChallengeID == "" {
		c.ErrorCode(http.StatusUnprocessableEntity, "validation_failed", "challenge_id is required")
		return
	}
	credID := req.Credential.ID
	if credID == "" {
		c.ErrorCode(http.StatusUnprocessableEntity, "validation_failed", "credential is required")
		return
	}

	if _, err := c.store.ConsumePasskeyChallenge(req.ChallengeID, store.PasskeyPurposeAuthentication); err != nil {
		writePasskeyChallengeError(c, err)
		return
	}
	pk, ok := c.store.FindPasskeyByCredentialID(credID)
	if !ok {
		c.ErrorCode(http.StatusUnauthorized, "invalid_credentials",
			"No passkey found for the provided credential")
		return
	}
	u, ok := c.store.FindUserByID(pk.UserID)
	if !ok {
		c.ErrorCode(http.StatusUnauthorized, "invalid_credentials",
			"No passkey found for the provided credential")
		return
	}

	// A passkey login is single-factor primary auth: aal1 with amr=[webauthn],
	// signed with the same key as password login.
	tr, err := c.tokens.IssueWithMethod(u, store.FactorTypeWebAuthn)
	if err != nil {
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]any{
		"session": tr,
		"user":    u,
	})
}

// writePasskeyChallengeError maps a ConsumePasskeyChallenge error to its response.
func writePasskeyChallengeError(c *Context, err error) {
	if errors.Is(err, store.ErrPasskeyChallengeExpired) {
		c.ErrorCode(http.StatusUnprocessableEntity, "passkey_challenge_expired",
			"passkey challenge has expired, request a new challenge")
		return
	}
	c.ErrorCode(http.StatusNotFound, "passkey_challenge_not_found", "passkey challenge not found")
}

// passkeyCreationOptions builds the PublicKeyCredentialCreationOptionsJSON handed
// to the browser's registration ceremony (residentKey required, so the
// credential is discoverable at authentication time).
func (c *Context) passkeyCreationOptions(u *store.User, challenge string, exclude []store.Passkey) map[string]any {
	excludeCreds := make([]map[string]any, 0, len(exclude))
	for _, pk := range exclude {
		excludeCreds = append(excludeCreds, map[string]any{"id": pk.CredentialID, "type": "public-key"})
	}
	return map[string]any{
		"challenge":        challenge,
		"rp":               c.webauthnRP(),
		"user":             webauthnUser(u),
		"pubKeyCredParams": webauthnPubKeyCredParams(),
		"timeout":          60000,
		"attestation":      "none",
		"authenticatorSelection": map[string]any{
			"residentKey":        "required",
			"requireResidentKey": true,
			"userVerification":   "required",
		},
		"excludeCredentials": excludeCreds,
	}
}

// passkeyRequestOptions builds the PublicKeyCredentialRequestOptionsJSON for a
// discoverable authentication ceremony (empty allowCredentials).
func (c *Context) passkeyRequestOptions(challenge string) map[string]any {
	return map[string]any{
		"challenge":        challenge,
		"rpId":             c.webauthn.RPID,
		"timeout":          60000,
		"userVerification": "required",
		"allowCredentials": []map[string]any{},
	}
}
