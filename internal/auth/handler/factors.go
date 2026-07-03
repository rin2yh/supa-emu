package handler

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/rin2yh/supa-emu/internal/auth/store"
)

// passkey (WebAuthn) MFA を GoTrue の /auth/v1/factors 系エンドポイント互換で提供する。
//
// エミュレータのため WebAuthn の attestation / assertion 署名は検証しない。credential は
// そのまま受理し、フロー（enroll → challenge → verify → unenroll）と AAL 昇格の HTTP 契約を
// supabase-js の auth.mfa.* / getAuthenticatorAssuranceLevel と揃えることを目的とする。

// requireUser は Bearer を検証し認証済み user と claims を返す。失敗時はエラー応答済みで ok=false。
// GetUser と同じ error_code 分類（no_authorization / bad_jwt / session_not_found）を共有する。
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

// EnrollFactor は passkey を登録する（POST /auth/v1/factors）。
// factor は unverified で作られ、WebAuthn credential creation options を添えて返す。
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
	// 本エミュレータは passkey (webauthn) のみ実装する。空指定は webauthn とみなす。
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
			"credential_creation_options": c.credentialCreationOptions(u, store.Challenge{Value: base64.RawURLEncoding.EncodeToString([]byte(f.ID))}),
		},
	})
}

// ChallengeFactor は factor に対する検証チャレンジを発行する
// （POST /auth/v1/factors/{factorId}/challenge）。unverified なら登録用の creation options、
// verified なら認証用の request options を添えて返す。
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
		webAuthn["credential_request_options"] = c.credentialRequestOptions(*ch)
	} else {
		webAuthn["credential_creation_options"] = c.credentialCreationOptions(u, *ch)
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
	// WebAuthn の登録/認証応答。エミュレータは署名検証しないため任意の JSON を受理する。
	CredentialResponse any `json:"credential_response"`
}

// VerifyFactor は challenge を消費し passkey を検証する
// （POST /auth/v1/factors/{factorId}/verify）。成功で factor を verified に昇格させ、
// 現在の session を aal2 へ引き上げた新しい access_token / refresh_token を返す。
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

	// credential_response は emulator では検証しないが、あれば識別子として記録しておく。
	credential := ""
	if req.CredentialResponse != nil {
		credential = base64.RawURLEncoding.EncodeToString([]byte(req.ChallengeID))
	}
	if _, err := c.store.VerifyFactor(factorID, credential); err != nil {
		if errors.Is(err, store.ErrFactorNotFound) {
			c.ErrorCode(http.StatusNotFound, "mfa_factor_not_found", "MFA factor not found")
			return
		}
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}

	// 現在の session を aal2 へ昇格し、同一 session で refresh_token を rotate した新ペアを返す。
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
	// factor が verified になった状態を反映するため user を読み直す。
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

// UnenrollFactor は passkey を削除する（DELETE /auth/v1/factors/{factorId}）。
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

// credentialCreationOptions は WebAuthn 登録 ceremony 用の PublicKeyCredentialCreationOptions
// 相当の JSON を組み立てる。エミュレータでは検証されないが構造的に妥当な形を返す。
func (c *Context) credentialCreationOptions(u *store.User, ch store.Challenge) map[string]any {
	return map[string]any{
		"publicKey": map[string]any{
			"challenge": ch.Value,
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

// credentialRequestOptions は WebAuthn 認証 ceremony 用の PublicKeyCredentialRequestOptions
// 相当の JSON を組み立てる。
func (c *Context) credentialRequestOptions(ch store.Challenge) map[string]any {
	return map[string]any{
		"publicKey": map[string]any{
			"challenge":        ch.Value,
			"rpId":             c.webauthn.RPID,
			"timeout":          60000,
			"userVerification": "preferred",
		},
	}
}
