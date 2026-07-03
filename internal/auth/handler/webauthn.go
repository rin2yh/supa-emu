package handler

import (
	"encoding/base64"

	"github.com/rin2yh/supa-emu/internal/auth/store"
)

// Shared PublicKeyCredential option fragments, used by both the passwordless
// passkey (passkeys.go) and MFA factor (factors.go) ceremonies. The two full
// option builders differ (wrapping, userVerification, residentKey), but these
// inner sub-objects are identical, so keeping them here avoids drift.

func (c *Context) webauthnRP() map[string]any {
	return map[string]any{"id": c.webauthn.RPID, "name": c.webauthn.RPName}
}

func webauthnUser(u *store.User) map[string]any {
	return map[string]any{
		"id":          base64.RawURLEncoding.EncodeToString([]byte(u.ID)),
		"name":        u.Email,
		"displayName": u.Email,
	}
}

func webauthnPubKeyCredParams() []map[string]any {
	return []map[string]any{
		{"type": "public-key", "alg": -7},
		{"type": "public-key", "alg": -257},
	}
}
