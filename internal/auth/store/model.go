package store

import "time"

type User struct {
	ID               string         `json:"id"`
	Email            string         `json:"email"`
	Aud              string         `json:"aud"`
	Role             string         `json:"role"`
	EmailConfirmedAt *time.Time     `json:"email_confirmed_at,omitempty"`
	Phone            string         `json:"phone,omitempty"`
	ConfirmedAt      *time.Time     `json:"confirmed_at,omitempty"`
	LastSignInAt     *time.Time     `json:"last_sign_in_at,omitempty"`
	AppMetadata      map[string]any `json:"app_metadata"`
	UserMetadata     map[string]any `json:"user_metadata"`
	Identities       []Identity     `json:"identities"`
	// Factors is the list of MFA factors read by supabase-js mfa.listFactors().
	// GetUser / Snapshot fill in the user's factors ordered by CreatedAt.
	Factors   []Factor  `json:"factors"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	PasswordHash []byte `json:"-"`
}

type Identity struct {
	// IdentityID is the identity row's own unique id. supabase-js
	// unlinkIdentity(identity) issues DELETE /user/identities/{identity.identity_id},
	// so this is the value the unlink route matches on. It mirrors GoTrue, whose
	// identity JSON exposes the row id as "identity_id" and the provider-scoped id
	// (the sub) as "id".
	IdentityID   string         `json:"identity_id"`
	ID           string         `json:"id"`
	UserID       string         `json:"user_id"`
	Provider     string         `json:"provider"`
	IdentityData map[string]any `json:"identity_data"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	LastSignInAt time.Time      `json:"last_sign_in_at"`
}

// AuthCode is a single-use OAuth authorization code minted by GET
// /auth/v1/authorize and exchanged by POST /auth/v1/token?grant_type=pkce
// (supabase-js exchangeCodeForSession). The emulator does not verify PKCE, so
// the code carries only what the exchange needs: the user to sign in and an
// expiry bounding the exchange window.
type AuthCode struct {
	Code      string
	UserID    string
	ExpiresAt time.Time
}

type RefreshToken struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	IssuedAt  time.Time `json:"issued_at"`
	Revoked   bool      `json:"revoked"`
	// Parent は rotation チェーン上の親トークン。reuse_interval 内なら再利用可。
	Parent string `json:"parent,omitempty"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	// AAL is the session's Authenticator Assurance Level: "aal1" right after a
	// password login, promoted to "aal2" after an MFA (passkey/webauthn) verify.
	// It is the source of the JWT aal claim.
	AAL string `json:"aal"`
	// AMR is the Authentication Methods References history. It becomes the JWT
	// amr claim, from which supabase-js getAuthenticatorAssuranceLevel derives
	// currentAuthenticationMethods.
	AMR []AMREntry `json:"amr,omitempty"`
}

// AMREntry represents a single authentication event (method and timestamp).
type AMREntry struct {
	Method    string `json:"method"`
	Timestamp int64  `json:"timestamp"`
}

// Factor is an MFA factor. This emulator only implements factor_type "webauthn"
// (passkey). Like GoTrue's user.factors it exposes friendly_name / factor_type /
// status.
type Factor struct {
	ID           string    `json:"id"`
	UserID       string    `json:"-"`
	FriendlyName string    `json:"friendly_name,omitempty"`
	FactorType   string    `json:"factor_type"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Challenge is a single-use verification challenge for a factor, invalid once
// ExpiresAt has passed.
type Challenge struct {
	ID        string    `json:"id"`
	FactorID  string    `json:"factor_id"`
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Passkey is a passwordless (primary-authentication) WebAuthn credential, as
// used by supabase-js auth.passkey.*. Unlike Factor (a second factor promoting a
// session to aal2), a passkey authenticates a login from scratch.
// The emulator has no real public key: authentication is matched by CredentialID
// rather than by verifying a signature, so only the credential id is persisted.
type Passkey struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	FriendlyName string    `json:"friendly_name,omitempty"`
	CredentialID string    `json:"credential_id"`
	CreatedAt    time.Time `json:"created_at"`
	// LastUsedAt is the time of the passkey's most recent successful
	// authentication, nil until it has been used at least once. It backs the
	// last_used_at field of auth.passkey.list().
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// PasskeyChallenge is a single-use passkey ceremony challenge. Registration
// challenges carry the authenticated UserID; authentication challenges are
// discoverable (no user yet), so UserID is empty.
type PasskeyChallenge struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id,omitempty"`
	Purpose      string    `json:"purpose"`
	FriendlyName string    `json:"friendly_name,omitempty"`
	Value        string    `json:"value"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// /__emulator/snapshot で JSON 化される前提のため snake_case + 空 slice を担保する。
type Snapshot struct {
	Users         []User         `json:"users"`
	Sessions      []Session      `json:"sessions"`
	RefreshTokens []RefreshToken `json:"refresh_tokens"`
	Factors       []Factor       `json:"factors"`
	Challenges    []Challenge    `json:"challenges"`
	Passkeys      []Passkey      `json:"passkeys"`
}
