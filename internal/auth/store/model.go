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
	// Factors は supabase-js の mfa.listFactors() が参照する MFA 要素一覧。
	// GetUser / Snapshot でユーザに紐づく Factor を CreatedAt 昇順で埋める。
	Factors   []Factor  `json:"factors"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	PasswordHash []byte `json:"-"`
}

type Identity struct {
	ID           string         `json:"id"`
	UserID       string         `json:"user_id"`
	Provider     string         `json:"provider"`
	IdentityData map[string]any `json:"identity_data"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	LastSignInAt time.Time      `json:"last_sign_in_at"`
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
	// AAL は session の Authenticator Assurance Level。password ログイン直後は "aal1"、
	// MFA (passkey/webauthn) verify 後に "aal2" へ昇格する。JWT の aal claim の出所。
	AAL string `json:"aal"`
	// AMR は認証手段の履歴 (Authentication Methods References)。JWT の amr claim になり、
	// supabase-js の getAuthenticatorAssuranceLevel が currentAuthenticationMethods を導出する。
	AMR []AMREntry `json:"amr,omitempty"`
}

// AMREntry は 1 回の認証イベント（method と発生時刻）を表す。
type AMREntry struct {
	Method    string `json:"method"`
	Timestamp int64  `json:"timestamp"`
}

// Factor は MFA 要素。本エミュレータは factor_type "webauthn"（passkey）のみを実装する。
// GoTrue の user.factors と同じく friendly_name / factor_type / status を公開する。
type Factor struct {
	ID           string    `json:"id"`
	UserID       string    `json:"-"`
	FriendlyName string    `json:"friendly_name,omitempty"`
	FactorType   string    `json:"factor_type"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Challenge は factor に対する 1 回限りの検証チャレンジ。ExpiresAt 経過後は無効。
type Challenge struct {
	ID        string    `json:"id"`
	FactorID  string    `json:"factor_id"`
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// /__emulator/snapshot で JSON 化される前提のため snake_case + 空 slice を担保する。
type Snapshot struct {
	Users         []User         `json:"users"`
	Sessions      []Session      `json:"sessions"`
	RefreshTokens []RefreshToken `json:"refresh_tokens"`
	Factors       []Factor       `json:"factors"`
	Challenges    []Challenge    `json:"challenges"`
}
