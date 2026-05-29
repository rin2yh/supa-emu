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
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`

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
}

// /__emulator/snapshot で JSON 化される前提のため snake_case + 空 slice を担保する。
type Snapshot struct {
	Users         []User         `json:"users"`
	Sessions      []Session      `json:"sessions"`
	RefreshTokens []RefreshToken `json:"refresh_tokens"`
}
