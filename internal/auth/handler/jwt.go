package handler

import (
	"errors"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/rin2yh/supa-emu/internal/auth/store"
)

type Claims struct {
	Subject string `json:"sub,omitempty"`
	Issuer  string `json:"iss,omitempty"`
	// 本物 GoTrue と同じく単一 string で出すため、jwtv5.RegisteredClaims を embed せず自前定義する
	// （RegisteredClaims の Audience は ClaimStrings=[]string で配列に展開されてしまう）。
	Audience     string         `json:"aud,omitempty"`
	IssuedAt     int64          `json:"iat,omitempty"`
	Expiry       int64          `json:"exp,omitempty"`
	Role         string         `json:"role,omitempty"`
	Email        string         `json:"email,omitempty"`
	SessionID    string         `json:"session_id,omitempty"`
	AppMetadata  map[string]any `json:"app_metadata,omitempty"`
	UserMetadata map[string]any `json:"user_metadata,omitempty"`
	// AAL / AMR carry the MFA (passkey) assurance level. supabase-js
	// getAuthenticatorAssuranceLevel reads currentLevel from the access_token.
	AAL string           `json:"aal,omitempty"`
	AMR []store.AMREntry `json:"amr,omitempty"`
}

// jwtv5.Claims インターフェース実装。標準 validator (exp/nbf チェック) を流用するために必要。
func (c Claims) GetExpirationTime() (*jwtv5.NumericDate, error) {
	if c.Expiry == 0 {
		return nil, nil
	}
	return jwtv5.NewNumericDate(time.Unix(c.Expiry, 0)), nil
}

func (c Claims) GetIssuedAt() (*jwtv5.NumericDate, error) {
	if c.IssuedAt == 0 {
		return nil, nil
	}
	return jwtv5.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

func (c Claims) GetNotBefore() (*jwtv5.NumericDate, error) { return nil, nil }
func (c Claims) GetIssuer() (string, error)                { return c.Issuer, nil }
func (c Claims) GetSubject() (string, error)               { return c.Subject, nil }
func (c Claims) GetAudience() (jwtv5.ClaimStrings, error) {
	if c.Audience == "" {
		return nil, nil
	}
	return jwtv5.ClaimStrings{c.Audience}, nil
}

type TokenResponse struct {
	AccessToken  string      `json:"access_token"`
	TokenType    string      `json:"token_type"`
	ExpiresIn    int64       `json:"expires_in"`
	ExpiresAt    int64       `json:"expires_at"`
	RefreshToken string      `json:"refresh_token"`
	User         *store.User `json:"user"`
}

// Factory が 1 インスタンス保持し全ハンドラから共有されるため、フィールドは構築後 immutable に保つこと。
type Tokens struct {
	store  *store.Store
	secret string
	issuer string
	ttl    time.Duration
	clock  func() time.Time
}

func NewTokens(st *store.Store, secret, issuer string, ttl time.Duration, clock func() time.Time) *Tokens {
	if clock == nil {
		clock = time.Now
	}
	if ttl == 0 {
		ttl = time.Hour
	}
	if issuer == "" {
		issuer = "http://127.0.0.1:54321/auth/v1"
	}
	return &Tokens{store: st, secret: secret, issuer: issuer, ttl: ttl, clock: clock}
}

func (t *Tokens) keyFunc(tok *jwtv5.Token) (any, error) {
	if _, ok := tok.Method.(*jwtv5.SigningMethodHMAC); !ok {
		return nil, errors.New("unexpected signing method")
	}
	return []byte(t.secret), nil
}

// store.IssueSession で CreateSession + IssueRefreshToken を 1 ロックで実行することで、
// 並行 DeleteUser が走っても session 単独の leak が発生しない。
func (t *Tokens) Issue(u *store.User) (*TokenResponse, error) {
	sess, rt, err := t.store.IssueSession(u.ID)
	if err != nil {
		return nil, err
	}
	return t.Build(u, sess.ID, rt.Token)
}

// rotation 後の access_token 再発行で、既存 sessionID / refreshToken をそのまま流用するため
// Issue とは別経路で持つ。Issue にマージすると refresh のたびに新 session が増えて leak する。
func (t *Tokens) Build(u *store.User, sessionID, refreshToken string) (*TokenResponse, error) {
	now := t.clock()
	exp := now.Add(t.ttl)
	// aal / amr mirror the values held on the session into the JWT. If a passkey
	// verify has promoted the session to aal2, that assurance level is preserved
	// across refreshes.
	aal := "aal1"
	var amr []store.AMREntry
	if sess, ok := t.store.GetSession(sessionID); ok {
		if sess.AAL != "" {
			aal = sess.AAL
		}
		amr = sess.AMR
	}
	c := Claims{
		Subject:      u.ID,
		Issuer:       t.issuer,
		Audience:     u.Aud,
		IssuedAt:     now.Unix(),
		Expiry:       exp.Unix(),
		Role:         u.Role,
		Email:        u.Email,
		SessionID:    sessionID,
		AppMetadata:  u.AppMetadata,
		UserMetadata: u.UserMetadata,
		AAL:          aal,
		AMR:          amr,
	}
	signed, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, c).SignedString([]byte(t.secret))
	if err != nil {
		return nil, err
	}
	return &TokenResponse{
		AccessToken:  signed,
		TokenType:    "bearer",
		ExpiresIn:    int64(t.ttl.Seconds()),
		ExpiresAt:    exp.Unix(),
		RefreshToken: refreshToken,
		User:         u,
	}, nil
}

// WithTimeFunc で注入 clock を渡さないとテストで Clock を fake にした効果が及ばない。
// WithIssuer は、公開定数 DefaultJWTSecret で署名された anon / service_role JWT が
// user token として通ってしまうのを防ぐため必須。
func (t *Tokens) Verify(token string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwtv5.ParseWithClaims(token, claims, t.keyFunc,
		jwtv5.WithTimeFunc(t.clock), jwtv5.WithIssuer(t.issuer), jwtv5.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// logout は access_token が exp 切れでも session を revoke できるべきなので、exp 検証だけ飛ばして
// 署名と iss を確認し claims を返す。WithoutClaimsValidation が WithIssuer を無効化するため iss は
// 手動照合する（公開定数 DefaultJWTSecret で署名された anon / service_role JWT の流用を防ぐ）。
func (t *Tokens) VerifyIgnoringExpiry(token string) (*Claims, error) {
	claims := &Claims{}
	if _, err := jwtv5.NewParser(
		jwtv5.WithoutClaimsValidation(),
		jwtv5.WithValidMethods([]string{"HS256"}),
	).ParseWithClaims(token, claims, t.keyFunc); err != nil {
		return nil, err
	}
	if claims.Issuer != t.issuer {
		return nil, jwtv5.ErrTokenInvalidIssuer
	}
	return claims, nil
}
