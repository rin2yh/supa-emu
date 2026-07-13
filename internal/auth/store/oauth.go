package store

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// authCodeTTL bounds how long an authorization code minted by /auth/v1/authorize
// stays exchangeable. A short window mirrors GoTrue's single-use flow codes.
const authCodeTTL = 5 * time.Minute

var (
	// ErrAuthCodeNotFound is returned when an authorization code is unknown,
	// already consumed, or expired.
	ErrAuthCodeNotFound = errors.New("store: authorization code not found")
)

// CreateOAuthUser creates (or, when email is provided and already exists,
// reuses) a user carrying a single provider identity, as an OAuth sign-in
// (signInWithOAuth) would after the provider callback. When email is empty a
// unique address is synthesized so each anonymous OAuth flow yields a distinct
// user. It returns the user clone.
//
// The emulator never reaches the real provider; the identity is fabricated
// locally so exchangeCodeForSession resolves a user whose identities include the
// provider.
func (s *Store) CreateOAuthUser(provider, email string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock()
	email = strings.ToLower(strings.TrimSpace(email))
	if email != "" {
		if id, ok := s.emailIndex[email]; ok {
			// Reuse the existing account, attaching the provider identity if it is
			// not already present (idempotent for repeated OAuth sign-ins).
			u := s.users[id]
			if !hasProviderLocked(u, provider) {
				appendProviderIdentityLocked(u, provider, email, now)
				recomputeProvidersLocked(u)
				u.UpdatedAt = now
			}
			return s.cloneUser(u), nil
		}
	}

	if email == "" {
		// Synthesize a unique address so anonymous OAuth flows never collide on
		// the email index.
		email = provider + "_" + uuid.NewString() + "@oauth.supa-emu.test"
	}
	u := s.newUserLocked(email, now)
	appendProviderIdentityLocked(u, provider, email, now)
	recomputeProvidersLocked(u)
	return s.cloneUser(u), nil
}

func hasProviderLocked(u *User, provider string) bool {
	for _, id := range u.Identities {
		if id.Provider == provider {
			return true
		}
	}
	return false
}

// appendProviderIdentityLocked adds a fabricated provider identity to the user.
// The provider-scoped id (sub) is a fresh uuid, standing in for the external
// provider's account id. The write lock must be held.
func appendProviderIdentityLocked(u *User, provider, email string, now time.Time) {
	sub := uuid.NewString()
	data := map[string]any{"sub": sub, "email": email}
	if at := strings.IndexByte(email, '@'); at > 0 {
		data["user_name"] = email[:at]
	}
	u.Identities = append(u.Identities, newIdentity(u.ID, provider, sub, data, now))
}

// CreateAuthCode mints a single-use authorization code bound to the user. The
// code is exchanged by the pkce token grant.
func (s *Store) CreateAuthCode(userID string) (*AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return nil, ErrUserNotFound
	}
	now := s.clock()
	ac := &AuthCode{
		Code:      uuid.NewString(),
		UserID:    userID,
		ExpiresAt: now.Add(authCodeTTL),
	}
	s.authCodes[ac.Code] = ac
	clone := *ac
	return &clone, nil
}

// ConsumeAuthCode validates and single-use consumes an authorization code,
// returning it (its UserID identifies the account to sign in). An unknown /
// expired / already-consumed code yields ErrAuthCodeNotFound. The caller stamps
// the sign-in and issues the session, so the user is not resolved here.
func (s *Store) ConsumeAuthCode(code string) (*AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.authCodes[code]
	if !ok {
		return nil, ErrAuthCodeNotFound
	}
	if s.clock().After(ac.ExpiresAt) {
		delete(s.authCodes, code)
		return nil, ErrAuthCodeNotFound
	}
	delete(s.authCodes, code)
	clone := *ac
	return &clone, nil
}
