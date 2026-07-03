package store

import (
	"errors"
	"sort"

	"github.com/google/uuid"
)

// Passkey ceremony purposes, matching the /auth/v1/passkeys/{registration,authentication}/* split.
const (
	PasskeyPurposeRegistration   = "registration"
	PasskeyPurposeAuthentication = "authentication"
)

var (
	ErrPasskeyNotFound          = errors.New("store: passkey not found")
	ErrPasskeyExists            = errors.New("store: passkey credential already registered")
	ErrPasskeyChallengeNotFound = errors.New("store: passkey challenge not found")
	ErrPasskeyChallengeExpired  = errors.New("store: passkey challenge expired")
)

// CreatePasskeyChallenge issues a single-use ceremony challenge. Registration
// challenges (authenticated) carry userID and an optional friendlyName;
// authentication challenges are discoverable, so userID is empty.
func (s *Store) CreatePasskeyChallenge(userID, purpose, friendlyName string) (*PasskeyChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if userID != "" {
		if _, ok := s.users[userID]; !ok {
			return nil, ErrUserNotFound
		}
	}
	now := s.clock()
	ch := &PasskeyChallenge{
		ID:           uuid.NewString(),
		UserID:       userID,
		Purpose:      purpose,
		FriendlyName: friendlyName,
		Value:        randomChallenge(),
		CreatedAt:    now,
		ExpiresAt:    now.Add(challengeTTL),
	}
	s.passkeyChallenges[ch.ID] = ch
	return ch, nil
}

// ConsumePasskeyChallenge validates and single-use consumes a challenge for the
// given purpose. A missing/purpose-mismatched challenge yields
// ErrPasskeyChallengeNotFound; an expired one yields ErrPasskeyChallengeExpired
// (and is removed as well).
func (s *Store) ConsumePasskeyChallenge(challengeID, purpose string) (*PasskeyChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.passkeyChallenges[challengeID]
	if !ok || ch.Purpose != purpose {
		return nil, ErrPasskeyChallengeNotFound
	}
	if s.clock().After(ch.ExpiresAt) {
		delete(s.passkeyChallenges, challengeID)
		return nil, ErrPasskeyChallengeExpired
	}
	delete(s.passkeyChallenges, challengeID)
	c := *ch
	return &c, nil
}

// AddPasskey persists a registered credential for a user. A credentialID that is
// already registered yields ErrPasskeyExists.
func (s *Store) AddPasskey(userID, friendlyName, credentialID string) (*Passkey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return nil, ErrUserNotFound
	}
	if _, exists := s.passkeyByCred[credentialID]; exists {
		return nil, ErrPasskeyExists
	}
	pk := &Passkey{
		ID:           uuid.NewString(),
		UserID:       userID,
		FriendlyName: friendlyName,
		CredentialID: credentialID,
		CreatedAt:    s.clock(),
	}
	s.passkeys[pk.ID] = pk
	s.passkeyByCred[credentialID] = pk.ID
	return clonePasskey(pk), nil
}

// DeletePasskey removes a user's own passkey by its passkey ID. A passkey that
// does not exist, or is owned by a different user, yields ErrPasskeyNotFound so
// a caller cannot distinguish "not found" from "not yours".
func (s *Store) DeletePasskey(userID, passkeyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pk, ok := s.passkeys[passkeyID]
	if !ok || pk.UserID != userID {
		return ErrPasskeyNotFound
	}
	delete(s.passkeys, passkeyID)
	delete(s.passkeyByCred, pk.CredentialID)
	return nil
}

// MarkPasskeyUsed stamps a passkey's LastUsedAt with the current time after a
// successful authentication. A missing passkey is a no-op.
func (s *Store) MarkPasskeyUsed(passkeyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pk, ok := s.passkeys[passkeyID]
	if !ok {
		return
	}
	now := s.clock()
	pk.LastUsedAt = &now
}

// FindPasskeyByCredentialID resolves the credential presented during an
// authentication ceremony back to its stored passkey (and thus its owner).
func (s *Store) FindPasskeyByCredentialID(credentialID string) (*Passkey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.passkeyByCred[credentialID]
	if !ok {
		return nil, false
	}
	pk, ok := s.passkeys[id]
	if !ok {
		return nil, false
	}
	return clonePasskey(pk), true
}

// ListUserPasskeys returns the user's passkeys ordered by CreatedAt (ties broken
// by ID), as a non-nil slice.
func (s *Store) ListUserPasskeys(userID string) []Passkey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Passkey, 0)
	for _, pk := range s.passkeys {
		if pk.UserID == userID {
			// Passkey has no reference fields, so a value copy fully detaches it.
			out = append(out, *pk)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func clonePasskey(pk *Passkey) *Passkey {
	c := *pk
	return &c
}
