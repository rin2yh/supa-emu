package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/google/uuid"
)

// challengeTTL is the factor-challenge lifetime, matching GoTrue's default
// (MFA_CHALLENGE_EXPIRY_DURATION=300s).
const challengeTTL = 5 * time.Minute

// Factor / Challenge status and type values. These use the same strings as GoTrue.
const (
	FactorStatusUnverified = "unverified"
	FactorStatusVerified   = "verified"

	FactorTypeWebAuthn = "webauthn"
)

var (
	ErrFactorNotFound     = errors.New("store: factor not found")
	ErrFactorNameConflict = errors.New("store: factor friendly_name already exists")
	ErrChallengeNotFound  = errors.New("store: challenge not found")
	ErrChallengeExpired   = errors.New("store: challenge expired")
)

// EnrollFactor registers one unverified MFA factor and returns a clone.
// A duplicate friendly_name for the same user yields ErrFactorNameConflict
// (matching GoTrue's behavior).
func (s *Store) EnrollFactor(userID, factorType, friendlyName string) (*Factor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[userID]; !ok {
		return nil, ErrUserNotFound
	}
	if friendlyName != "" {
		for _, f := range s.factors {
			if f.UserID == userID && f.FriendlyName == friendlyName {
				return nil, ErrFactorNameConflict
			}
		}
	}

	now := s.clock()
	f := &Factor{
		ID:           uuid.NewString(),
		UserID:       userID,
		FriendlyName: friendlyName,
		FactorType:   factorType,
		Status:       FactorStatusUnverified,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.factors[f.ID] = f
	return cloneFactor(f), nil
}

// GetFactor returns a clone of the factor for factorID.
func (s *Store) GetFactor(factorID string) (*Factor, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.factors[factorID]
	if !ok {
		return nil, false
	}
	return cloneFactor(f), true
}

// VerifyFactor promotes the factor to verified.
// Verifying an already-verified factor succeeds idempotently (re-authentication
// flow); the updated clone is returned.
func (s *Store) VerifyFactor(factorID string) (*Factor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[factorID]
	if !ok {
		return nil, ErrFactorNotFound
	}
	f.Status = FactorStatusVerified
	f.UpdatedAt = s.clock()
	return cloneFactor(f), nil
}

// DeleteFactor removes a factor owned by userID together with its challenges.
// A missing factor or owner mismatch yields ErrFactorNotFound.
func (s *Store) DeleteFactor(userID, factorID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[factorID]
	if !ok || f.UserID != userID {
		return ErrFactorNotFound
	}
	s.deleteFactorLocked(factorID)
	return nil
}

// deleteFactorLocked removes a factor and its challenges. It assumes the write
// lock is held and keeps the cascade semantics in one place, shared by
// DeleteFactor (single delete) and DeleteUser (cascade).
func (s *Store) deleteFactorLocked(factorID string) {
	delete(s.factors, factorID)
	for cid, ch := range s.challenges {
		if ch.FactorID == factorID {
			delete(s.challenges, cid)
		}
	}
}

// CreateChallenge issues a single-use challenge for a factor.
func (s *Store) CreateChallenge(factorID string) (*Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.factors[factorID]; !ok {
		return nil, ErrFactorNotFound
	}
	now := s.clock()
	ch := &Challenge{
		ID:        uuid.NewString(),
		FactorID:  factorID,
		Value:     randomChallenge(),
		CreatedAt: now,
		ExpiresAt: now.Add(challengeTTL),
	}
	s.challenges[ch.ID] = ch
	return ch, nil
}

// ConsumeChallenge validates a challenge and consumes it single-use.
// A factor mismatch yields ErrChallengeNotFound; an expired challenge yields
// ErrChallengeExpired (and is removed as well).
func (s *Store) ConsumeChallenge(factorID, challengeID string) (*Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.challenges[challengeID]
	if !ok || ch.FactorID != factorID {
		return nil, ErrChallengeNotFound
	}
	// Treat expiry as consumption and remove it, so later calls surface expired
	// explicitly rather than degrading to not-found.
	if s.clock().After(ch.ExpiresAt) {
		delete(s.challenges, challengeID)
		return nil, ErrChallengeExpired
	}
	delete(s.challenges, challengeID)
	c := *ch
	return &c, nil
}

// UpgradeSessionAAL promotes a session to aal2 and appends method to its amr.
// A method already present is not appended twice. A missing session returns
// false rather than reusing ErrUserNotFound.
func (s *Store) UpgradeSessionAAL(sessionID, method string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, false
	}
	sess.AAL = "aal2"
	has := false
	for _, e := range sess.AMR {
		if e.Method == method {
			has = true
			break
		}
	}
	if !has {
		sess.AMR = append(sess.AMR, AMREntry{Method: method, Timestamp: s.clock().Unix()})
	}
	return cloneSession(sess), true
}

// randomChallenge generates the base64url challenge value carried in the
// WebAuthn options. It is never used for crypto verification (this is an
// emulator), so it falls back to a UUID if the random source fails.
func randomChallenge() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return base64.RawURLEncoding.EncodeToString([]byte(uuid.NewString()))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
