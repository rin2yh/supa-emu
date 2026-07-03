package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/google/uuid"
)

// challengeTTL は factor challenge の有効期限。GoTrue の既定 (MFA_CHALLENGE_EXPIRY_DURATION=300s) に合わせる。
const challengeTTL = 5 * time.Minute

// Factor / Challenge の状態値。GoTrue と同じ文字列を用いる。
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

// EnrollFactor は unverified な MFA 要素を 1 件登録して複製を返す。
// 同一ユーザ内で friendly_name が重複する場合は ErrFactorNameConflict（GoTrue と同挙動）。
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

// GetFactor は factorID から Factor の複製を返す。
func (s *Store) GetFactor(factorID string) (*Factor, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.factors[factorID]
	if !ok {
		return nil, false
	}
	return cloneFactor(f), true
}

// VerifyFactor は factor を verified に昇格させ、受領した credential 識別子を記録する。
// 既に verified でも冪等に成功扱いとし（再認証フロー）、更新後の複製を返す。
func (s *Store) VerifyFactor(factorID, credential string) (*Factor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[factorID]
	if !ok {
		return nil, ErrFactorNotFound
	}
	f.Status = FactorStatusVerified
	if credential != "" {
		f.WebAuthnCredential = credential
	}
	f.UpdatedAt = s.clock()
	return cloneFactor(f), nil
}

// DeleteFactor は userID 所有の factor と紐づく challenge を削除する。
// 所有者不一致 / 不存在は ErrFactorNotFound。
func (s *Store) DeleteFactor(userID, factorID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[factorID]
	if !ok || f.UserID != userID {
		return ErrFactorNotFound
	}
	delete(s.factors, factorID)
	for cid, ch := range s.challenges {
		if ch.FactorID == factorID {
			delete(s.challenges, cid)
		}
	}
	return nil
}

// CreateChallenge は factor に対する 1 回限りのチャレンジを発行する。
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

// ConsumeChallenge は challenge を検証して single-use で消費する。
// factor 不一致は ErrChallengeNotFound、期限切れは ErrChallengeExpired（この場合も掃除する）。
func (s *Store) ConsumeChallenge(factorID, challengeID string) (*Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.challenges[challengeID]
	if !ok || ch.FactorID != factorID {
		return nil, ErrChallengeNotFound
	}
	// 期限切れは消費扱いで除去し、以後 not found に落とさず expired を明示する。
	if s.clock().After(ch.ExpiresAt) {
		delete(s.challenges, challengeID)
		return nil, ErrChallengeExpired
	}
	delete(s.challenges, challengeID)
	c := *ch
	return &c, nil
}

// UpgradeSessionAAL は session を aal2 へ昇格させ、amr に method を追記する。
// 同一 method の重複追記は避ける。session 不存在は ErrUserNotFound を流用せず false を返す。
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

// randomChallenge は WebAuthn options に載せる base64url チャレンジ値を生成する。
// 暗号検証には使わない（エミュレータ）ため乱数源の失敗時は UUID にフォールバックする。
func randomChallenge() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return base64.RawURLEncoding.EncodeToString([]byte(uuid.NewString()))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
