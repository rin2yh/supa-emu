package store

import (
	"sort"
	"strings"

	"github.com/google/uuid"
)

func (s *Store) CreateUser(email string, passwordHash []byte) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 本物 GoTrue と同じく email は lowercase 正規化する。
	// 旧実装は原文保存していて、'Alice@example.com' が本物環境で join key 不一致を起こしていた。
	normalized := strings.ToLower(email)
	if _, exists := s.emailIndex[normalized]; exists {
		return nil, ErrUserAlreadyExists
	}

	now := s.clock()
	confirmed := now
	id := uuid.NewString()
	u := &User{
		ID:               id,
		Email:            normalized,
		Aud:              "authenticated",
		Role:             "authenticated",
		EmailConfirmedAt: &confirmed,
		ConfirmedAt:      &confirmed,
		AppMetadata:      map[string]any{"provider": "email", "providers": []string{"email"}},
		UserMetadata:     map[string]any{},
		Identities: []Identity{{
			ID:           id,
			UserID:       id,
			Provider:     "email",
			IdentityData: map[string]any{"email": normalized, "sub": id},
			CreatedAt:    now,
			UpdatedAt:    now,
			LastSignInAt: now,
		}},
		CreatedAt:    now,
		UpdatedAt:    now,
		PasswordHash: passwordHash,
	}
	s.users[id] = u
	s.emailIndex[normalized] = id
	return s.cloneUser(u), nil
}

func (s *Store) FindUserByEmail(email string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.emailIndex[strings.ToLower(email)]
	if !ok {
		return nil, false
	}
	u, ok := s.users[id]
	if !ok {
		return nil, false
	}
	return s.cloneUser(u), true
}

func (s *Store) FindUserByID(id string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, false
	}
	return s.cloneUser(u), true
}

func (s *Store) DeleteUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return ErrUserNotFound
	}
	delete(s.users, id)
	delete(s.emailIndex, strings.ToLower(u.Email))
	for sid, sess := range s.sessions {
		if sess.UserID == id {
			delete(s.sessions, sid)
		}
	}
	for tok, rt := range s.refreshTokens {
		if rt.UserID == id {
			delete(s.refreshTokens, tok)
			// 親→子の両エッジを掃除（rt が子側のエントリ + rt 自身が親として保持しているエントリ）
			if rt.Parent != "" {
				delete(s.parentToChild, rt.Parent)
			}
			delete(s.parentToChild, tok)
		}
	}
	return nil
}

// 本物 GoTrue の raw_user_meta_data は merge ではなく置換挙動なので合わせる。
// cloneAnyMap でネストした map/slice まで複製しないと、呼び出し元の req.Data 経由で
// ロック外から store の値が書き換えられて Snapshot と並走時 concurrent map fatal を起こす。
// 更新後の clone を返すので、呼び出し側は FindUserByID で読み直さなくてよい。
func (s *Store) SetUserMetadata(id string, data map[string]any) (*User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, false
	}
	u.UserMetadata = cloneAnyMap(data)
	u.UpdatedAt = s.clock()
	return s.cloneUser(u), true
}

func (s *Store) UpdateLastSignIn(id string) (*User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, false
	}
	now := s.clock()
	u.LastSignInAt = &now
	u.UpdatedAt = now
	return s.cloneUser(u), true
}

// ListUsers は CreatedAt 昇順で offset から limit 件の user 複製と全件数を返す。
// Snapshot と違い session / refresh_token を複製せず要求ページ分の user だけ clone する。
func (s *Store) ListUsers(offset, limit int) ([]User, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ordered := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		ordered = append(ordered, u)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].CreatedAt.Before(ordered[j].CreatedAt)
	})

	total := len(ordered)
	// AdminListUsers は (page-1)*perPage を offset に渡すので int オーバーフローで負値になりうる。
	// 範囲外は空ページとして返し ordered[offset:end] の panic を防ぐ。
	if offset < 0 || offset >= total {
		return []User{}, total
	}
	// offset+limit はオーバーフローしうるので加算前に残り件数と比較する。
	end := total
	if limit < total-offset {
		end = offset + limit
	}
	page := ordered[offset:end]
	users := make([]User, len(page))
	for i, u := range page {
		users[i] = *s.cloneUser(u)
	}
	return users, total
}
