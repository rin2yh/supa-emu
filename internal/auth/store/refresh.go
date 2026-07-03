package store

import (
	"time"

	"github.com/google/uuid"
)

func (s *Store) CreateSession(userID string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createSessionLocked(userID, "password")
}

func (s *Store) IssueRefreshToken(userID, sessionID string) (*RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issueRefreshTokenLocked(userID, sessionID)
}

// CreateSession + IssueRefreshToken を別ロックで呼ぶと、その隙に DeleteUser が走った場合に
// session だけ残って refresh_token 発行が失敗するため、handler 経路では 1 ロックで両方発行する。
// amrMethod is the authentication method recorded in the session's amr
// ("password" for password login, "webauthn" for passwordless passkey login).
func (s *Store) IssueSession(userID string) (*Session, *RefreshToken, error) {
	return s.IssueSessionWithMethod(userID, "password")
}

func (s *Store) IssueSessionWithMethod(userID, amrMethod string) (*Session, *RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, err := s.createSessionLocked(userID, amrMethod)
	if err != nil {
		return nil, nil, err
	}
	rt, err := s.issueRefreshTokenLocked(userID, sess.ID)
	if err != nil {
		// session 単独で残らないよう巻き戻す
		delete(s.sessions, sess.ID)
		return nil, nil, err
	}
	return sess, rt, nil
}

func (s *Store) createSessionLocked(userID, amrMethod string) (*Session, error) {
	if _, ok := s.users[userID]; !ok {
		return nil, ErrUserNotFound
	}
	now := s.clock()
	sess := &Session{
		ID:        uuid.NewString(),
		UserID:    userID,
		CreatedAt: now,
		// A single-factor login (password or passwordless passkey) starts at
		// aal1; a later MFA passkey verify promotes the session to aal2.
		AAL: "aal1",
		AMR: []AMREntry{{Method: amrMethod, Timestamp: now.Unix()}},
	}
	s.sessions[sess.ID] = sess
	return cloneSession(sess), nil
}

// GetSession returns a clone of the session. Build uses it to read the aal / amr
// claims when issuing a JWT.
func (s *Store) GetSession(sessionID string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, false
	}
	return cloneSession(sess), true
}

func (s *Store) issueRefreshTokenLocked(userID, sessionID string) (*RefreshToken, error) {
	if _, ok := s.users[userID]; !ok {
		return nil, ErrUserNotFound
	}
	rt := &RefreshToken{
		// 64 hex 文字相当の token を生成（GoTrue のデフォルト refresh_token と同等の長さ）
		Token:     uuid.NewString() + uuid.NewString(),
		UserID:    userID,
		SessionID: sessionID,
		IssuedAt:  s.clock(),
	}
	s.refreshTokens[rt.Token] = rt
	return cloneRefreshToken(rt), nil
}

// Revoked token を reuse_interval 内に再 consume したときに親→子チェーンの末端を返すのは
// 「ネットワークロストで client が同じ token をもう一度送ってきた」シナリオへの耐性のため。
func (s *Store) ConsumeRefreshToken(token string) (*RefreshToken, *User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rt, ok := s.refreshTokens[token]
	if !ok {
		return nil, nil, ErrInvalidRefreshToken
	}
	u, ok := s.users[rt.UserID]
	if !ok {
		return nil, nil, ErrInvalidRefreshToken
	}

	if rt.Revoked {
		// 子も並行 rotation で revoke されているケース（A→B→C のとき A を再試行）に
		// 対応するため Parent チェーンを末端まで辿る。
		if s.clock().Sub(rt.IssuedAt) <= s.reuseInterval {
			if leaf := s.findLatestChild(rt.Token); leaf != nil {
				return cloneRefreshToken(leaf), s.cloneUser(u), nil
			}
		}
		return nil, nil, ErrInvalidRefreshToken
	}

	now := s.clock()
	rt.Revoked = true
	rt.IssuedAt = now

	newRT := &RefreshToken{
		Token:     uuid.NewString() + uuid.NewString(),
		UserID:    rt.UserID,
		SessionID: rt.SessionID,
		IssuedAt:  now,
		Parent:    rt.Token,
	}
	s.refreshTokens[newRT.Token] = newRT
	s.parentToChild[rt.Token] = newRT.Token
	return cloneRefreshToken(newRT), s.cloneUser(u), nil
}

// findLatestChild は parentToChild 副索引でチェーンを O(チェーン長) で辿る。write lock 保持前提。
func (s *Store) findLatestChild(parent string) *RefreshToken {
	visited := map[string]bool{parent: true}
	current := parent
	for {
		childToken, ok := s.parentToChild[current]
		if !ok || visited[childToken] {
			return nil
		}
		visited[childToken] = true
		child, ok := s.refreshTokens[childToken]
		if !ok {
			return nil
		}
		if !child.Revoked {
			return child
		}
		current = childToken
	}
}

// logout で reuse_interval 内 reuse もブロックしたいので IssuedAt を reuse_interval+1s 過去に
// 遡らせる。-1h 固定だと運用で reuse_interval を 2h 等にした瞬間 logout が無効化される。
func (s *Store) RevokeRefreshTokensBySession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	past := s.clock().Add(-(s.reuseInterval + time.Second))
	for tok, rt := range s.refreshTokens {
		if rt.SessionID == sessionID {
			rt.Revoked = true
			rt.IssuedAt = past
			// parentToChild に残ると findLatestChild が無駄に辿ってしまうので両端を掃除する。
			if rt.Parent != "" {
				delete(s.parentToChild, rt.Parent)
			}
			delete(s.parentToChild, tok)
		}
	}
	delete(s.sessions, sessionID)
}
