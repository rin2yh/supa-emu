package store

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func newStore() *Store {
	return New(Config{
		Clock:         func() time.Time { return time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC) },
		ReuseInterval: 10 * time.Second,
	})
}

func TestCreateUser(t *testing.T) {
	t.Run("新規ユーザーがIDとともに登録される", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, err := s.CreateUser("alice@example.com", hash)
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if u.ID == "" || u.Email != "alice@example.com" {
			t.Errorf("got=%+v", u)
		}
		if u.Aud != "authenticated" || u.Role != "authenticated" {
			t.Errorf("aud/role mismatch: %+v", u)
		}
	})

	t.Run("同じemailで2回作るとErrUserAlreadyExists", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		_, _ = s.CreateUser("alice@example.com", hash)
		_, err := s.CreateUser("alice@example.com", hash)
		if !errors.Is(err, ErrUserAlreadyExists) {
			t.Fatalf("expected ErrUserAlreadyExists, got %v", err)
		}
	})

	t.Run("emailを大文字小文字無視して重複検知し、lowercaseで保存する", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("Alice@Example.COM", hash)
		if u.Email != "alice@example.com" {
			t.Errorf("email must be lowercased: %s", u.Email)
		}
		_, err := s.CreateUser("ALICE@example.com", hash)
		if !errors.Is(err, ErrUserAlreadyExists) {
			t.Fatalf("expected ErrUserAlreadyExists, got %v", err)
		}
	})
}

func TestFindUser(t *testing.T) {
	t.Run("emailの大文字小文字を無視して検索できる", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		created, _ := s.CreateUser("alice@example.com", hash)
		got, ok := s.FindUserByEmail("ALICE@EXAMPLE.COM")
		if !ok || got.ID != created.ID {
			t.Fatalf("not found or ID mismatch")
		}
	})

	t.Run("存在しないIDはfalseを返す", func(t *testing.T) {
		s := newStore()
		if _, ok := s.FindUserByID("nope"); ok {
			t.Error("should not be found")
		}
	})
}

func TestDeleteUser(t *testing.T) {
	t.Run("削除で関連session/refresh_tokenも消える", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		sess, _ := s.CreateSession(u.ID)
		tok, _ := s.IssueRefreshToken(u.ID, sess.ID)

		if err := s.DeleteUser(u.ID); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		if _, ok := s.FindUserByID(u.ID); ok {
			t.Error("user still exists")
		}
		if _, _, err := s.ConsumeRefreshToken(tok.Token); err == nil {
			t.Error("refresh token still usable after delete")
		}
	})

	t.Run("存在しないIDはErrUserNotFound", func(t *testing.T) {
		s := newStore()
		if err := s.DeleteUser("nonexistent"); !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("expected ErrUserNotFound, got %v", err)
		}
	})
}

func TestSetUserMetadata(t *testing.T) {
	t.Run("Storeに永続化され、後続のFindで取得できる", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)

		s.SetUserMetadata(u.ID, map[string]any{"nickname": "alice"})

		fresh, _ := s.FindUserByID(u.ID)
		if got := fresh.UserMetadata["nickname"]; got != "alice" {
			t.Errorf("metadata not persisted: got=%v", got)
		}
	})
}

func TestListUsers(t *testing.T) {
	t.Run("CreatedAt昇順でページ単位に返り、totalは全件数", func(t *testing.T) {
		base := time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC)
		tick := 0
		s := New(Config{Clock: func() time.Time {
			tick++
			return base.Add(time.Duration(tick) * time.Second)
		}, ReuseInterval: 10 * time.Second})
		hash, _ := HashPassword("password123")
		for _, e := range []string{"a@example.com", "b@example.com", "c@example.com"} {
			if _, err := s.CreateUser(e, hash); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
		}

		page, total := s.ListUsers(0, 2)
		if total != 3 {
			t.Errorf("total: got=%d want=3", total)
		}
		if len(page) != 2 || page[0].Email != "a@example.com" || page[1].Email != "b@example.com" {
			t.Errorf("page1 mismatch: %+v", page)
		}

		page2, _ := s.ListUsers(2, 2)
		if len(page2) != 1 || page2[0].Email != "c@example.com" {
			t.Errorf("page2 mismatch: %+v", page2)
		}
	})

	t.Run("offsetが件数を超えても非nilの空スライスを返す", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		_, _ = s.CreateUser("a@example.com", hash)

		page, total := s.ListUsers(50, 10)
		if total != 1 {
			t.Errorf("total: got=%d want=1", total)
		}
		if page == nil || len(page) != 0 {
			t.Errorf("expected non-nil empty slice, got %+v", page)
		}
	})

	t.Run("負のoffset(page由来のオーバーフロー)でもpanicせず空スライス", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		_, _ = s.CreateUser("a@example.com", hash)

		page, total := s.ListUsers(-100, 10)
		if total != 1 {
			t.Errorf("total: got=%d want=1", total)
		}
		if page == nil || len(page) != 0 {
			t.Errorf("expected non-nil empty slice, got %+v", page)
		}
	})
}

func TestRefreshTokenRotation(t *testing.T) {
	t.Run("Consumeで新tokenを発行し旧tokenを失効させる", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		sess, _ := s.CreateSession(u.ID)
		old, _ := s.IssueRefreshToken(u.ID, sess.ID)

		newTok, gotUser, err := s.ConsumeRefreshToken(old.Token)
		if err != nil {
			t.Fatalf("ConsumeRefreshToken: %v", err)
		}
		if newTok.Token == old.Token {
			t.Fatal("token not rotated")
		}
		if gotUser.ID != u.ID {
			t.Errorf("user ID mismatch")
		}
	})

	t.Run("reuse_interval内なら旧tokenの再利用で同じ子tokenが返る", func(t *testing.T) {
		now := time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC)
		s := New(Config{Clock: func() time.Time { return now }, ReuseInterval: 10 * time.Second})
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		sess, _ := s.CreateSession(u.ID)
		old, _ := s.IssueRefreshToken(u.ID, sess.ID)

		first, _, _ := s.ConsumeRefreshToken(old.Token)
		reused, _, err := s.ConsumeRefreshToken(old.Token)
		if err != nil {
			t.Fatalf("reuse within interval should succeed: %v", err)
		}
		if reused.Token != first.Token {
			t.Errorf("reuse must return same child token: %s vs %s", reused.Token, first.Token)
		}
	})

	t.Run("reuse_interval超過後は旧tokenがinvalidになる", func(t *testing.T) {
		now := time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC)
		s := New(Config{Clock: func() time.Time { return now }, ReuseInterval: 10 * time.Second})
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		sess, _ := s.CreateSession(u.ID)
		old, _ := s.IssueRefreshToken(u.ID, sess.ID)

		_, _, _ = s.ConsumeRefreshToken(old.Token)
		now = now.Add(11 * time.Second)
		_, _, err := s.ConsumeRefreshToken(old.Token)
		if !errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatalf("expected ErrInvalidRefreshToken, got %v", err)
		}
	})

	t.Run("T0→T1→T2 とローテートされても、T0 reuse で末端 T2 を返す", func(t *testing.T) {
		now := time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC)
		s := New(Config{Clock: func() time.Time { return now }, ReuseInterval: time.Minute})
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		sess, _ := s.CreateSession(u.ID)
		t0, _ := s.IssueRefreshToken(u.ID, sess.ID)

		t1, _, _ := s.ConsumeRefreshToken(t0.Token)
		t2, _, _ := s.ConsumeRefreshToken(t1.Token)

		reused, _, err := s.ConsumeRefreshToken(t0.Token)
		if err != nil {
			t.Fatalf("reuse: %v", err)
		}
		if reused.Token != t2.Token {
			t.Errorf("reuse must follow chain to leaf t2: got=%s want=%s", reused.Token, t2.Token)
		}
	})

	t.Run("RevokeRefreshTokensBySessionでreuse_intervalが2hでも再利用不可", func(t *testing.T) {
		now := time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC)
		s := New(Config{Clock: func() time.Time { return now }, ReuseInterval: 2 * time.Hour})
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		sess, _ := s.CreateSession(u.ID)
		tok, _ := s.IssueRefreshToken(u.ID, sess.ID)

		s.RevokeRefreshTokensBySession(sess.ID)
		if _, _, err := s.ConsumeRefreshToken(tok.Token); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatalf("expected ErrInvalidRefreshToken, got %v", err)
		}
	})
}

func TestSnapshotAndReset(t *testing.T) {
	t.Run("空ストアで空配列が返る（JSONでnullにならない）", func(t *testing.T) {
		s := newStore()
		snap := s.Snapshot()
		if snap.Users == nil || snap.Sessions == nil || snap.RefreshTokens == nil {
			t.Fatalf("must be empty slice not nil: %+v", snap)
		}
	})

	t.Run("Resetで全データが消える", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		sess, _ := s.CreateSession(u.ID)
		_, _ = s.IssueRefreshToken(u.ID, sess.ID)

		s.Reset()

		snap := s.Snapshot()
		if len(snap.Users) != 0 || len(snap.RefreshTokens) != 0 || len(snap.Sessions) != 0 {
			t.Errorf("snapshot not empty: %+v", snap)
		}
	})
}

func TestCloneIsDeep(t *testing.T) {
	t.Run("clone のmetadata書き換えがStore本体に影響しない", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		created, _ := s.CreateUser("alice@example.com", hash)

		created.AppMetadata["injected"] = true
		created.UserMetadata["nick"] = "evil"
		created.Identities[0].IdentityData["email"] = "tampered@example.com"

		fresh, _ := s.FindUserByID(created.ID)
		if _, exists := fresh.AppMetadata["injected"]; exists {
			t.Error("AppMetadata leaked into store")
		}
		if _, exists := fresh.UserMetadata["nick"]; exists {
			t.Error("UserMetadata leaked into store")
		}
		if got := fresh.Identities[0].IdentityData["email"]; got != "alice@example.com" {
			t.Errorf("identity email leaked: %v", got)
		}
	})
}

func TestCloneIsDeep_NestedSliceInAppMetadata(t *testing.T) {
	t.Run("AppMetadata['providers'] の []string を書き換えても Store 本体は影響を受けない", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		created, _ := s.CreateUser("alice@example.com", hash)

		// CreateUser が seed する providers slice をクライアント側で書き換える
		providers, ok := created.AppMetadata["providers"].([]string)
		if !ok {
			t.Fatalf("providers slice missing: %T", created.AppMetadata["providers"])
		}
		providers[0] = "github"

		fresh, _ := s.FindUserByID(created.ID)
		if got := fresh.AppMetadata["providers"].([]string)[0]; got != "email" {
			t.Errorf("providers leaked into store: %s", got)
		}
	})
}

func TestIssueSession_Atomic(t *testing.T) {
	t.Run("削除済みユーザに対しては ErrUserNotFound を返し、session も残らない", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		if err := s.DeleteUser(u.ID); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}

		_, _, err := s.IssueSession(u.ID)
		if !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("expected ErrUserNotFound, got %v", err)
		}
		if len(s.Snapshot().Sessions) != 0 {
			t.Error("session leaked on failed IssueSession")
		}
	})
}

func TestRevokeRefreshTokensBySession_CleansParentToChild(t *testing.T) {
	t.Run("logout 後に同じ session の parentToChild エントリが残らない", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		sess, rt, err := s.IssueSession(u.ID)
		if err != nil {
			t.Fatalf("IssueSession: %v", err)
		}
		// 1 回 rotation して parentToChild にエントリを作る
		if _, _, err := s.ConsumeRefreshToken(rt.Token); err != nil {
			t.Fatalf("Consume: %v", err)
		}

		s.RevokeRefreshTokensBySession(sess.ID)
		if got := len(s.parentToChild); got != 0 {
			t.Errorf("parentToChild not cleaned: %d entries remain", got)
		}
	})
}

func TestDeleteUser_CleansParentToChild(t *testing.T) {
	t.Run("ユーザ削除時に parentToChild の両エッジが掃除される", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		_, rt, _ := s.IssueSession(u.ID)
		_, _, _ = s.ConsumeRefreshToken(rt.Token)

		if err := s.DeleteUser(u.ID); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		if got := len(s.parentToChild); got != 0 {
			t.Errorf("parentToChild not cleaned: %d entries remain", got)
		}
	})
}

func TestRace(t *testing.T) {
	t.Run("並行書き込みで競合しない", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				email := "u" + itoa(i) + "@example.com"
				u, err := s.CreateUser(email, hash)
				if err != nil {
					t.Errorf("CreateUser: %v", err)
					return
				}
				sess, _ := s.CreateSession(u.ID)
				_, _ = s.IssueRefreshToken(u.ID, sess.ID)
			}(i)
		}
		wg.Wait()
		if got := len(s.Snapshot().Users); got != 50 {
			t.Errorf("user count: got=%d want=50", got)
		}
	})
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [10]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
