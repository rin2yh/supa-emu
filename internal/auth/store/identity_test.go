package store

import (
	"errors"
	"testing"
	"time"
)

func TestAddIdentity(t *testing.T) {
	t.Run("github identity を付与すると providers が更新される", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)

		got, err := s.AddIdentity(u.ID, "github", map[string]any{"sub": "gh-1"})
		if err != nil {
			t.Fatalf("AddIdentity: %v", err)
		}
		if len(got.Identities) != 2 {
			t.Fatalf("identities want 2, got %d", len(got.Identities))
		}
		gh := got.Identities[1]
		if gh.Provider != "github" || gh.ID != "gh-1" || gh.IdentityID == "" {
			t.Errorf("github identity: %+v", gh)
		}
		providers, _ := got.AppMetadata["providers"].([]string)
		if len(providers) != 2 || providers[0] != "email" || providers[1] != "github" {
			t.Errorf("providers=%v", got.AppMetadata["providers"])
		}
		// The primary provider stays email (the first identity).
		if got.AppMetadata["provider"] != "email" {
			t.Errorf("provider=%v", got.AppMetadata["provider"])
		}
	})

	t.Run("同一 provider の重複は ErrIdentityExists", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		if _, err := s.AddIdentity(u.ID, "github", nil); err != nil {
			t.Fatalf("first AddIdentity: %v", err)
		}
		if _, err := s.AddIdentity(u.ID, "github", nil); !errors.Is(err, ErrIdentityExists) {
			t.Errorf("want ErrIdentityExists, got %v", err)
		}
	})

	t.Run("存在しないユーザーは ErrUserNotFound", func(t *testing.T) {
		s := newStore()
		if _, err := s.AddIdentity("nope", "github", nil); !errors.Is(err, ErrUserNotFound) {
			t.Errorf("want ErrUserNotFound, got %v", err)
		}
	})
}

func TestRemoveIdentity(t *testing.T) {
	t.Run("付与した github identity を identity_id で解除できる", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		withGH, _ := s.AddIdentity(u.ID, "github", nil)
		ghID := withGH.Identities[1].IdentityID

		got, err := s.RemoveIdentity(u.ID, ghID)
		if err != nil {
			t.Fatalf("RemoveIdentity: %v", err)
		}
		if len(got.Identities) != 1 || got.Identities[0].Provider != "email" {
			t.Errorf("identities after unlink: %+v", got.Identities)
		}
		providers, _ := got.AppMetadata["providers"].([]string)
		if len(providers) != 1 || providers[0] != "email" {
			t.Errorf("providers=%v", got.AppMetadata["providers"])
		}
	})

	t.Run("唯一の identity は ErrLastIdentity", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		emailID := u.Identities[0].IdentityID
		if _, err := s.RemoveIdentity(u.ID, emailID); !errors.Is(err, ErrLastIdentity) {
			t.Errorf("want ErrLastIdentity, got %v", err)
		}
	})

	t.Run("未知の identity_id は ErrIdentityNotFound", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		_, _ = s.AddIdentity(u.ID, "github", nil)
		if _, err := s.RemoveIdentity(u.ID, "missing"); !errors.Is(err, ErrIdentityNotFound) {
			t.Errorf("want ErrIdentityNotFound, got %v", err)
		}
	})
}

func TestOAuthUserAndAuthCode(t *testing.T) {
	t.Run("CreateOAuthUser は provider identity 付きユーザーを作る", func(t *testing.T) {
		s := newStore()
		u, err := s.CreateOAuthUser("github", "")
		if err != nil {
			t.Fatalf("CreateOAuthUser: %v", err)
		}
		if len(u.Identities) != 1 || u.Identities[0].Provider != "github" {
			t.Fatalf("identities: %+v", u.Identities)
		}
		if u.Email == "" {
			t.Errorf("synthesized email empty")
		}
		if u.AppMetadata["provider"] != "github" {
			t.Errorf("provider=%v", u.AppMetadata["provider"])
		}
	})

	t.Run("login_hint(email) 指定は同一 email を再利用する", func(t *testing.T) {
		s := newStore()
		a, _ := s.CreateOAuthUser("github", "dev@example.com")
		b, _ := s.CreateOAuthUser("github", "dev@example.com")
		if a.ID != b.ID {
			t.Errorf("want same user, got %q vs %q", a.ID, b.ID)
		}
		if len(b.Identities) != 1 {
			t.Errorf("identity duplicated on reuse: %+v", b.Identities)
		}
	})

	t.Run("auth code は単回使用でユーザーに交換される", func(t *testing.T) {
		s := newStore()
		u, _ := s.CreateOAuthUser("github", "")
		ac, err := s.CreateAuthCode(u.ID, "github", "challenge")
		if err != nil {
			t.Fatalf("CreateAuthCode: %v", err)
		}
		got, gotUser, err := s.ConsumeAuthCode(ac.Code)
		if err != nil {
			t.Fatalf("ConsumeAuthCode: %v", err)
		}
		if got.UserID != u.ID || gotUser.ID != u.ID {
			t.Errorf("mismatch: code.UserID=%s user.ID=%s want=%s", got.UserID, gotUser.ID, u.ID)
		}
		if _, _, err := s.ConsumeAuthCode(ac.Code); !errors.Is(err, ErrAuthCodeNotFound) {
			t.Errorf("second consume want ErrAuthCodeNotFound, got %v", err)
		}
	})

	t.Run("期限切れ auth code は ErrAuthCodeNotFound", func(t *testing.T) {
		now := time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC)
		s := New(Config{Clock: func() time.Time { return now }, ReuseInterval: 10 * time.Second})
		u, _ := s.CreateOAuthUser("github", "")
		ac, _ := s.CreateAuthCode(u.ID, "github", "")
		now = now.Add(authCodeTTL + time.Second)
		if _, _, err := s.ConsumeAuthCode(ac.Code); !errors.Is(err, ErrAuthCodeNotFound) {
			t.Errorf("want ErrAuthCodeNotFound, got %v", err)
		}
	})
}
