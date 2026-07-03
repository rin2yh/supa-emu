package store

import (
	"errors"
	"testing"
	"time"
)

func TestEnrollFactor(t *testing.T) {
	t.Run("unverified な webauthn factor を登録し user.Factors に現れる", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)

		f, err := s.EnrollFactor(u.ID, FactorTypeWebAuthn, "MacBook")
		if err != nil {
			t.Fatalf("EnrollFactor: %v", err)
		}
		if f.Status != FactorStatusUnverified || f.FactorType != FactorTypeWebAuthn {
			t.Errorf("unexpected factor: %+v", f)
		}

		fresh, _ := s.FindUserByID(u.ID)
		if len(fresh.Factors) != 1 || fresh.Factors[0].ID != f.ID {
			t.Fatalf("factor not attached to user: %+v", fresh.Factors)
		}
		if fresh.Factors[0].FriendlyName != "MacBook" {
			t.Errorf("friendly_name: %s", fresh.Factors[0].FriendlyName)
		}
	})

	t.Run("同一ユーザで friendly_name が重複すると ErrFactorNameConflict", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)

		if _, err := s.EnrollFactor(u.ID, FactorTypeWebAuthn, "Key"); err != nil {
			t.Fatalf("first enroll: %v", err)
		}
		if _, err := s.EnrollFactor(u.ID, FactorTypeWebAuthn, "Key"); !errors.Is(err, ErrFactorNameConflict) {
			t.Fatalf("expected ErrFactorNameConflict, got %v", err)
		}
	})

	t.Run("存在しないユーザは ErrUserNotFound", func(t *testing.T) {
		s := newStore()
		if _, err := s.EnrollFactor("nope", FactorTypeWebAuthn, ""); !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("expected ErrUserNotFound, got %v", err)
		}
	})
}

func TestVerifyFactorAndChallenge(t *testing.T) {
	t.Run("challenge を発行し consume で single-use 消費、factor を verified に昇格", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		f, _ := s.EnrollFactor(u.ID, FactorTypeWebAuthn, "Key")

		ch, err := s.CreateChallenge(f.ID)
		if err != nil {
			t.Fatalf("CreateChallenge: %v", err)
		}
		if ch.Value == "" {
			t.Error("challenge value must be non-empty")
		}

		if _, err := s.ConsumeChallenge(f.ID, ch.ID); err != nil {
			t.Fatalf("ConsumeChallenge: %v", err)
		}
		// 2 回目は single-use のため not found
		if _, err := s.ConsumeChallenge(f.ID, ch.ID); !errors.Is(err, ErrChallengeNotFound) {
			t.Fatalf("expected ErrChallengeNotFound on reuse, got %v", err)
		}

		verified, err := s.VerifyFactor(f.ID, "cred")
		if err != nil {
			t.Fatalf("VerifyFactor: %v", err)
		}
		if verified.Status != FactorStatusVerified {
			t.Errorf("status: %s", verified.Status)
		}
	})

	t.Run("factor 不一致の challenge は ErrChallengeNotFound", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		f1, _ := s.EnrollFactor(u.ID, FactorTypeWebAuthn, "A")
		f2, _ := s.EnrollFactor(u.ID, FactorTypeWebAuthn, "B")

		ch, _ := s.CreateChallenge(f1.ID)
		if _, err := s.ConsumeChallenge(f2.ID, ch.ID); !errors.Is(err, ErrChallengeNotFound) {
			t.Fatalf("expected ErrChallengeNotFound, got %v", err)
		}
	})

	t.Run("期限切れ challenge は ErrChallengeExpired", func(t *testing.T) {
		now := time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC)
		s := New(Config{Clock: func() time.Time { return now }, ReuseInterval: 10 * time.Second})
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		f, _ := s.EnrollFactor(u.ID, FactorTypeWebAuthn, "Key")

		ch, _ := s.CreateChallenge(f.ID)
		now = now.Add(challengeTTL + time.Second)
		if _, err := s.ConsumeChallenge(f.ID, ch.ID); !errors.Is(err, ErrChallengeExpired) {
			t.Fatalf("expected ErrChallengeExpired, got %v", err)
		}
	})
}

func TestUpgradeSessionAAL(t *testing.T) {
	t.Run("session を aal2 に昇格し amr に webauthn を追記する", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		sess, _ := s.CreateSession(u.ID)
		if sess.AAL != "aal1" {
			t.Fatalf("initial aal: %s", sess.AAL)
		}

		upgraded, ok := s.UpgradeSessionAAL(sess.ID, FactorTypeWebAuthn)
		if !ok {
			t.Fatal("UpgradeSessionAAL returned false")
		}
		if upgraded.AAL != "aal2" {
			t.Errorf("aal: %s", upgraded.AAL)
		}
		methods := map[string]bool{}
		for _, e := range upgraded.AMR {
			methods[e.Method] = true
		}
		if !methods["password"] || !methods[FactorTypeWebAuthn] {
			t.Errorf("amr must contain password + webauthn: %+v", upgraded.AMR)
		}
	})

	t.Run("存在しない session は false", func(t *testing.T) {
		s := newStore()
		if _, ok := s.UpgradeSessionAAL("nope", FactorTypeWebAuthn); ok {
			t.Error("expected false for missing session")
		}
	})
}

func TestDeleteFactor(t *testing.T) {
	t.Run("所有者の factor と紐づく challenge を削除する", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		f, _ := s.EnrollFactor(u.ID, FactorTypeWebAuthn, "Key")
		ch, _ := s.CreateChallenge(f.ID)

		if err := s.DeleteFactor(u.ID, f.ID); err != nil {
			t.Fatalf("DeleteFactor: %v", err)
		}
		if _, ok := s.GetFactor(f.ID); ok {
			t.Error("factor still present")
		}
		if _, err := s.ConsumeChallenge(f.ID, ch.ID); !errors.Is(err, ErrChallengeNotFound) {
			t.Error("challenge not cascaded on factor delete")
		}
	})

	t.Run("他ユーザの factor は ErrFactorNotFound", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		owner, _ := s.CreateUser("alice@example.com", hash)
		other, _ := s.CreateUser("bob@example.com", hash)
		f, _ := s.EnrollFactor(owner.ID, FactorTypeWebAuthn, "Key")

		if err := s.DeleteFactor(other.ID, f.ID); !errors.Is(err, ErrFactorNotFound) {
			t.Fatalf("expected ErrFactorNotFound, got %v", err)
		}
	})
}

func TestDeleteUserCascadesFactors(t *testing.T) {
	t.Run("ユーザ削除で factor / challenge も消える", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		f, _ := s.EnrollFactor(u.ID, FactorTypeWebAuthn, "Key")
		_, _ = s.CreateChallenge(f.ID)

		if err := s.DeleteUser(u.ID); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		snap := s.Snapshot()
		if len(snap.Factors) != 0 || len(snap.Challenges) != 0 {
			t.Errorf("factors/challenges not cascaded: %+v", snap)
		}
	})
}

func TestSnapshotFactorsNonNil(t *testing.T) {
	t.Run("空ストアで Factors / Challenges は非 nil の空 slice", func(t *testing.T) {
		s := newStore()
		snap := s.Snapshot()
		if snap.Factors == nil || snap.Challenges == nil {
			t.Fatalf("must be empty slice not nil: %+v", snap)
		}
	})
}
