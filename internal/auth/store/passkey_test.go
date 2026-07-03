package store

import (
	"errors"
	"testing"
	"time"
)

func TestPasskeyRegistrationAndLookup(t *testing.T) {
	t.Run("registers a credential and resolves it back to the owner", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)

		pk, err := s.AddPasskey(u.ID, "My Laptop", "cred-abc")
		if err != nil {
			t.Fatalf("AddPasskey: %v", err)
		}
		if pk.ID == "" || pk.CredentialID != "cred-abc" {
			t.Errorf("unexpected passkey: %+v", pk)
		}

		found, ok := s.FindPasskeyByCredentialID("cred-abc")
		if !ok || found.UserID != u.ID {
			t.Fatalf("lookup failed: %+v ok=%v", found, ok)
		}
	})

	t.Run("a duplicate credential id returns ErrPasskeyExists", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)

		if _, err := s.AddPasskey(u.ID, "A", "cred-dup"); err != nil {
			t.Fatalf("first AddPasskey: %v", err)
		}
		if _, err := s.AddPasskey(u.ID, "B", "cred-dup"); !errors.Is(err, ErrPasskeyExists) {
			t.Fatalf("expected ErrPasskeyExists, got %v", err)
		}
	})

	t.Run("an unknown credential id is not found", func(t *testing.T) {
		s := newStore()
		if _, ok := s.FindPasskeyByCredentialID("nope"); ok {
			t.Error("should not be found")
		}
	})
}

func TestListUserPasskeys(t *testing.T) {
	t.Run("returns only the given user's passkeys ordered by CreatedAt", func(t *testing.T) {
		now := time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)
		s := New(Config{Clock: func() time.Time { return now }, ReuseInterval: 10 * time.Second})
		hash, _ := HashPassword("password123")
		alice, _ := s.CreateUser("alice@example.com", hash)
		bob, _ := s.CreateUser("bob@example.com", hash)

		_, _ = s.AddPasskey(alice.ID, "Laptop", "cred-a1")
		now = now.Add(time.Minute)
		_, _ = s.AddPasskey(alice.ID, "Phone", "cred-a2")
		_, _ = s.AddPasskey(bob.ID, "Bob Key", "cred-b1")

		list := s.ListUserPasskeys(alice.ID)
		if len(list) != 2 {
			t.Fatalf("expected 2 passkeys for alice, got %d: %+v", len(list), list)
		}
		if list[0].CredentialID != "cred-a1" || list[1].CredentialID != "cred-a2" {
			t.Errorf("wrong order: %+v", list)
		}
		if list[0].LastUsedAt != nil {
			t.Errorf("LastUsedAt should be nil before use: %+v", list[0].LastUsedAt)
		}
	})
}

func TestDeletePasskey(t *testing.T) {
	t.Run("deletes the owner's passkey and clears the credential index", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		pk, _ := s.AddPasskey(u.ID, "Key", "cred-del")

		if err := s.DeletePasskey(u.ID, pk.ID); err != nil {
			t.Fatalf("DeletePasskey: %v", err)
		}
		if _, ok := s.FindPasskeyByCredentialID("cred-del"); ok {
			t.Error("credential still resolvable after delete")
		}
		if got := s.ListUserPasskeys(u.ID); len(got) != 0 {
			t.Errorf("passkey not removed from list: %+v", got)
		}
	})

	t.Run("a missing passkey returns ErrPasskeyNotFound", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		if err := s.DeletePasskey(u.ID, "nope"); !errors.Is(err, ErrPasskeyNotFound) {
			t.Fatalf("expected ErrPasskeyNotFound, got %v", err)
		}
	})

	t.Run("another user's passkey is not deletable and returns ErrPasskeyNotFound", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		alice, _ := s.CreateUser("alice@example.com", hash)
		bob, _ := s.CreateUser("bob@example.com", hash)
		pk, _ := s.AddPasskey(bob.ID, "Bob Key", "cred-bob")

		if err := s.DeletePasskey(alice.ID, pk.ID); !errors.Is(err, ErrPasskeyNotFound) {
			t.Fatalf("expected ErrPasskeyNotFound, got %v", err)
		}
		if _, ok := s.FindPasskeyByCredentialID("cred-bob"); !ok {
			t.Error("bob's passkey should survive alice's delete attempt")
		}
	})
}

func TestMarkPasskeyUsed(t *testing.T) {
	t.Run("stamps LastUsedAt with the current clock", func(t *testing.T) {
		now := time.Date(2026, 7, 3, 1, 0, 0, 0, time.UTC)
		s := New(Config{Clock: func() time.Time { return now }, ReuseInterval: 10 * time.Second})
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		pk, _ := s.AddPasskey(u.ID, "Key", "cred-used")

		s.MarkPasskeyUsed(pk.ID)

		list := s.ListUserPasskeys(u.ID)
		if len(list) != 1 || list[0].LastUsedAt == nil {
			t.Fatalf("LastUsedAt not set: %+v", list)
		}
		if !list[0].LastUsedAt.Equal(now) {
			t.Errorf("LastUsedAt: got=%v want=%v", *list[0].LastUsedAt, now)
		}
	})

	t.Run("a missing passkey is a no-op", func(t *testing.T) {
		s := newStore()
		s.MarkPasskeyUsed("nope") // must not panic
	})
}

func TestPasskeyChallenge(t *testing.T) {
	t.Run("registration challenge carries the user and is single-use", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)

		ch, err := s.CreatePasskeyChallenge(u.ID, PasskeyPurposeRegistration, "My Laptop")
		if err != nil {
			t.Fatalf("CreatePasskeyChallenge: %v", err)
		}
		if ch.UserID != u.ID || ch.FriendlyName != "My Laptop" || ch.Value == "" {
			t.Errorf("unexpected challenge: %+v", ch)
		}

		if _, err := s.ConsumePasskeyChallenge(ch.ID, PasskeyPurposeRegistration); err != nil {
			t.Fatalf("ConsumePasskeyChallenge: %v", err)
		}
		if _, err := s.ConsumePasskeyChallenge(ch.ID, PasskeyPurposeRegistration); !errors.Is(err, ErrPasskeyChallengeNotFound) {
			t.Fatalf("expected ErrPasskeyChallengeNotFound on reuse, got %v", err)
		}
	})

	t.Run("authentication challenge is discoverable (no user required)", func(t *testing.T) {
		s := newStore()
		ch, err := s.CreatePasskeyChallenge("", PasskeyPurposeAuthentication, "")
		if err != nil {
			t.Fatalf("CreatePasskeyChallenge: %v", err)
		}
		if ch.UserID != "" {
			t.Errorf("authentication challenge must not carry a user: %+v", ch)
		}
	})

	t.Run("consuming with the wrong purpose returns ErrPasskeyChallengeNotFound", func(t *testing.T) {
		s := newStore()
		ch, _ := s.CreatePasskeyChallenge("", PasskeyPurposeAuthentication, "")
		if _, err := s.ConsumePasskeyChallenge(ch.ID, PasskeyPurposeRegistration); !errors.Is(err, ErrPasskeyChallengeNotFound) {
			t.Fatalf("expected ErrPasskeyChallengeNotFound, got %v", err)
		}
	})

	t.Run("an expired challenge returns ErrPasskeyChallengeExpired", func(t *testing.T) {
		now := time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC)
		s := New(Config{Clock: func() time.Time { return now }, ReuseInterval: 10 * time.Second})
		ch, _ := s.CreatePasskeyChallenge("", PasskeyPurposeAuthentication, "")
		now = now.Add(challengeTTL + time.Second)
		if _, err := s.ConsumePasskeyChallenge(ch.ID, PasskeyPurposeAuthentication); !errors.Is(err, ErrPasskeyChallengeExpired) {
			t.Fatalf("expected ErrPasskeyChallengeExpired, got %v", err)
		}
	})
}

func TestDeleteUserCascadesPasskeys(t *testing.T) {
	t.Run("deleting a user removes their passkeys, the credential index, and challenges", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)
		_, _ = s.AddPasskey(u.ID, "Key", "cred-1")
		_, _ = s.CreatePasskeyChallenge(u.ID, PasskeyPurposeRegistration, "Key")

		if err := s.DeleteUser(u.ID); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		if _, ok := s.FindPasskeyByCredentialID("cred-1"); ok {
			t.Error("passkey still resolvable after user delete")
		}
		snap := s.Snapshot()
		if len(snap.Passkeys) != 0 {
			t.Errorf("passkeys not cascaded: %+v", snap.Passkeys)
		}
	})
}

func TestSnapshotPasskeysNonNil(t *testing.T) {
	t.Run("Passkeys is a non-nil empty slice for an empty store", func(t *testing.T) {
		s := newStore()
		if s.Snapshot().Passkeys == nil {
			t.Fatal("Passkeys must be an empty slice not nil")
		}
	})
}

func TestIssueSessionWithMethod(t *testing.T) {
	t.Run("records the given amr method on the session", func(t *testing.T) {
		s := newStore()
		hash, _ := HashPassword("password123")
		u, _ := s.CreateUser("alice@example.com", hash)

		sess, _, err := s.IssueSessionWithMethod(u.ID, FactorTypeWebAuthn)
		if err != nil {
			t.Fatalf("IssueSessionWithMethod: %v", err)
		}
		if sess.AAL != "aal1" {
			t.Errorf("passwordless passkey login must stay aal1: %s", sess.AAL)
		}
		if len(sess.AMR) != 1 || sess.AMR[0].Method != FactorTypeWebAuthn {
			t.Errorf("amr must be [webauthn]: %+v", sess.AMR)
		}
	})
}
