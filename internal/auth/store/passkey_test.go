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

		pk, err := s.AddPasskey(u.ID, "My Laptop", "cred-abc", "cred-abc")
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

		if _, err := s.AddPasskey(u.ID, "A", "cred-dup", "cred-dup"); err != nil {
			t.Fatalf("first AddPasskey: %v", err)
		}
		if _, err := s.AddPasskey(u.ID, "B", "cred-dup", "cred-dup"); !errors.Is(err, ErrPasskeyExists) {
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
		_, _ = s.AddPasskey(u.ID, "Key", "cred-1", "cred-1")
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
