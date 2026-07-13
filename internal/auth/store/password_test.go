package store

import "testing"

func TestPassword(t *testing.T) {
	t.Run("hashed password matches the plaintext", func(t *testing.T) {
		hash, err := HashPassword("password123")
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		if !VerifyPassword(hash, "password123") {
			t.Fatal("VerifyPassword returned false for matching password")
		}
	})

	t.Run("a different password does not match", func(t *testing.T) {
		hash, _ := HashPassword("password123")
		if VerifyPassword(hash, "wrong-password") {
			t.Fatal("VerifyPassword returned true for wrong password")
		}
	})
}
