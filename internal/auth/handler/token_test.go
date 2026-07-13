package handler_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/handler/handlertest"
)

func TestToken(t *testing.T) {
	t.Run("password grant", func(t *testing.T) {
		t.Run("returns 200 with correct credentials", func(t *testing.T) {
			st := handlertest.NewStore(nil)
			tk := handlertest.NewTokens(st, nil)
			f := handler.NewFactory(st, tk)
			handlertest.Seed(t, st, tk, "alice@example.com", "password123")

			rec := httptest.NewRecorder()
			handlertest.Serve(f, handler.Token, rec, handlertest.NewRequest(t, http.MethodPost, "/auth/v1/token?grant_type=password", map[string]string{
				"email": "alice@example.com", "password": "password123",
			}))
			if rec.Code != http.StatusOK {
				t.Fatalf("status: %d", rec.Code)
			}
		})

		t.Run("auth failure returns 400 + invalid_grant + 'Invalid login credentials'", func(t *testing.T) {
			cases := []struct {
				name string
				body map[string]string
			}{
				{name: "wrong password", body: map[string]string{"email": "alice@example.com", "password": "WRONG"}},
				{name: "unregistered email", body: map[string]string{"email": "nobody@example.com", "password": "password123"}},
				{name: "both email and password empty", body: map[string]string{}},
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					st := handlertest.NewStore(nil)
					tk := handlertest.NewTokens(st, nil)
					f := handler.NewFactory(st, tk)
					handlertest.Seed(t, st, tk, "alice@example.com", "password123")

					rec := httptest.NewRecorder()
					handlertest.Serve(f, handler.Token, rec, handlertest.NewRequest(t, http.MethodPost, "/auth/v1/token?grant_type=password", c.body))

					if rec.Code != http.StatusBadRequest {
						t.Fatalf("status: %d", rec.Code)
					}
					body := rec.Body.String()
					if !strings.Contains(body, "invalid_grant") || !strings.Contains(body, "Invalid login credentials") {
						t.Errorf("body: %s", body)
					}
				})
			}
		})
	})

	t.Run("refresh_token grant", func(t *testing.T) {
		t.Run("valid refresh_token returns a rotated new pair", func(t *testing.T) {
			st := handlertest.NewStore(nil)
			tk := handlertest.NewTokens(st, nil)
			f := handler.NewFactory(st, tk)
			seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")

			rec := httptest.NewRecorder()
			handlertest.Serve(f, handler.Token, rec, handlertest.NewRequest(t, http.MethodPost, "/auth/v1/token?grant_type=refresh_token", map[string]string{
				"refresh_token": seeded.RefreshToken,
			}))
			if rec.Code != http.StatusOK {
				t.Fatalf("status: %d", rec.Code)
			}
			var rotated handler.TokenResponse
			handlertest.DecodeJSON(t, rec, &rotated)
			if rotated.RefreshToken == seeded.RefreshToken {
				t.Error("refresh_token not rotated")
			}
		})

		t.Run("invalid refresh_token returns 400 + 'Invalid Refresh Token'", func(t *testing.T) {
			cases := []struct {
				name       string
				refreshTok string
			}{
				{name: "nonexistent token", refreshTok: "bogus"},
				{name: "empty string", refreshTok: ""},
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					st := handlertest.NewStore(nil)
					f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

					rec := httptest.NewRecorder()
					handlertest.Serve(f, handler.Token, rec, handlertest.NewRequest(t, http.MethodPost, "/auth/v1/token?grant_type=refresh_token", map[string]string{
						"refresh_token": c.refreshTok,
					}))
					if rec.Code != http.StatusBadRequest {
						t.Fatalf("status: %d", rec.Code)
					}
					if !strings.Contains(rec.Body.String(), "Invalid Refresh Token") {
						t.Errorf("body: %s", rec.Body.String())
					}
				})
			}
		})
	})

	t.Run("password grant: trims trailing spaces from email and logs in", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		handlertest.Seed(t, st, tk, "alice@example.com", "password123")

		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.Token, rec, handlertest.NewRequest(t, http.MethodPost, "/auth/v1/token?grant_type=password", map[string]string{
			"email": "  alice@example.com  ", "password": "password123",
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status: %d, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("missing grant_type returns 400", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.Token, rec, handlertest.NewRequest(t, http.MethodPost, "/auth/v1/token", map[string]string{
			"email": "alice@example.com", "password": "password123",
		}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status: %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "unsupported_grant_type") {
			t.Errorf("body: %s", rec.Body.String())
		}
	})
}
