package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/handler/handlertest"
)

func TestLogout(t *testing.T) {
	t.Run("idempotent (always 204 for GoTrue compatibility)", func(t *testing.T) {
		cases := []struct {
			name      string
			setHeader func(r *http.Request)
		}{
			{name: "no Authorization", setHeader: func(*http.Request) {}},
			{name: "invalid Bearer", setHeader: func(r *http.Request) { r.Header.Set("Authorization", "Bearer bogus") }},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				st := handlertest.NewStore(nil)
				f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

				req := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/logout", nil)
				c.setHeader(req)
				rec := httptest.NewRecorder()
				handlertest.Serve(f, handler.Logout, rec, req)
				if rec.Code != http.StatusNoContent {
					t.Fatalf("status: %d", rec.Code)
				}
			})
		}
	})

	t.Run("valid Bearer returns 204 + revokes refresh_token", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")

		req := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/logout", nil)
		req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.Logout, rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("logout status: %d", rec.Code)
		}

		refresh := httptest.NewRecorder()
		handlertest.Serve(f, handler.Token, refresh, handlertest.NewRequest(t, http.MethodPost, "/auth/v1/token?grant_type=refresh_token", map[string]string{
			"refresh_token": seeded.RefreshToken,
		}))
		if refresh.Code != http.StatusBadRequest {
			t.Errorf("refresh after logout status: %d", refresh.Code)
		}
	})

	t.Run("refresh_token is revoked even with an expired access_token", func(t *testing.T) {
		current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		clock := func() time.Time { return current }
		st := handlertest.NewStore(clock)
		tk := handlertest.NewTokens(st, clock)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")

		current = current.Add(2 * time.Hour)

		req := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/logout", nil)
		req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.Logout, rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("logout status: %d", rec.Code)
		}

		refresh := httptest.NewRecorder()
		handlertest.Serve(f, handler.Token, refresh, handlertest.NewRequest(t, http.MethodPost, "/auth/v1/token?grant_type=refresh_token", map[string]string{
			"refresh_token": seeded.RefreshToken,
		}))
		if refresh.Code != http.StatusBadRequest {
			t.Errorf("expired-logout 後の refresh は失敗するべき: %d", refresh.Code)
		}
	})
}
