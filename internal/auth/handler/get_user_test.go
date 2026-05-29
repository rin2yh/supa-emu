package handler_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/handler/handlertest"
)

func TestGetUser(t *testing.T) {
	t.Run("正常系: 有効な Bearer で user を返す", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")

		req := handlertest.NewRequest(t, http.MethodGet, "/auth/v1/user", nil)
		req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.GetUser, rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status: %d", rec.Code)
		}
	})

	t.Run("認証失敗のエラーコード分類", func(t *testing.T) {
		cases := []struct {
			name          string
			setHeader     func(r *http.Request, validToken string)
			deleteUser    bool
			wantErrorCode string
		}{
			{
				name:          "Authorization 欠落は no_authorization",
				setHeader:     func(*http.Request, string) {},
				wantErrorCode: "no_authorization",
			},
			{
				name:          "不正な署名の Bearer は bad_jwt",
				setHeader:     func(r *http.Request, _ string) { r.Header.Set("Authorization", "Bearer not-a-jwt") },
				wantErrorCode: "bad_jwt",
			},
			{
				name: "user が削除済みは session_not_found",
				setHeader: func(r *http.Request, validToken string) {
					r.Header.Set("Authorization", "Bearer "+validToken)
				},
				deleteUser:    true,
				wantErrorCode: "session_not_found",
			},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				st := handlertest.NewStore(nil)
				tk := handlertest.NewTokens(st, nil)
				f := handler.NewFactory(st, tk)

				var validToken string
				if c.deleteUser {
					seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
					validToken = seeded.AccessToken
					if err := st.DeleteUser(seeded.User.ID); err != nil {
						t.Fatalf("DeleteUser: %v", err)
					}
				}

				req := handlertest.NewRequest(t, http.MethodGet, "/auth/v1/user", nil)
				c.setHeader(req, validToken)
				rec := httptest.NewRecorder()
				handlertest.Serve(f, handler.GetUser, rec, req)

				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("status: %d", rec.Code)
				}
				if rec.Header().Get("X-Supabase-Api-Version") == "" {
					t.Error("X-Supabase-Api-Version header missing")
				}
				if !strings.Contains(rec.Body.String(), `"error_code":"`+c.wantErrorCode+`"`) {
					t.Errorf("error_code want=%s body=%s", c.wantErrorCode, rec.Body.String())
				}
			})
		}
	})

	t.Run("注入clockを進めて期限切れJWTで401", func(t *testing.T) {
		current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		clock := func() time.Time { return current }
		st := handlertest.NewStore(clock)
		tk := handlertest.NewTokens(st, clock)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")

		current = current.Add(2 * time.Hour)
		req := handlertest.NewRequest(t, http.MethodGet, "/auth/v1/user", nil)
		req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.GetUser, rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status: %d", rec.Code)
		}
	})
}
