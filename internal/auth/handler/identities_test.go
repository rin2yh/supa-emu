package handler_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/handler/handlertest"
	"github.com/rin2yh/supa-emu/internal/config"
)

func TestLinkIdentityAuthorize(t *testing.T) {
	const target = "/auth/v1/user/identities/authorize?provider=github" +
		"&code_challenge=abc123&code_challenge_method=s256" +
		"&redirect_to=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback&skip_http_redirect=true"

	t.Run("正常系: skip_http_redirect=true は 200 で { url } を返す", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")

		req := handlertest.NewRequest(t, http.MethodGet, target, nil)
		req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.LinkIdentityAuthorize, rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			URL string `json:"url"`
		}
		handlertest.DecodeJSON(t, rec, &resp)
		if resp.URL == "" {
			t.Fatalf("empty url: %s", rec.Body.String())
		}
		u, err := url.Parse(resp.URL)
		if err != nil {
			t.Fatalf("url parse: %v", err)
		}
		// The authorize URL stays local (the emulator's own /auth/v1/authorize,
		// like signInWithOAuth) rather than bouncing to the real provider, with the
		// provider + PKCE + redirect params passed through.
		if u.Path != "/auth/v1/authorize" {
			t.Errorf("path want /auth/v1/authorize, url=%s", resp.URL)
		}
		if strings.Contains(u.Host, "github.com") {
			t.Errorf("host should stay local, not github.com, url=%s", resp.URL)
		}
		q := u.Query()
		if got := q.Get("provider"); got != "github" {
			t.Errorf("provider=%q url=%s", got, resp.URL)
		}
		if got := q.Get("code_challenge"); got != "abc123" {
			t.Errorf("code_challenge=%q url=%s", got, resp.URL)
		}
		if got := q.Get("code_challenge_method"); got != "s256" {
			t.Errorf("code_challenge_method=%q url=%s", got, resp.URL)
		}
		if got := q.Get("redirect_to"); got != "http://127.0.0.1:3000/callback" {
			t.Errorf("redirect_to=%q url=%s", got, resp.URL)
		}
		if q.Get("state") == "" {
			t.Errorf("state missing url=%s", resp.URL)
		}
	})

	t.Run("skip_http_redirect なしは 302 で Location を返す", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")

		req := handlertest.NewRequest(t, http.MethodGet, "/auth/v1/user/identities/authorize?provider=github", nil)
		req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.LinkIdentityAuthorize, rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "/auth/v1/authorize") {
			t.Errorf("Location want /auth/v1/authorize, got %q", loc)
		}
		// GoTrue's redirect is an empty-body 302; it must not carry a JSON body.
		if body := rec.Body.String(); body != "" {
			t.Errorf("302 body want empty, got %q", body)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "" {
			t.Errorf("302 Content-Type want empty, got %q", ct)
		}
	})

	t.Run("github 以外のプロバイダも同じローカル authorize に寄せる", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")

		req := handlertest.NewRequest(t, http.MethodGet,
			"/auth/v1/user/identities/authorize?provider=google&skip_http_redirect=true", nil)
		req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.LinkIdentityAuthorize, rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			URL string `json:"url"`
		}
		handlertest.DecodeJSON(t, rec, &resp)
		u, err := url.Parse(resp.URL)
		if err != nil {
			t.Fatalf("url parse: %v", err)
		}
		if u.Path != "/auth/v1/authorize" {
			t.Errorf("path want /auth/v1/authorize, url=%s", resp.URL)
		}
		if got := u.Query().Get("provider"); got != "google" {
			t.Errorf("provider=%q url=%s", got, resp.URL)
		}
	})

	t.Run("末尾スラッシュ付き issuer でも二重スラッシュにならない", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		// Issuer with a trailing slash must not produce "…//authorize".
		tk := handler.NewTokens(st, config.DefaultJWTSecret, handlertest.Issuer+"/", time.Hour, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")

		req := handlertest.NewRequest(t, http.MethodGet,
			"/auth/v1/user/identities/authorize?provider=github&skip_http_redirect=true", nil)
		req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.LinkIdentityAuthorize, rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			URL string `json:"url"`
		}
		handlertest.DecodeJSON(t, rec, &resp)
		if strings.Contains(resp.URL, "//auth/v1/authorize") {
			t.Errorf("double slash in url=%s", resp.URL)
		}
		u, err := url.Parse(resp.URL)
		if err != nil {
			t.Fatalf("url parse: %v", err)
		}
		if u.Path != "/auth/v1/authorize" {
			t.Errorf("path want /auth/v1/authorize, url=%s", resp.URL)
		}
	})

	t.Run("provider 欠落は 422 validation_failed", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")

		req := handlertest.NewRequest(t, http.MethodGet, "/auth/v1/user/identities/authorize?skip_http_redirect=true", nil)
		req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.LinkIdentityAuthorize, rec, req)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status: %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"error_code":"validation_failed"`) {
			t.Errorf("body=%s", rec.Body.String())
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
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				st := handlertest.NewStore(nil)
				tk := handlertest.NewTokens(st, nil)
				f := handler.NewFactory(st, tk)

				var validToken string
				if tc.deleteUser {
					seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
					validToken = seeded.AccessToken
					if err := st.DeleteUser(seeded.User.ID); err != nil {
						t.Fatalf("DeleteUser: %v", err)
					}
				}

				req := handlertest.NewRequest(t, http.MethodGet, target, nil)
				tc.setHeader(req, validToken)
				rec := httptest.NewRecorder()
				handlertest.Serve(f, handler.LinkIdentityAuthorize, rec, req)

				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("status: %d", rec.Code)
				}
				if !strings.Contains(rec.Body.String(), `"error_code":"`+tc.wantErrorCode+`"`) {
					t.Errorf("error_code want=%s body=%s", tc.wantErrorCode, rec.Body.String())
				}
			})
		}
	})
}
