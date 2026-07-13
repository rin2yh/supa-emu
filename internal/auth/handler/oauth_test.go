package handler_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/handler/handlertest"
)

// authorizeCode drives GET /auth/v1/authorize and returns the authorization code
// delivered on the redirect_to callback.
func authorizeCode(t *testing.T, f *handler.Factory, target string) (string, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	handlertest.Serve(f, handler.Authorize, rec, handlertest.NewRequest(t, http.MethodGet, target, nil))
	loc := rec.Header().Get("Location")
	if loc == "" {
		return "", rec
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location %q: %v", loc, err)
	}
	return u.Query().Get("code"), rec
}

func TestOAuthRoundTrip(t *testing.T) {
	const callback = "http://127.0.0.1:3000/auth/callback"

	t.Run("正常系: authorize が code を callback に返し token(pkce) が session に交換する", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)

		target := "/auth/v1/authorize?provider=github&code_challenge=abc123&code_challenge_method=s256" +
			"&redirect_to=" + url.QueryEscape(callback)
		code, rec := authorizeCode(t, f, target)
		if rec.Code != http.StatusFound {
			t.Fatalf("authorize status: %d body=%s", rec.Code, rec.Body.String())
		}
		// The redirect must stay on the app callback, not bounce to github.com.
		loc := rec.Header().Get("Location")
		if !strings.HasPrefix(loc, callback) {
			t.Errorf("Location want prefix %q, got %q", callback, loc)
		}
		if strings.Contains(loc, "github.com") {
			t.Errorf("Location should stay local, got %q", loc)
		}
		if code == "" {
			t.Fatalf("no code delivered, Location=%q", loc)
		}

		// exchangeCodeForSession: POST /auth/v1/token?grant_type=pkce.
		rec = httptest.NewRecorder()
		handlertest.Serve(f, handler.Token, rec, handlertest.NewRequest(t, http.MethodPost,
			"/auth/v1/token?grant_type=pkce", map[string]string{
				"auth_code": code, "code_verifier": "the-verifier",
			}))
		if rec.Code != http.StatusOK {
			t.Fatalf("token status: %d body=%s", rec.Code, rec.Body.String())
		}
		var tr handler.TokenResponse
		handlertest.DecodeJSON(t, rec, &tr)
		if tr.AccessToken == "" || tr.RefreshToken == "" {
			t.Fatalf("missing tokens: %+v", tr)
		}
		if tr.User == nil {
			t.Fatalf("missing user")
		}
		// user.identities must carry the github identity so getUserIdentities /
		// linked:true resolves.
		var providers []string
		for _, id := range tr.User.Identities {
			providers = append(providers, id.Provider)
		}
		if len(tr.User.Identities) != 1 || tr.User.Identities[0].Provider != "github" {
			t.Errorf("identities want [github], got %v", providers)
		}
		if tr.User.Identities[0].IdentityID == "" {
			t.Errorf("identity_id missing: %+v", tr.User.Identities[0])
		}
	})

	t.Run("code は単回使用: 二度目の交換は invalid_grant", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		code, _ := authorizeCode(t, f,
			"/auth/v1/authorize?provider=github&redirect_to="+url.QueryEscape(callback))

		exchange := func() int {
			rec := httptest.NewRecorder()
			handlertest.Serve(f, handler.Token, rec, handlertest.NewRequest(t, http.MethodPost,
				"/auth/v1/token?grant_type=pkce", map[string]string{"auth_code": code}))
			return rec.Code
		}
		if got := exchange(); got != http.StatusOK {
			t.Fatalf("first exchange: %d", got)
		}
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.Token, rec, handlertest.NewRequest(t, http.MethodPost,
			"/auth/v1/token?grant_type=pkce", map[string]string{"auth_code": code}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("second exchange status: %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"error":"invalid_grant"`) {
			t.Errorf("body=%s", rec.Body.String())
		}
	})

	t.Run("login_hint で email を固定でき、再ログインは同一ユーザーに寄せる", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		exchange := func() *handler.TokenResponse {
			code, rec := authorizeCode(t, f,
				"/auth/v1/authorize?provider=github&login_hint=dev%40example.com&redirect_to="+url.QueryEscape(callback))
			if rec.Code != http.StatusFound {
				t.Fatalf("authorize status: %d", rec.Code)
			}
			trec := httptest.NewRecorder()
			handlertest.Serve(f, handler.Token, trec, handlertest.NewRequest(t, http.MethodPost,
				"/auth/v1/token?grant_type=pkce", map[string]string{"auth_code": code}))
			if trec.Code != http.StatusOK {
				t.Fatalf("token status: %d body=%s", trec.Code, trec.Body.String())
			}
			var tr handler.TokenResponse
			handlertest.DecodeJSON(t, trec, &tr)
			return &tr
		}
		first := exchange()
		second := exchange()
		if first.User.Email != "dev@example.com" {
			t.Errorf("email want dev@example.com, got %q", first.User.Email)
		}
		if first.User.ID != second.User.ID {
			t.Errorf("login_hint should reuse the same user: %q vs %q", first.User.ID, second.User.ID)
		}
	})

	t.Run("provider 欠落は 422、redirect_to 欠落は 422", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		cases := []struct{ name, target string }{
			{"provider欠落", "/auth/v1/authorize?redirect_to=" + url.QueryEscape(callback)},
			{"redirect_to欠落", "/auth/v1/authorize?provider=github"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rec := httptest.NewRecorder()
				handlertest.Serve(f, handler.Authorize, rec, handlertest.NewRequest(t, http.MethodGet, tc.target, nil))
				if rec.Code != http.StatusUnprocessableEntity {
					t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
				}
			})
		}
	})

	t.Run("未知の auth_code は invalid_grant、auth_code 欠落は invalid_request", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.Token, rec, handlertest.NewRequest(t, http.MethodPost,
			"/auth/v1/token?grant_type=pkce", map[string]string{"auth_code": "nope"}))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error":"invalid_grant"`) {
			t.Errorf("unknown code: status=%d body=%s", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		handlertest.Serve(f, handler.Token, rec, handlertest.NewRequest(t, http.MethodPost,
			"/auth/v1/token?grant_type=pkce", map[string]string{"code_verifier": "v"}))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error":"invalid_request"`) {
			t.Errorf("missing auth_code: status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}
