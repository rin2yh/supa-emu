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
	"github.com/rin2yh/supa-emu/internal/auth/store"
	"github.com/rin2yh/supa-emu/internal/config"
)

func TestLinkIdentityAuthorize(t *testing.T) {
	const target = "/auth/v1/user/identities/authorize?provider=github" +
		"&code_challenge=abc123&code_challenge_method=s256" +
		"&redirect_to=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback&skip_http_redirect=true"

	t.Run("success: skip_http_redirect=true returns 200 with { url }", func(t *testing.T) {
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

	t.Run("without skip_http_redirect returns 302 with Location", func(t *testing.T) {
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

	t.Run("a non-github provider also resolves to the same local authorize", func(t *testing.T) {
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

	t.Run("a trailing-slash issuer does not produce a double slash", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		// Issuer with a trailing slash must not produce "...//authorize".
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

	t.Run("missing provider is 422 validation_failed", func(t *testing.T) {
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

	t.Run("auth failure error-code classification", func(t *testing.T) {
		cases := []struct {
			name          string
			setHeader     func(r *http.Request, validToken string)
			deleteUser    bool
			wantErrorCode string
		}{
			{
				name:          "missing Authorization is no_authorization",
				setHeader:     func(*http.Request, string) {},
				wantErrorCode: "no_authorization",
			},
			{
				name:          "a bad-signature Bearer is bad_jwt",
				setHeader:     func(r *http.Request, _ string) { r.Header.Set("Authorization", "Bearer not-a-jwt") },
				wantErrorCode: "bad_jwt",
			},
			{
				name: "a deleted user is session_not_found",
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

func TestUnlinkIdentity(t *testing.T) {
	// addGithubIdentity attaches a github identity and returns its identity_id
	// (the value unlinkIdentity targets).
	addGithubIdentity := func(t *testing.T, st *store.Store, userID string) string {
		t.Helper()
		u, err := st.AddIdentity(userID, "github", map[string]any{"sub": "gh-123"})
		if err != nil {
			t.Fatalf("AddIdentity: %v", err)
		}
		for _, id := range u.Identities {
			if id.Provider == "github" {
				return id.IdentityID
			}
		}
		t.Fatalf("github identity not found after AddIdentity")
		return ""
	}

	t.Run("success: a seeded github identity can be unlinked with 204", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
		githubID := addGithubIdentity(t, st, seeded.User.ID)

		req := handlertest.NewRequest(t, http.MethodDelete,
			"/auth/v1/user/identities/"+githubID, nil, "identity_id", githubID)
		req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.UnlinkIdentity, rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); body != "" {
			t.Errorf("204 body want empty, got %q", body)
		}
		// The github identity must be gone; only email remains.
		u, ok := st.FindUserByID(seeded.User.ID)
		if !ok {
			t.Fatalf("user gone")
		}
		for _, id := range u.Identities {
			if id.Provider == "github" {
				t.Errorf("github identity still present: %+v", id)
			}
		}
	})

	t.Run("the only identity cannot be unlinked: 422 single_identity_not_deletable", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
		// The user has only its default email identity.
		emailIdentityID := seeded.User.Identities[0].IdentityID

		req := handlertest.NewRequest(t, http.MethodDelete,
			"/auth/v1/user/identities/"+emailIdentityID, nil, "identity_id", emailIdentityID)
		req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.UnlinkIdentity, rec, req)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"error_code":"single_identity_not_deletable"`) {
			t.Errorf("body=%s", rec.Body.String())
		}
	})

	t.Run("an unknown identity_id is 404 identity_not_found", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")

		req := handlertest.NewRequest(t, http.MethodDelete,
			"/auth/v1/user/identities/does-not-exist", nil, "identity_id", "does-not-exist")
		req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.UnlinkIdentity, rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"error_code":"identity_not_found"`) {
			t.Errorf("body=%s", rec.Body.String())
		}
	})

	t.Run("missing Authorization is 401 no_authorization", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)

		req := handlertest.NewRequest(t, http.MethodDelete,
			"/auth/v1/user/identities/whatever", nil, "identity_id", "whatever")
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.UnlinkIdentity, rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status: %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"error_code":"no_authorization"`) {
			t.Errorf("body=%s", rec.Body.String())
		}
	})
}
