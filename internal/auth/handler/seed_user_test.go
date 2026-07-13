package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/handler/handlertest"
)

func TestSeedUser(t *testing.T) {
	t.Run("success: 201", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.SeedUser, rec, handlertest.NewRequest(t, http.MethodPost, "/__emulator/users", map[string]string{
			"email": "alice@example.com", "password": "password123",
		}))
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: %d", rec.Code)
		}
	})

	t.Run("identities attaches a github identity so linked:true can be verified", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.SeedUser, rec, handlertest.NewRequest(t, http.MethodPost, "/__emulator/users", map[string]any{
			"email": "alice@example.com", "password": "password123",
			"identities": []map[string]any{{"provider": "github"}},
		}))
		if rec.Code != http.StatusCreated {
			t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
		}
		var u struct {
			Identities []struct {
				IdentityID string `json:"identity_id"`
				Provider   string `json:"provider"`
			} `json:"identities"`
			AppMetadata map[string]any `json:"app_metadata"`
		}
		handlertest.DecodeJSON(t, rec, &u)

		var providers []string
		var githubIdentityID string
		for _, id := range u.Identities {
			providers = append(providers, id.Provider)
			if id.Provider == "github" {
				githubIdentityID = id.IdentityID
			}
		}
		// The default email identity plus the seeded github identity.
		if len(u.Identities) != 2 {
			t.Fatalf("identities want 2, got %v", providers)
		}
		if githubIdentityID == "" {
			t.Errorf("github identity missing identity_id: %v", u.Identities)
		}
		// app_metadata.providers must list both so linked:true holds.
		gotProviders, _ := u.AppMetadata["providers"].([]any)
		if len(gotProviders) != 2 {
			t.Errorf("app_metadata.providers want 2, got %v", u.AppMetadata["providers"])
		}
	})

	t.Run("a missing identity provider is 400", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.SeedUser, rec, handlertest.NewRequest(t, http.MethodPost, "/__emulator/users", map[string]any{
			"email": "alice@example.com", "password": "password123",
			"identities": []map[string]any{{"identity_data": map[string]any{"sub": "x"}}},
		}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("validation / duplicate", func(t *testing.T) {
		cases := []struct {
			name       string
			seed       bool
			body       map[string]string
			wantStatus int
		}{
			{name: "missing email is 400", body: map[string]string{"password": "password123"}, wantStatus: http.StatusBadRequest},
			{name: "missing password is 400", body: map[string]string{"email": "alice@example.com"}, wantStatus: http.StatusBadRequest},
			{name: "existing email is 409", seed: true, body: map[string]string{"email": "alice@example.com", "password": "password123"}, wantStatus: http.StatusConflict},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				st := handlertest.NewStore(nil)
				f := handler.NewFactory(st, handlertest.NewTokens(st, nil))
				if c.seed {
					handlertest.Serve(f, handler.SeedUser, httptest.NewRecorder(), handlertest.NewRequest(t, http.MethodPost, "/__emulator/users", map[string]string{
						"email": "alice@example.com", "password": "password123",
					}))
				}

				rec := httptest.NewRecorder()
				handlertest.Serve(f, handler.SeedUser, rec, handlertest.NewRequest(t, http.MethodPost, "/__emulator/users", c.body))
				if rec.Code != c.wantStatus {
					t.Fatalf("status: got=%d want=%d", rec.Code, c.wantStatus)
				}
			})
		}
	})
}
