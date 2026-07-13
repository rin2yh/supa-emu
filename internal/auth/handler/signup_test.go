package handler_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/handler/handlertest"
)

func TestSignup(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		t.Run("returns 200 with access_token / refresh_token / user", func(t *testing.T) {
			st := handlertest.NewStore(nil)
			f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

			rec := httptest.NewRecorder()
			handlertest.Serve(f, handler.Signup, rec, handlertest.NewRequest(t, http.MethodPost, "/auth/v1/signup", map[string]string{
				"email": "alice@example.com", "password": "password123",
			}))

			if rec.Code != http.StatusOK {
				t.Fatalf("status: %d", rec.Code)
			}
			var tr handler.TokenResponse
			handlertest.DecodeJSON(t, rec, &tr)
			if tr.AccessToken == "" || tr.RefreshToken == "" || tr.User == nil {
				t.Fatalf("missing fields: %+v", tr)
			}
			if tr.User.Email != "alice@example.com" {
				t.Errorf("email: %s", tr.User.Email)
			}
		})

		t.Run("persists the data field to the Store", func(t *testing.T) {
			st := handlertest.NewStore(nil)
			f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

			rec := httptest.NewRecorder()
			handlertest.Serve(f, handler.Signup, rec, handlertest.NewRequest(t, http.MethodPost, "/auth/v1/signup", map[string]any{
				"email": "alice@example.com", "password": "password123",
				"data": map[string]any{"nickname": "alice"},
			}))

			var tr handler.TokenResponse
			handlertest.DecodeJSON(t, rec, &tr)
			if got := tr.User.UserMetadata["nickname"]; got != "alice" {
				t.Errorf("response nickname: %v", got)
			}
			stored, _ := st.FindUserByID(tr.User.ID)
			if got := stored.UserMetadata["nickname"]; got != "alice" {
				t.Errorf("store nickname: %v", got)
			}
		})

		t.Run("stores email normalized to lowercase", func(t *testing.T) {
			st := handlertest.NewStore(nil)
			f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

			rec := httptest.NewRecorder()
			handlertest.Serve(f, handler.Signup, rec, handlertest.NewRequest(t, http.MethodPost, "/auth/v1/signup", map[string]string{
				"email": "Alice@Example.COM", "password": "password123",
			}))

			var tr handler.TokenResponse
			handlertest.DecodeJSON(t, rec, &tr)
			if tr.User.Email != "alice@example.com" {
				t.Errorf("email: %s", tr.User.Email)
			}
			if _, ok := st.FindUserByEmail("alice@example.com"); !ok {
				t.Error("lowercase lookup failed")
			}
		})
	})

	t.Run("validation failure", func(t *testing.T) {
		cases := []struct {
			name       string
			body       map[string]string
			wantStatus int
			wantMsg    string
		}{
			{name: "missing email returns 400", body: map[string]string{"password": "password123"}, wantStatus: http.StatusBadRequest, wantMsg: "required"},
			{name: "missing password returns 400", body: map[string]string{"email": "alice@example.com"}, wantStatus: http.StatusBadRequest, wantMsg: "required"},
			{name: "email without @ returns 400", body: map[string]string{"email": "no-at-sign", "password": "password123"}, wantStatus: http.StatusBadRequest, wantMsg: "invalid format"},
			{name: "password of 5 chars or fewer returns 422", body: map[string]string{"email": "alice@example.com", "password": "abc"}, wantStatus: http.StatusUnprocessableEntity, wantMsg: "at least 6 characters"},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				st := handlertest.NewStore(nil)
				f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

				rec := httptest.NewRecorder()
				handlertest.Serve(f, handler.Signup, rec, handlertest.NewRequest(t, http.MethodPost, "/auth/v1/signup", c.body))

				if rec.Code != c.wantStatus {
					t.Fatalf("status: got=%d want=%d", rec.Code, c.wantStatus)
				}
				if !strings.Contains(rec.Body.String(), c.wantMsg) {
					t.Errorf("body must contain %q: %s", c.wantMsg, rec.Body.String())
				}
			})
		}
	})

	t.Run("existing email", func(t *testing.T) {
		t.Run("returns 422 + 'already registered' (app-layer isUserAlreadyExistsError compatible)", func(t *testing.T) {
			st := handlertest.NewStore(nil)
			f := handler.NewFactory(st, handlertest.NewTokens(st, nil))
			body := map[string]string{"email": "alice@example.com", "password": "password123"}
			handlertest.Serve(f, handler.Signup, httptest.NewRecorder(), handlertest.NewRequest(t, http.MethodPost, "/auth/v1/signup", body))

			rec := httptest.NewRecorder()
			handlertest.Serve(f, handler.Signup, rec, handlertest.NewRequest(t, http.MethodPost, "/auth/v1/signup", body))
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status: %d", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "already registered") {
				t.Errorf("body: %s", rec.Body.String())
			}
		})
	})
}
