package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/handler/handlertest"
)

func TestSeedUser(t *testing.T) {
	t.Run("正常系: 201", func(t *testing.T) {
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

	t.Run("バリデーション/重複", func(t *testing.T) {
		cases := []struct {
			name       string
			seed       bool
			body       map[string]string
			wantStatus int
		}{
			{name: "email欠落で400", body: map[string]string{"password": "password123"}, wantStatus: http.StatusBadRequest},
			{name: "password欠落で400", body: map[string]string{"email": "alice@example.com"}, wantStatus: http.StatusBadRequest},
			{name: "既存emailで409", seed: true, body: map[string]string{"email": "alice@example.com", "password": "password123"}, wantStatus: http.StatusConflict},
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
