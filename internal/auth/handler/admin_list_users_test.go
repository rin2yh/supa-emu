package handler_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/handler/handlertest"
)

func TestAdminListUsers(t *testing.T) {
	t.Run("ページネーションヘッダ", func(t *testing.T) {
		cases := []struct {
			name        string
			seedEmails  []string
			query       string
			wantTotal   string
			mustContain []string
			mustExclude []string
		}{
			{
				name:        "1ページ目で next/last が両方付く",
				seedEmails:  []string{"a@example.com", "b@example.com", "c@example.com"},
				query:       "page=1&per_page=2",
				wantTotal:   "3",
				mustContain: []string{`rel="next"`, `rel="last"`},
			},
			{
				name:        "単一ページでも rel=\"last\" は必ず出る",
				seedEmails:  []string{"alice@example.com"},
				query:       "page=1&per_page=50",
				wantTotal:   "1",
				mustContain: []string{`rel="last"`},
				mustExclude: []string{`rel="next"`},
			},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				st := handlertest.NewStore(nil)
				tk := handlertest.NewTokens(st, nil)
				f := handler.NewFactory(st, tk)
				for _, e := range c.seedEmails {
					handlertest.Seed(t, st, tk, e, "password123")
				}

				rec := httptest.NewRecorder()
				handlertest.Serve(f, handler.AdminListUsers, rec, handlertest.NewRequest(t, http.MethodGet, "/auth/v1/admin/users?"+c.query, nil))

				if got := rec.Header().Get("x-total-count"); got != c.wantTotal {
					t.Errorf("x-total-count: got=%s want=%s", got, c.wantTotal)
				}
				link := rec.Header().Get("Link")
				for _, want := range c.mustContain {
					if !strings.Contains(link, want) {
						t.Errorf("Link must contain %q: %s", want, link)
					}
				}
				for _, no := range c.mustExclude {
					if strings.Contains(link, no) {
						t.Errorf("Link must NOT contain %q: %s", no, link)
					}
				}
			})
		}
	})

	t.Run("空ストアでも users:[] が返る", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.AdminListUsers, rec, handlertest.NewRequest(t, http.MethodGet, "/auth/v1/admin/users", nil))
		if !strings.Contains(rec.Body.String(), `"users":[]`) {
			t.Errorf("users must be empty array: %s", rec.Body.String())
		}
	})
}
