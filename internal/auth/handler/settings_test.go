package handler_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/handler/handlertest"
)

func TestSettings(t *testing.T) {
	t.Run("mailer_autoconfirm=true を返す", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.Settings, rec, handlertest.NewRequest(t, http.MethodGet, "/auth/v1/settings", nil))
		if !strings.Contains(rec.Body.String(), `"mailer_autoconfirm":true`) {
			t.Errorf("body: %s", rec.Body.String())
		}
	})
}
