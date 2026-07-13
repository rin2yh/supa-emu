package handler_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/handler/handlertest"
)

func TestSnapshot(t *testing.T) {
	t.Run("returns empty snake_case arrays for an empty store", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.Snapshot, rec, handlertest.NewRequest(t, http.MethodGet, "/__emulator/snapshot", nil))
		body := rec.Body.String()
		for _, key := range []string{`"users":[]`, `"sessions":[]`, `"refresh_tokens":[]`} {
			if !strings.Contains(body, key) {
				t.Errorf("snapshot must contain %s: %s", key, body)
			}
		}
	})
}
