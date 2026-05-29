package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/handler/handlertest"
)

func TestReset(t *testing.T) {
	t.Run("204 を返し Store が空になる", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		handlertest.Seed(t, st, tk, "alice@example.com", "password123")

		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.Reset, rec, handlertest.NewRequest(t, http.MethodPost, "/__emulator/reset", nil))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: %d", rec.Code)
		}
		if got := len(st.Snapshot().Users); got != 0 {
			t.Errorf("users remain: %d", got)
		}
	})
}
