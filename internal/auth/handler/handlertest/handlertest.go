// Package handlertest は handler パッケージのテストで共用するヘルパ群を提供する。
package handlertest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/store"
	"github.com/rin2yh/supa-emu/internal/config"
)

const Issuer = "http://127.0.0.1:54321/auth/v1"

func NewStore(clock func() time.Time) *store.Store {
	return store.New(store.Config{Clock: clock, ReuseInterval: 10 * time.Second})
}

func NewTokens(st *store.Store, clock func() time.Time) *handler.Tokens {
	return handler.NewTokens(st, config.DefaultJWTSecret, Issuer, time.Hour, clock)
}

func Seed(t *testing.T, st *store.Store, tk *handler.Tokens, email, password string) *handler.TokenResponse {
	t.Helper()
	hash, _ := store.HashPassword(password)
	u, err := st.CreateUser(email, hash)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	resp, err := tk.Issue(u)
	if err != nil {
		t.Fatalf("seed issue: %v", err)
	}
	return resp
}

// paths は key, value, key, value... のペアで PathValue を直接埋める。
// 本番では ServeMux がパターンマッチで埋めるが、テストでは mux を通さないので手動で渡す。
func NewRequest(t *testing.T, method, target string, body any, paths ...string) *http.Request {
	t.Helper()
	if len(paths)%2 != 0 {
		t.Fatalf("NewRequest: paths must be key/value pairs, got %d args", len(paths))
	}
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, target, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i < len(paths); i += 2 {
		req.SetPathValue(paths[i], paths[i+1])
	}
	return req
}

func Serve(f *handler.Factory, fn handler.Func, rec *httptest.ResponseRecorder, req *http.Request) {
	f.Handle(fn).ServeHTTP(rec, req)
}

func DecodeJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(dst); err != nil {
		t.Fatalf("decode: %v", err)
	}
}
