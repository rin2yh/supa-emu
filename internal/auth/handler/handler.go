package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/rin2yh/supa-emu/internal/auth/store"
)

// supabase-js v2 (2024-01-01 以降) が error_code を typed error にマップする条件として、
// X-Supabase-Api-Version ヘッダを全エラーレスポンスに付与する必要がある。
const apiVersion = "2024-01-01"

type Func func(*Context)

// WebAuthnConfig holds passkey (WebAuthn) Relying Party info carried in the
// credential creation / request options. Since the emulator does not verify
// signatures, the values are informational.
type WebAuthnConfig struct {
	RPID   string
	RPName string
}

func defaultWebAuthnConfig() WebAuthnConfig {
	return WebAuthnConfig{RPID: "localhost", RPName: "supa-emu"}
}

type Factory struct {
	store    *store.Store
	tokens   *Tokens
	webauthn WebAuthnConfig
}

// FactoryOption is an optional setting for NewFactory. It is variadic so existing
// callers (NewFactory(st, tk)) keep working.
type FactoryOption func(*Factory)

// WithWebAuthn injects the passkey Relying Party settings. When unset,
// defaultWebAuthnConfig applies.
func WithWebAuthn(cfg WebAuthnConfig) FactoryOption {
	return func(f *Factory) {
		if cfg.RPID != "" {
			f.webauthn.RPID = cfg.RPID
		}
		if cfg.RPName != "" {
			f.webauthn.RPName = cfg.RPName
		}
	}
}

func NewFactory(st *store.Store, tk *Tokens, opts ...FactoryOption) *Factory {
	f := &Factory{store: st, tokens: tk, webauthn: defaultWebAuthnConfig()}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

func (f *Factory) Handle(fn Func) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := &Context{w: w, r: r, store: f.store, tokens: f.tokens, webauthn: f.webauthn}
		// handler 内 panic を 500 + JSON エラーに変換し、connection reset を防ぐ。
		defer func() {
			if rec := recover(); rec != nil {
				fmt.Fprintf(os.Stderr, "supa-emu: handler panic: %v\n%s\n", rec, debug.Stack())
				c.ErrorCode(http.StatusInternalServerError, "unexpected_failure", "internal server error")
			}
		}()
		fn(c)
	})
}

// written フラグで JSON/NoContent/Error 系の二重呼び出しを no-op にし、
// superfluous WriteHeader / body 連結を防ぐ。
type Context struct {
	w        http.ResponseWriter
	r        *http.Request
	store    *store.Store
	tokens   *Tokens
	webauthn WebAuthnConfig
	written  bool
}

func (c *Context) Request() *http.Request   { return c.r }
func (c *Context) Header() http.Header      { return c.w.Header() }
func (c *Context) Path(name string) string  { return c.r.PathValue(name) }
func (c *Context) Query(name string) string { return c.r.URL.Query().Get(name) }

// supabase-js は gotrue_meta_security 等の追加フィールドを送るため DisallowUnknownFields は付けない。
func (c *Context) ReadJSON(dst any) error {
	return json.NewDecoder(c.r.Body).Decode(dst)
}

func (c *Context) Bearer() string {
	v := c.r.Header.Get("Authorization")
	if v == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(v, prefix) {
		return ""
	}
	return strings.TrimSpace(v[len(prefix):])
}

func (c *Context) JSON(status int, body any) {
	if c.written {
		return
	}
	c.written = true
	c.w.Header().Set("Content-Type", "application/json")
	c.w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(c.w).Encode(body); err != nil {
		// WriteHeader 既送のためレスポンスでは挽回不可。半端 JSON の事実だけ stderr に残す。
		fmt.Fprintf(os.Stderr, "supa-emu: response encode failed: %v\n", err)
	}
}

// RFC 7230 §3.3.2 に従い、204 では Content-Type / Content-Length を出さない。
func (c *Context) NoContent() {
	if c.written {
		return
	}
	c.written = true
	c.w.Header().Del("Content-Type")
	c.w.Header().Del("Content-Length")
	c.w.WriteHeader(http.StatusNoContent)
}

// Error / ErrorCode は同じ apiErrorBody（サインアップ系の {"code","error_code","msg"}）、
// OAuth は別形式の oauthErrorBody（トークン系の {"error","error_description"}）を返す。
//
// アプリ側の文字列マッチ判定（"already registered" / "Invalid login credentials" /
// "Auth session missing"）と整合させるため、msg / error_description の値は変更しないこと。
// Code は string で出す（supabase-js v2 strict path は typeof === 'string' を要求）。

type apiErrorBody struct {
	Code      string `json:"code"`
	ErrorCode string `json:"error_code,omitempty"`
	Msg       string `json:"msg"`
}

type oauthErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func (c *Context) Error(status int, msg string) {
	c.writeError(status, apiErrorBody{Code: strconv.Itoa(status), Msg: msg})
}

func (c *Context) ErrorCode(status int, errCode, msg string) {
	c.writeError(status, apiErrorBody{Code: strconv.Itoa(status), ErrorCode: errCode, Msg: msg})
}

func (c *Context) OAuth(status int, errCode, description string) {
	c.writeError(status, oauthErrorBody{Error: errCode, ErrorDescription: description})
}

// writeError は X-Supabase-Api-Version の付与とエラー JSON 書き出しを 1 箇所に集約する。
// 二重書き出しの抑止は c.JSON 側の written ガードに任せる。
func (c *Context) writeError(status int, body any) {
	c.w.Header().Set("X-Supabase-Api-Version", apiVersion)
	c.JSON(status, body)
}
