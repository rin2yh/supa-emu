package handler_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/rin2yh/supa-emu/internal/auth/handler/handlertest"
	"github.com/rin2yh/supa-emu/internal/auth/store"
	"github.com/rin2yh/supa-emu/internal/config"
)

func TestTokensBuild_AudIsString(t *testing.T) {
	// 旧実装は jwtv5.RegisteredClaims を使っていたため aud が JSON 配列で出ていた。
	// 本物 GoTrue は単一 string で出すため、payload を decode して string であることを検証する。
	st := handlertest.NewStore(nil)
	tk := handlertest.NewTokens(st, nil)
	u, _ := st.CreateUser("alice@example.com", mustHash(t, "password123"))

	resp, err := tk.Issue(u)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parts := strings.Split(resp.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %s", resp.AccessToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, isString := raw["aud"].(string); !isString {
		t.Fatalf("aud must be string, got %T (%v)", raw["aud"], raw["aud"])
	}
	if raw["aud"] != "authenticated" {
		t.Errorf("aud value: %v", raw["aud"])
	}
}

func TestTokensVerify_RejectsForeignIssuer(t *testing.T) {
	// 公開定数 DefaultJWTSecret で署名された anon/service_role JWT は別 issuer なので、
	// emulator の Verify で reject される必要がある。WithIssuer 抜けの再発防止。
	st := handlertest.NewStore(nil)
	tk := handlertest.NewTokens(st, nil)

	foreign := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, jwtv5.MapClaims{
		"iss":  "supabase-demo",
		"role": "service_role",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	signed, err := foreign.SignedString([]byte(config.DefaultJWTSecret))
	if err != nil {
		t.Fatalf("sign foreign: %v", err)
	}
	if _, err := tk.Verify(signed); err == nil {
		t.Fatal("Verify must reject token with different issuer")
	}
}

func TestTokensIssue_AtomicWithDeleteUser(t *testing.T) {
	// IssueSession を 1 ロックで実行するため、session 単独の leak が起きないことを確認。
	// 削除済みユーザに対しては ErrUserNotFound を返し、session/refresh_token は store に残らない。
	st := handlertest.NewStore(nil)
	tk := handlertest.NewTokens(st, nil)
	u, _ := st.CreateUser("alice@example.com", mustHash(t, "password123"))
	if err := st.DeleteUser(u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	if _, err := tk.Issue(u); err == nil {
		t.Fatal("Issue should fail for deleted user")
	}
	snap := st.Snapshot()
	if len(snap.Sessions) != 0 {
		t.Errorf("session leak: %+v", snap.Sessions)
	}
}

func mustHash(t *testing.T, pw string) []byte {
	t.Helper()
	h, err := store.HashPassword(pw)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return h
}
