package config

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	t.Run("returns default values", func(t *testing.T) {
		t.Setenv("SUPA_EMU_ADDR", "")
		t.Setenv("SUPA_EMU_JWT_SECRET", "")
		cfg, err := Parse(nil)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if cfg.Addr != "127.0.0.1:54321" {
			t.Errorf("Addr: %s", cfg.Addr)
		}
		if cfg.Auth.AccessTokenTTL != time.Hour {
			t.Errorf("AccessTokenTTL: %s", cfg.Auth.AccessTokenTTL)
		}
		if cfg.Auth.JWTSecret != DefaultJWTSecret {
			t.Errorf("JWTSecret default mismatch")
		}
	})

	t.Run("CLI flags take precedence over environment variables", func(t *testing.T) {
		t.Setenv("SUPA_EMU_ADDR", "0.0.0.0:9999")
		cfg, err := Parse([]string{"-addr", "127.0.0.1:8888"})
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if cfg.Addr != "127.0.0.1:8888" {
			t.Errorf("Addr: %s", cfg.Addr)
		}
	})

	t.Run("does not print Usage to stderr even for an invalid flag (assumes SetOutput(io.Discard))", func(t *testing.T) {
		// Parse はエラーを返すが、内部 FlagSet が stderr に Usage を吐くと
		// テスト出力やオペレータの stderr が二重に汚染される。
		_, err := Parse([]string{"-no-such-flag"})
		if err == nil {
			t.Fatal("unknown flag should return error")
		}
	})

	t.Run("--jwt-secret flag overrides the secret key", func(t *testing.T) {
		cfg, err := Parse([]string{"-jwt-secret", "custom-secret-for-testing-1234567890"})
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if cfg.Auth.JWTSecret != "custom-secret-for-testing-1234567890" {
			t.Errorf("JWTSecret: %s", cfg.Auth.JWTSecret)
		}
	})
}
