package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/store"
	"github.com/rin2yh/supa-emu/internal/config"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "supa-emu: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := config.Parse(args)
	if err != nil {
		return err
	}

	clock := time.Now
	st := store.New(store.Config{Clock: clock, ReuseInterval: cfg.Auth.ReuseInterval})
	tk := handler.NewTokens(st, cfg.Auth.JWTSecret, cfg.Auth.JWTIssuer, cfg.Auth.AccessTokenTTL, clock)
	f := handler.NewFactory(st, tk, handler.WithWebAuthn(handler.WebAuthnConfig{
		RPID:   cfg.Auth.WebAuthn.RPID,
		RPName: cfg.Auth.WebAuthn.RPName,
	}))

	mux := http.NewServeMux()
	mux.Handle("GET /auth/v1/health", f.Handle(handler.Health))
	mux.Handle("GET /auth/v1/settings", f.Handle(handler.Settings))
	mux.Handle("POST /auth/v1/signup", f.Handle(handler.Signup))
	mux.Handle("POST /auth/v1/token", f.Handle(handler.Token))
	mux.Handle("GET /auth/v1/user", f.Handle(handler.GetUser))
	mux.Handle("POST /auth/v1/logout", f.Handle(handler.Logout))
	// WebAuthn MFA (second factor): enroll -> challenge -> verify -> unenroll
	mux.Handle("POST /auth/v1/factors", f.Handle(handler.EnrollFactor))
	mux.Handle("POST /auth/v1/factors/{factorId}/challenge", f.Handle(handler.ChallengeFactor))
	mux.Handle("POST /auth/v1/factors/{factorId}/verify", f.Handle(handler.VerifyFactor))
	mux.Handle("DELETE /auth/v1/factors/{factorId}", f.Handle(handler.UnenrollFactor))
	// Passwordless passkeys (primary auth): registration + authentication ceremonies
	mux.Handle("POST /auth/v1/passkeys/registration/options", f.Handle(handler.PasskeyRegistrationOptions))
	mux.Handle("POST /auth/v1/passkeys/registration/verify", f.Handle(handler.PasskeyRegistrationVerify))
	mux.Handle("POST /auth/v1/passkeys/authentication/options", f.Handle(handler.PasskeyAuthenticationOptions))
	mux.Handle("POST /auth/v1/passkeys/authentication/verify", f.Handle(handler.PasskeyAuthenticationVerify))
	mux.Handle("GET /auth/v1/admin/users", f.Handle(handler.AdminListUsers))
	mux.Handle("DELETE /auth/v1/admin/users/{id}", f.Handle(handler.AdminDeleteUser))
	mux.Handle("POST /__emulator/reset", f.Handle(handler.Reset))
	mux.Handle("GET /__emulator/snapshot", f.Handle(handler.Snapshot))
	mux.Handle("POST /__emulator/users", f.Handle(handler.SeedUser))
	// Go 1.22 mux は具体性の高いパターンを優先するので "/" は既存ルートに干渉せず catch-all になる。
	mux.Handle("/", f.Handle(handler.NotFound))

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		_, _ = fmt.Fprintf(os.Stdout, "supa-emu listening on %s\n", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigCh:
	case err := <-errCh:
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}
