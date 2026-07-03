package handler_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/handler/handlertest"
	"github.com/rin2yh/supa-emu/internal/auth/store"
)

// optionsChallengeID serves a passkey options endpoint and returns its challenge_id.
func optionsChallengeID(t *testing.T, f *handler.Factory, fn handler.Func, bearer string, body any) string {
	t.Helper()
	req := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/passkeys/options", body)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	handlertest.Serve(f, fn, rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("options status: %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ChallengeID string         `json:"challenge_id"`
		Options     map[string]any `json:"options"`
		ExpiresAt   int64          `json:"expires_at"`
	}
	handlertest.DecodeJSON(t, rec, &resp)
	if resp.ChallengeID == "" || resp.Options == nil || resp.ExpiresAt == 0 {
		t.Fatalf("incomplete options response: %+v", resp)
	}
	return resp.ChallengeID
}

// registerPasskey runs a full registration ceremony for the bearer's user and
// returns the persisted passkey id.
func registerPasskey(t *testing.T, f *handler.Factory, bearer, credID, friendlyName string) string {
	t.Helper()
	challengeID := optionsChallengeID(t, f, handler.PasskeyRegistrationOptions, bearer,
		map[string]string{"friendly_name": friendlyName})

	req := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/passkeys/registration/verify", map[string]any{
		"challenge_id": challengeID,
		"credential":   map[string]any{"id": credID, "rawId": credID, "type": "public-key"},
	})
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	handlertest.Serve(f, handler.PasskeyRegistrationVerify, rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("registration verify status: %d body=%s", rec.Code, rec.Body.String())
	}
	var reg struct {
		ID           string `json:"id"`
		FriendlyName string `json:"friendly_name"`
	}
	handlertest.DecodeJSON(t, rec, &reg)
	if reg.ID == "" {
		t.Fatalf("registration returned no id: %s", rec.Body.String())
	}
	if reg.FriendlyName != friendlyName {
		t.Errorf("friendly_name: got=%q want=%q", reg.FriendlyName, friendlyName)
	}
	return reg.ID
}

func TestPasswordlessPasskeyFlow(t *testing.T) {
	t.Run("register then authenticate issues a new aal1 session for the passkey owner", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		// Seed provides an already-logged-in user so they can register a passkey.
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
		registerPasskey(t, f, seeded.AccessToken, "cred-flow-1", "My Laptop")

		// Authentication is unauthenticated: no Bearer.
		challengeID := optionsChallengeID(t, f, handler.PasskeyAuthenticationOptions, "", nil)
		vReq := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/passkeys/authentication/verify", map[string]any{
			"challenge_id": challengeID,
			"credential":   map[string]any{"id": "cred-flow-1", "type": "public-key"},
		})
		vRec := httptest.NewRecorder()
		handlertest.Serve(f, handler.PasskeyAuthenticationVerify, vRec, vReq)
		if vRec.Code != http.StatusOK {
			t.Fatalf("authentication verify status: %d body=%s", vRec.Code, vRec.Body.String())
		}

		var resp struct {
			Session handler.TokenResponse `json:"session"`
			User    store.User            `json:"user"`
		}
		handlertest.DecodeJSON(t, vRec, &resp)
		if resp.Session.AccessToken == "" || resp.Session.RefreshToken == "" {
			t.Fatalf("no session tokens: %+v", resp.Session)
		}
		if resp.User.Email != "alice@example.com" {
			t.Errorf("authenticated as wrong user: %s", resp.User.Email)
		}

		// The access_token must verify under the same key/issuer as a password
		// login, and carry aal1 + amr=[webauthn] (primary auth, not an aal2 upgrade).
		claims, err := tk.Verify(resp.Session.AccessToken)
		if err != nil {
			t.Fatalf("verify passkey access_token: %v", err)
		}
		if claims.AAL != "aal1" {
			t.Errorf("aal: got=%s want=aal1", claims.AAL)
		}
		hasWebAuthn := false
		for _, e := range claims.AMR {
			if e.Method == "webauthn" {
				hasWebAuthn = true
			}
		}
		if !hasWebAuthn {
			t.Errorf("amr must include webauthn: %+v", claims.AMR)
		}
		if claims.Subject != resp.User.ID {
			t.Errorf("token subject %s != user %s", claims.Subject, resp.User.ID)
		}
	})
}

func TestPasskeyRegistrationRequiresAuth(t *testing.T) {
	t.Run("registration/options without a Bearer returns 401 no_authorization", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.PasskeyRegistrationOptions, rec,
			handlertest.NewRequest(t, http.MethodPost, "/auth/v1/passkeys/registration/options", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status: %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "no_authorization") {
			t.Errorf("body: %s", rec.Body.String())
		}
	})
}

func TestPasskeyAuthenticationVerifyErrors(t *testing.T) {
	t.Run("an unregistered credential returns 401 invalid_credentials", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)

		challengeID := optionsChallengeID(t, f, handler.PasskeyAuthenticationOptions, "", nil)
		vReq := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/passkeys/authentication/verify", map[string]any{
			"challenge_id": challengeID,
			"credential":   map[string]any{"id": "never-registered"},
		})
		vRec := httptest.NewRecorder()
		handlertest.Serve(f, handler.PasskeyAuthenticationVerify, vRec, vReq)
		if vRec.Code != http.StatusUnauthorized {
			t.Fatalf("status: %d", vRec.Code)
		}
		if !strings.Contains(vRec.Body.String(), "invalid_credentials") {
			t.Errorf("body: %s", vRec.Body.String())
		}
	})

	t.Run("an unknown challenge_id returns 404 passkey_challenge_not_found", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		vReq := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/passkeys/authentication/verify", map[string]any{
			"challenge_id": "bogus",
			"credential":   map[string]any{"id": "whatever"},
		})
		vRec := httptest.NewRecorder()
		handlertest.Serve(f, handler.PasskeyAuthenticationVerify, vRec, vReq)
		if vRec.Code != http.StatusNotFound {
			t.Fatalf("status: %d", vRec.Code)
		}
		if !strings.Contains(vRec.Body.String(), "passkey_challenge_not_found") {
			t.Errorf("body: %s", vRec.Body.String())
		}
	})
}
