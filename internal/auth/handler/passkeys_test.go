package handler_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rin2yh/supa-emu/internal/auth/handler"
	"github.com/rin2yh/supa-emu/internal/auth/handler/handlertest"
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

// listPasskeys calls GET /auth/v1/passkeys for the bearer and returns the decoded
// top-level array, failing the test if the status is not 200.
func listPasskeys(t *testing.T, f *handler.Factory, bearer string) []map[string]any {
	t.Helper()
	req := handlertest.NewRequest(t, http.MethodGet, "/auth/v1/passkeys", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	handlertest.Serve(f, handler.PasskeyList, rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status: %d body=%s", rec.Code, rec.Body.String())
	}
	var list []map[string]any
	handlertest.DecodeJSON(t, rec, &list)
	return list
}

func TestPasskeyList(t *testing.T) {
	t.Run("returns the caller's passkeys as a top-level JSON array", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
		id := registerPasskey(t, f, seeded.AccessToken, "cred-list-1", "My device")

		// The body must be a top-level array (not wrapped under a key), since
		// supabase-js auth.passkey.list() hands the raw array back as PasskeyListItem[].
		list := listPasskeys(t, f, seeded.AccessToken)
		if len(list) != 1 {
			t.Fatalf("expected 1 passkey, got %d: %+v", len(list), list)
		}
		item := list[0]
		if item["id"] != id {
			t.Errorf("id: got=%v want=%q", item["id"], id)
		}
		if item["friendly_name"] != "My device" {
			t.Errorf("friendly_name: got=%v", item["friendly_name"])
		}
		if _, present := item["created_at"]; !present {
			t.Error("created_at missing")
		}
		// Never authenticated, so last_used_at must be present and null.
		if v, present := item["last_used_at"]; !present || v != nil {
			t.Errorf("last_used_at: present=%v value=%v (want present, null)", present, v)
		}
	})

	t.Run("without a Bearer returns 401 no_authorization", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.PasskeyList, rec,
			handlertest.NewRequest(t, http.MethodGet, "/auth/v1/passkeys", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status: %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "no_authorization") {
			t.Errorf("body: %s", rec.Body.String())
		}
	})

	t.Run("last_used_at is populated after a successful authentication", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
		registerPasskey(t, f, seeded.AccessToken, "cred-used-1", "My device")

		challengeID := optionsChallengeID(t, f, handler.PasskeyAuthenticationOptions, "", nil)
		vReq := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/passkeys/authentication/verify", map[string]any{
			"challenge_id": challengeID,
			"credential":   map[string]any{"id": "cred-used-1"},
		})
		vRec := httptest.NewRecorder()
		handlertest.Serve(f, handler.PasskeyAuthenticationVerify, vRec, vReq)
		if vRec.Code != http.StatusOK {
			t.Fatalf("authentication verify status: %d body=%s", vRec.Code, vRec.Body.String())
		}

		list := listPasskeys(t, f, seeded.AccessToken)
		if len(list) != 1 || list[0]["last_used_at"] == nil {
			t.Fatalf("last_used_at should be set after auth: %+v", list)
		}
	})
}

func TestPasskeyDelete(t *testing.T) {
	t.Run("deletes the caller's own passkey and removes it from the list", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
		id := registerPasskey(t, f, seeded.AccessToken, "cred-del-1", "My device")

		req := handlertest.NewRequest(t, http.MethodDelete, "/auth/v1/passkeys/"+id, nil, "id", id)
		req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.PasskeyDelete, rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			ID string `json:"id"`
		}
		handlertest.DecodeJSON(t, rec, &resp)
		if resp.ID != id {
			t.Errorf("id: got=%q want=%q", resp.ID, id)
		}

		// Now the list is empty.
		if list := listPasskeys(t, f, seeded.AccessToken); len(list) != 0 {
			t.Errorf("passkey not deleted: %+v", list)
		}
	})

	t.Run("another user's passkey returns 404 passkey_not_found", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		alice := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
		bob := handlertest.Seed(t, st, tk, "bob@example.com", "password123")
		bobKey := registerPasskey(t, f, bob.AccessToken, "cred-bob-1", "Bob device")

		req := handlertest.NewRequest(t, http.MethodDelete, "/auth/v1/passkeys/"+bobKey, nil, "id", bobKey)
		req.Header.Set("Authorization", "Bearer "+alice.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.PasskeyDelete, rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "passkey_not_found") {
			t.Errorf("body: %s", rec.Body.String())
		}
	})

	t.Run("without a Bearer returns 401 no_authorization", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.PasskeyDelete, rec,
			handlertest.NewRequest(t, http.MethodDelete, "/auth/v1/passkeys/some-id", nil, "id", "some-id"))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status: %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "no_authorization") {
			t.Errorf("body: %s", rec.Body.String())
		}
	})
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

		// The token response is returned at the top level (GoTrue shape), not
		// nested under "session" — supabase-js's _sessionResponse detects the
		// session via a top-level access_token, so nesting would resolve it to null.
		var resp handler.TokenResponse
		handlertest.DecodeJSON(t, vRec, &resp)
		if resp.AccessToken == "" || resp.RefreshToken == "" {
			t.Fatalf("no session tokens: %+v", resp)
		}
		if resp.User == nil || resp.User.Email != "alice@example.com" {
			t.Errorf("authenticated as wrong user: %+v", resp.User)
		}

		// The access_token must verify under the same key/issuer as a password
		// login, and carry aal1 + amr=[webauthn] (primary auth, not an aal2 upgrade).
		claims, err := tk.Verify(resp.AccessToken)
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

func TestPasskeySessionSharesPasswordSigning(t *testing.T) {
	t.Run("passkey and password access tokens verify under the same key and issuer", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		// Seed issues a password-login token (tk.Issue), the baseline to match.
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
		registerPasskey(t, f, seeded.AccessToken, "cred-share-1", "Key")

		challengeID := optionsChallengeID(t, f, handler.PasskeyAuthenticationOptions, "", nil)
		vReq := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/passkeys/authentication/verify", map[string]any{
			"challenge_id": challengeID,
			"credential":   map[string]any{"id": "cred-share-1"},
		})
		vRec := httptest.NewRecorder()
		handlertest.Serve(f, handler.PasskeyAuthenticationVerify, vRec, vReq)
		if vRec.Code != http.StatusOK {
			t.Fatalf("authentication verify status: %d body=%s", vRec.Code, vRec.Body.String())
		}
		var resp handler.TokenResponse
		handlertest.DecodeJSON(t, vRec, &resp)

		// Both tokens must verify under the same tokens instance. tk.Verify enforces
		// the signing key (HS256 secret) and the issuer (WithIssuer), so a passkey
		// token signed with a different key or issuer than password login would fail
		// here — which would break app-side getClaims().
		pwClaims, err := tk.Verify(seeded.AccessToken)
		if err != nil {
			t.Fatalf("verify password-login token: %v", err)
		}
		pkClaims, err := tk.Verify(resp.AccessToken)
		if err != nil {
			t.Fatalf("verify passkey token: %v", err)
		}
		if pkClaims.Issuer == "" || pkClaims.Issuer != pwClaims.Issuer {
			t.Errorf("issuer mismatch: passkey=%q password=%q", pkClaims.Issuer, pwClaims.Issuer)
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
