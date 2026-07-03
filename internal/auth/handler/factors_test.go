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

// enroll is a helper that registers a passkey factor and returns its factor id.
func enroll(t *testing.T, f *handler.Factory, bearer string) string {
	t.Helper()
	req := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/factors", map[string]string{
		"factor_type": "webauthn", "friendly_name": "Key",
	})
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	handlertest.Serve(f, handler.EnrollFactor, rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll status: %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	handlertest.DecodeJSON(t, rec, &resp)
	if resp.ID == "" || resp.Type != "webauthn" {
		t.Fatalf("enroll response: %+v", resp)
	}
	return resp.ID
}

func TestPasskeyFlow(t *testing.T) {
	t.Run("enroll -> challenge -> verify promotes to aal2 and marks the factor verified", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")

		factorID := enroll(t, f, seeded.AccessToken)

		// challenge
		chReq := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/factors/"+factorID+"/challenge", nil, "factorId", factorID)
		chReq.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		chRec := httptest.NewRecorder()
		handlertest.Serve(f, handler.ChallengeFactor, chRec, chReq)
		if chRec.Code != http.StatusOK {
			t.Fatalf("challenge status: %d body=%s", chRec.Code, chRec.Body.String())
		}
		var chResp struct {
			ID       string `json:"id"`
			WebAuthn struct {
				CredentialCreationOptions map[string]any `json:"credential_creation_options"`
			} `json:"web_authn"`
		}
		handlertest.DecodeJSON(t, chRec, &chResp)
		if chResp.ID == "" {
			t.Fatalf("no challenge id: %s", chRec.Body.String())
		}
		if chResp.WebAuthn.CredentialCreationOptions == nil {
			t.Error("unverified factor must return credential_creation_options")
		}

		// verify
		vReq := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/factors/"+factorID+"/verify", map[string]any{
			"challenge_id":        chResp.ID,
			"credential_response": map[string]any{"id": "fake", "rawId": "fake"},
		}, "factorId", factorID)
		vReq.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		vRec := httptest.NewRecorder()
		handlertest.Serve(f, handler.VerifyFactor, vRec, vReq)
		if vRec.Code != http.StatusOK {
			t.Fatalf("verify status: %d body=%s", vRec.Code, vRec.Body.String())
		}
		var tr handler.TokenResponse
		handlertest.DecodeJSON(t, vRec, &tr)
		if tr.AccessToken == "" || tr.RefreshToken == "" {
			t.Fatalf("verify must return new token pair: %+v", tr)
		}
		claims, err := tk.Verify(tr.AccessToken)
		if err != nil {
			t.Fatalf("verify token: %v", err)
		}
		if claims.AAL != "aal2" {
			t.Errorf("aal must be aal2 after passkey verify: %s", claims.AAL)
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

		// getUser: the factor appears as verified
		uReq := handlertest.NewRequest(t, http.MethodGet, "/auth/v1/user", nil)
		uReq.Header.Set("Authorization", "Bearer "+tr.AccessToken)
		uRec := httptest.NewRecorder()
		handlertest.Serve(f, handler.GetUser, uRec, uReq)
		var user store.User
		handlertest.DecodeJSON(t, uRec, &user)
		if len(user.Factors) != 1 || user.Factors[0].Status != "verified" {
			t.Fatalf("factor should be verified on user: %+v", user.Factors)
		}
	})

	t.Run("re-authentication: a verified factor's challenge returns request options", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
		factorID := enroll(t, f, seeded.AccessToken)
		if _, err := st.VerifyFactor(factorID); err != nil {
			t.Fatalf("VerifyFactor: %v", err)
		}

		chReq := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/factors/"+factorID+"/challenge", nil, "factorId", factorID)
		chReq.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		chRec := httptest.NewRecorder()
		handlertest.Serve(f, handler.ChallengeFactor, chRec, chReq)
		if !strings.Contains(chRec.Body.String(), "credential_request_options") {
			t.Errorf("verified factor must return credential_request_options: %s", chRec.Body.String())
		}
	})

	t.Run("unenroll removes the factor", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
		factorID := enroll(t, f, seeded.AccessToken)

		dReq := handlertest.NewRequest(t, http.MethodDelete, "/auth/v1/factors/"+factorID, nil, "factorId", factorID)
		dReq.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		dRec := httptest.NewRecorder()
		handlertest.Serve(f, handler.UnenrollFactor, dRec, dReq)
		if dRec.Code != http.StatusOK {
			t.Fatalf("unenroll status: %d", dRec.Code)
		}
		if _, ok := st.GetFactor(factorID); ok {
			t.Error("factor still present after unenroll")
		}
	})
}

// TestEnrollFactorValidation table-drives the EnrollFactor rejection paths that
// share one setup (a seeded user with an existing "Key" factor). Each case only
// varies the request body and whether a Bearer is attached.
func TestEnrollFactorValidation(t *testing.T) {
	cases := []struct {
		name       string
		body       map[string]string
		withBearer bool
		wantStatus int
		wantCode   string
	}{
		{
			name:       "missing Bearer returns 401 no_authorization",
			body:       map[string]string{"factor_type": "webauthn"},
			withBearer: false,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "no_authorization",
		},
		{
			name:       "unsupported factor_type returns 422 mfa_factor_type_not_supported",
			body:       map[string]string{"factor_type": "totp"},
			withBearer: true,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "mfa_factor_type_not_supported",
		},
		{
			name:       "duplicate friendly_name returns 422 mfa_factor_name_conflict",
			body:       map[string]string{"factor_type": "webauthn", "friendly_name": "Key"},
			withBearer: true,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "mfa_factor_name_conflict",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := handlertest.NewStore(nil)
			tk := handlertest.NewTokens(st, nil)
			f := handler.NewFactory(st, tk)
			seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
			enroll(t, f, seeded.AccessToken) // pre-existing "Key" factor for the conflict case

			req := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/factors", c.body)
			if c.withBearer {
				req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
			}
			rec := httptest.NewRecorder()
			handlertest.Serve(f, handler.EnrollFactor, rec, req)

			if rec.Code != c.wantStatus {
				t.Fatalf("status: got=%d want=%d body=%s", rec.Code, c.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), c.wantCode) {
				t.Errorf("body must contain %q: %s", c.wantCode, rec.Body.String())
			}
		})
	}
}

// The challenge/verify not-found paths hit different handlers with different
// setups, so they stay as focused subtests rather than a table with per-row
// handler funcs.
func TestPasskeyChallengeVerifyNotFound(t *testing.T) {
	t.Run("verify with an unknown challenge_id returns 404 mfa_challenge_not_found", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
		factorID := enroll(t, f, seeded.AccessToken)

		vReq := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/factors/"+factorID+"/verify", map[string]any{
			"challenge_id": "bogus",
		}, "factorId", factorID)
		vReq.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		vRec := httptest.NewRecorder()
		handlertest.Serve(f, handler.VerifyFactor, vRec, vReq)
		if vRec.Code != http.StatusNotFound {
			t.Fatalf("status: %d", vRec.Code)
		}
		if !strings.Contains(vRec.Body.String(), "mfa_challenge_not_found") {
			t.Errorf("body: %s", vRec.Body.String())
		}
	})

	t.Run("challenging another user's factor returns 404 mfa_factor_not_found", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		owner := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
		other := handlertest.Seed(t, st, tk, "bob@example.com", "password123")
		factorID := enroll(t, f, owner.AccessToken)

		chReq := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/factors/"+factorID+"/challenge", nil, "factorId", factorID)
		chReq.Header.Set("Authorization", "Bearer "+other.AccessToken)
		chRec := httptest.NewRecorder()
		handlertest.Serve(f, handler.ChallengeFactor, chRec, chReq)
		if chRec.Code != http.StatusNotFound {
			t.Fatalf("status: %d", chRec.Code)
		}
		if !strings.Contains(chRec.Body.String(), "mfa_factor_not_found") {
			t.Errorf("body: %s", chRec.Body.String())
		}
	})
}
