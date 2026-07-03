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

// enroll は passkey factor を登録し factor id を返すヘルパ。
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
	t.Run("enroll → challenge → verify で aal2 に昇格し factor が verified になる", func(t *testing.T) {
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

		// getUser: factor が verified で現れる
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

	t.Run("再認証: verified factor の challenge は request options を返す", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
		factorID := enroll(t, f, seeded.AccessToken)
		if _, err := st.VerifyFactor(factorID, "cred"); err != nil {
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

	t.Run("unenroll で factor が消える", func(t *testing.T) {
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

func TestPasskeyValidation(t *testing.T) {
	t.Run("Bearer 無しの enroll は 401 no_authorization", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		f := handler.NewFactory(st, handlertest.NewTokens(st, nil))

		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.EnrollFactor, rec, handlertest.NewRequest(t, http.MethodPost, "/auth/v1/factors", map[string]string{
			"factor_type": "webauthn",
		}))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status: %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "no_authorization") {
			t.Errorf("body: %s", rec.Body.String())
		}
	})

	t.Run("未対応 factor_type は 422 mfa_factor_type_not_supported", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")

		req := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/factors", map[string]string{"factor_type": "totp"})
		req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.EnrollFactor, rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status: %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "mfa_factor_type_not_supported") {
			t.Errorf("body: %s", rec.Body.String())
		}
	})

	t.Run("friendly_name 重複は 422 mfa_factor_name_conflict", func(t *testing.T) {
		st := handlertest.NewStore(nil)
		tk := handlertest.NewTokens(st, nil)
		f := handler.NewFactory(st, tk)
		seeded := handlertest.Seed(t, st, tk, "alice@example.com", "password123")
		enroll(t, f, seeded.AccessToken)

		req := handlertest.NewRequest(t, http.MethodPost, "/auth/v1/factors", map[string]string{
			"factor_type": "webauthn", "friendly_name": "Key",
		})
		req.Header.Set("Authorization", "Bearer "+seeded.AccessToken)
		rec := httptest.NewRecorder()
		handlertest.Serve(f, handler.EnrollFactor, rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "mfa_factor_name_conflict") {
			t.Errorf("body: %s", rec.Body.String())
		}
	})

	t.Run("存在しない challenge_id での verify は 404 mfa_challenge_not_found", func(t *testing.T) {
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

	t.Run("他ユーザの factor への challenge は 404 mfa_factor_not_found", func(t *testing.T) {
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
