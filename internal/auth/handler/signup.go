package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/rin2yh/supa-emu/internal/auth/store"
)

type signupRequest struct {
	Email    string         `json:"email"`
	Password string         `json:"password"`
	Data     map[string]any `json:"data"`
}

func Signup(c *Context) {
	var req signupRequest
	if err := c.ReadJSON(&req); err != nil {
		c.Error(http.StatusBadRequest, "invalid request body")
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || req.Password == "" {
		c.Error(http.StatusBadRequest, "email and password are required")
		return
	}
	if !strings.Contains(req.Email, "@") {
		c.Error(http.StatusBadRequest, "Unable to validate email address: invalid format")
		return
	}
	// GoTrue デフォルト password_min_length=6 と合わせる。アプリ層 Zod は min=8 を要求するため
	// エミュレータ直叩きしない限り 6-7 文字はアプリ側で先に弾かれる。
	if len(req.Password) < 6 {
		c.Error(http.StatusUnprocessableEntity, "Password should be at least 6 characters")
		return
	}

	hash, err := store.HashPassword(req.Password)
	if err != nil {
		c.Error(http.StatusInternalServerError, "failed to hash password")
		return
	}

	u, err := c.store.CreateUser(req.Email, hash)
	if err != nil {
		if errors.Is(err, store.ErrUserAlreadyExists) {
			// アプリ側 isUserAlreadyExistsError は "already registered" 包含判定なので変更不可
			c.Error(http.StatusUnprocessableEntity, "User already registered")
			return
		}
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}
	if len(req.Data) > 0 {
		if fresh, ok := c.store.SetUserMetadata(u.ID, req.Data); ok {
			u = fresh
		}
	}

	// mailer_autoconfirm=true 想定。GoTrue は AccessTokenResponse をそのまま返し、
	// supabase-js が {data:{user, session}} に再構成する。
	session, err := c.tokens.Issue(u)
	if err != nil {
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, session)
}
