package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/rin2yh/supa-emu/internal/auth/store"
)

type passwordGrantRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshGrantRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Token is the /auth/v1/token dispatcher, keyed on grant_type:
//   - password       signInWithPassword (email + password)
//   - refresh_token  refreshSession (rotating refresh tokens)
//   - pkce           exchangeCodeForSession (OAuth code exchange; see oauth.go)
func Token(c *Context) {
	switch c.Query("grant_type") {
	case "password":
		tokenPassword(c)
	case "refresh_token":
		tokenRefresh(c)
	case "pkce":
		tokenPKCE(c)
	default:
		c.OAuth(http.StatusBadRequest, "unsupported_grant_type", "grant_type is required")
	}
}

func tokenPassword(c *Context) {
	var req passwordGrantRequest
	if err := c.ReadJSON(&req); err != nil {
		c.OAuth(http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	// signup 側で TrimSpace してから保存するので、login も同じ正規化を行わないと
	// トレーリングスペース付き email でログインできない非対称が生まれる。
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || req.Password == "" {
		c.OAuth(http.StatusBadRequest, "invalid_grant", "Invalid login credentials")
		return
	}

	u, ok := c.store.FindUserByEmail(req.Email)
	if !ok || !store.VerifyPassword(u.PasswordHash, req.Password) {
		c.OAuth(http.StatusBadRequest, "invalid_grant", "Invalid login credentials")
		return
	}

	// 並行 DeleteUser で消えていたら ok=false。更新後の clone をそのまま Issue に渡す。
	fresh, ok := c.store.UpdateLastSignIn(u.ID)
	if !ok {
		c.OAuth(http.StatusBadRequest, "invalid_grant", "Invalid login credentials")
		return
	}

	tr, err := c.tokens.Issue(fresh)
	if err != nil {
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, tr)
}

func tokenRefresh(c *Context) {
	var req refreshGrantRequest
	if err := c.ReadJSON(&req); err != nil {
		c.OAuth(http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	if req.RefreshToken == "" {
		c.OAuth(http.StatusBadRequest, "invalid_grant", "Invalid Refresh Token")
		return
	}

	newRT, u, err := c.store.ConsumeRefreshToken(req.RefreshToken)
	if err != nil {
		if errors.Is(err, store.ErrInvalidRefreshToken) {
			c.OAuth(http.StatusBadRequest, "invalid_grant", "Invalid Refresh Token")
			return
		}
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}

	tr, err := c.tokens.Build(u, newRT.SessionID, newRT.Token)
	if err != nil {
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, tr)
}
