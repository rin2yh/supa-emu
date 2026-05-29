package handler

func Logout(c *Context) {
	// GoTrue は logout を冪等として扱い、Bearer 無し/期限切れでも 204 を返す。
	// exp 検証を絡めると expired token で revoke が走らず、同 session の refresh_token が
	// そのまま使えてしまうため、署名のみ検証して SessionID を取り出す。
	if token := c.Bearer(); token != "" {
		if claims, err := c.tokens.VerifyIgnoringExpiry(token); err == nil && claims.SessionID != "" {
			c.store.RevokeRefreshTokensBySession(claims.SessionID)
		}
	}
	c.NoContent()
}
