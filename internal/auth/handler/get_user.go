package handler

import "net/http"

func GetUser(c *Context) {
	token := c.Bearer()
	if token == "" {
		// supabase-js は session_not_found に対し _removeSession() で SSR cookie を wipe する。
		// 認可ヘッダ自体が無いのは「セッション喪失」ではないので no_authorization で分離する。
		c.ErrorCode(http.StatusUnauthorized, "no_authorization",
			"No Authorization header included in request")
		return
	}
	claims, err := c.tokens.Verify(token)
	if err != nil {
		// 署名不正・期限切れ・issuer mismatch は全部 bad_jwt（cookie wipe 対象外）。
		c.ErrorCode(http.StatusUnauthorized, "bad_jwt", "invalid JWT: "+err.Error())
		return
	}
	u, ok := c.store.FindUserByID(claims.Subject)
	if !ok {
		// 署名は通ったが該当 user が消えている状態だけが本当の session_not_found。
		c.ErrorCode(http.StatusUnauthorized, "session_not_found",
			"AuthSessionMissingError: Auth session missing!")
		return
	}
	c.JSON(http.StatusOK, u)
}
