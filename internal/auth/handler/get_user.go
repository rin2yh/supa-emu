package handler

import "net/http"

func GetUser(c *Context) {
	// 認証分類（no_authorization / bad_jwt / session_not_found）は requireUser に集約している。
	// no_authorization は認可ヘッダ欠落、session_not_found は署名通過後に user 消失した場合のみ。
	// いずれも supabase-js の cookie wipe 判定に対応する。
	u, _, ok := requireUser(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, u)
}
