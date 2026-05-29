package handler

import "net/http"

// catch-all。デフォルトの http.NotFoundHandler は text/plain で X-Supabase-Api-Version も
// 無いため、supabase-js の typed error マッピングが効かない。
func NotFound(c *Context) {
	c.ErrorCode(http.StatusNotFound, "not_found",
		"endpoint not found: "+c.Request().Method+" "+c.Request().URL.Path)
}
