package handler

import (
	"fmt"
	"net/http"
	"strconv"
)

func AdminListUsers(c *Context) {
	page, _ := strconv.Atoi(c.Query("page"))
	if page <= 0 {
		page = 1
	}
	perPage, _ := strconv.Atoi(c.Query("per_page"))
	if perPage <= 0 {
		perPage = 50
	}

	users, total := c.store.ListUsers((page-1)*perPage, perPage)

	// supabase-js GoTrueAdminApi.listUsers は x-total-count と Link ヘッダから
	// nextPage / lastPage / total を組み立てる。
	c.Header().Set("x-total-count", strconv.Itoa(total))
	if link := paginationLinkHeader(c.Request(), page, perPage, total); link != "" {
		c.Header().Set("Link", link)
	}

	c.JSON(http.StatusOK, map[string]any{
		"users": users,
		"aud":   "authenticated",
	})
}

// paginationLinkHeader は単一ページでも rel="last" を必ず付ける。
// supabase-js (GoTrueAdminApi.listUsers) は Link が空のとき pagination.total を 0 にしてしまうため、
// 本物 GoTrue と同じく rel="last" を常時出す。
func paginationLinkHeader(r *http.Request, page, perPage, total int) string {
	lastPage := (total + perPage - 1) / perPage
	if lastPage < 1 {
		lastPage = 1
	}
	base := r.URL.Path
	links := ""
	if page < lastPage {
		links += fmt.Sprintf(`<%s?page=%d&per_page=%d>; rel="next"`, base, page+1, perPage)
	}
	if links != "" {
		links += ", "
	}
	links += fmt.Sprintf(`<%s?page=%d&per_page=%d>; rel="last"`, base, lastPage, perPage)
	return links
}
