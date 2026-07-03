package handler

import "net/http"

func GetUser(c *Context) {
	// The auth classification (no_authorization / bad_jwt / session_not_found) is
	// centralized in requireUser. Only session_not_found (valid signature, user
	// gone) triggers supabase-js's _removeSession() SSR cookie wipe;
	// no_authorization (missing header) and bad_jwt (bad signature / expiry /
	// issuer) are kept distinct precisely so they do not wipe.
	u, _, ok := requireUser(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, u)
}
