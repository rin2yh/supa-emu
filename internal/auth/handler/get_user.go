package handler

import "net/http"

func GetUser(c *Context) {
	// The auth classification (no_authorization / bad_jwt / session_not_found) is
	// centralized in requireUser. no_authorization means the Authorization header
	// is missing; session_not_found only when the user is gone after a valid
	// signature. Both map to supabase-js's cookie-wipe decision.
	u, _, ok := requireUser(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, u)
}
