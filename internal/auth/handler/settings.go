package handler

import "net/http"

func Settings(c *Context) {
	c.JSON(http.StatusOK, map[string]any{
		"external": map[string]bool{
			"anonymous_users": false,
			"email":           true,
			"phone":           false,
		},
		"disable_signup":     false,
		"mailer_autoconfirm": true,
		"phone_autoconfirm":  false,
		"sms_provider":       "",
		"saml_enabled":       false,
	})
}
