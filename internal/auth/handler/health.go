package handler

import "net/http"

func Health(c *Context) {
	c.JSON(http.StatusOK, map[string]any{
		"version":     "v2.150.0",
		"name":        "GoTrue",
		"description": "GoTrue is a user registration and authentication API (emulator)",
	})
}
