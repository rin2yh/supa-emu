package handler

import (
	"errors"
	"net/http"

	"github.com/rin2yh/supa-emu/internal/auth/store"
)

func AdminDeleteUser(c *Context) {
	id := c.Path("id")
	if id == "" {
		c.Error(http.StatusBadRequest, "user id is required")
		return
	}
	if err := c.store.DeleteUser(id); err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			c.Error(http.StatusNotFound, "User not found")
			return
		}
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]any{})
}
