package handler

import (
	"net/http"
	"strings"

	"github.com/rin2yh/supa-emu/internal/auth/store"
)

type seedUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func SeedUser(c *Context) {
	var req seedUserRequest
	if err := c.ReadJSON(&req); err != nil {
		c.Error(http.StatusBadRequest, "invalid request body")
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || req.Password == "" {
		c.Error(http.StatusBadRequest, "email and password are required")
		return
	}
	hash, err := store.HashPassword(req.Password)
	if err != nil {
		c.Error(http.StatusInternalServerError, err.Error())
		return
	}
	u, err := c.store.CreateUser(req.Email, hash)
	if err != nil {
		c.Error(http.StatusConflict, err.Error())
		return
	}
	c.JSON(http.StatusCreated, u)
}
