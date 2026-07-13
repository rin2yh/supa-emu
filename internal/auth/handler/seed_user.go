package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/rin2yh/supa-emu/internal/auth/store"
)

type seedIdentity struct {
	Provider     string         `json:"provider"`
	IdentityData map[string]any `json:"identity_data"`
}

type seedUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	// Identities optionally seeds extra OAuth provider identities (e.g.
	// [{ "provider": "github" }]) on top of the default email identity, so a test
	// can assert getUserIdentities / linked:true without a real OAuth round trip.
	Identities []seedIdentity `json:"identities"`
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

	for _, id := range req.Identities {
		provider := strings.TrimSpace(id.Provider)
		if provider == "" {
			c.Error(http.StatusBadRequest, "identity provider is required")
			return
		}
		// The email identity is created by CreateUser, so seeding it again is a
		// caller mistake rather than a second identity.
		updated, err := c.store.AddIdentity(u.ID, provider, id.IdentityData)
		if err != nil {
			if errors.Is(err, store.ErrIdentityExists) {
				c.Error(http.StatusConflict, "identity for provider "+provider+" already exists")
				return
			}
			c.Error(http.StatusInternalServerError, err.Error())
			return
		}
		u = updated
	}

	c.JSON(http.StatusCreated, u)
}
