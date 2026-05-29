package handler

import "net/http"

func Snapshot(c *Context) {
	c.JSON(http.StatusOK, c.store.Snapshot())
}
