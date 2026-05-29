package handler

func Reset(c *Context) {
	c.store.Reset()
	c.NoContent()
}
