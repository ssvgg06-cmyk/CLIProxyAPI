package management

import (
	_ "embed"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed pool_console.html
var poolConsoleHTML string

// PoolLogConsole serves the credential pool log console. It is only available
// while the instance runs in pool mode; otherwise the route reports 404 so the
// standard build exposes no extra surface.
func (h *Handler) PoolLogConsole(c *gin.Context) {
	if h == nil || !h.poolMode {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(poolConsoleHTML))
}
