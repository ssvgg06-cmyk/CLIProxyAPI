package management

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// PoolMode reports whether this handler is serving the read-only credential pool.
func (h *Handler) PoolMode() bool {
	return h != nil && h.poolMode
}

// GetPoolLogAccount returns the current or archived masked identity used by a
// log association. It never returns tokens or a usable credential document.
func (h *Handler) GetPoolLogAccount(c *gin.Context) {
	if h == nil || !h.poolMode || h.poolState == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	authIndex := strings.TrimSpace(c.Param("auth_index"))
	if authIndex == "" || len(authIndex) > 256 || strings.ContainsAny(authIndex, "/\\") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid auth index"})
		return
	}
	account, ok := h.poolState.logAccountByAuthIndex(time.Now(), authIndex)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "associated account not found"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"account": account})
}
