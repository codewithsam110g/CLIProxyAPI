package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func (h *Handler) balancedRouter() *coreauth.SessionBalancedSelector {
	if h == nil || h.authManager == nil {
		return nil
	}
	router, _ := h.authManager.Selector().(*coreauth.SessionBalancedSelector)
	return router
}

// GetRoutingSessions returns routing metadata, never provider or client tokens.
func (h *Handler) GetRoutingSessions(c *gin.Context) {
	router := h.balancedRouter()
	if router == nil {
		c.JSON(http.StatusOK, coreauth.BalancedRoutingSnapshot{Sessions: []coreauth.SessionBinding{}, Accounts: []coreauth.RoutingAccount{}})
		return
	}
	c.JSON(http.StatusOK, router.Snapshot())
}

func (h *Handler) MoveRoutingSession(c *gin.Context) {
	router := h.balancedRouter()
	if router == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "enable routing.strategy: session-balanced first"})
		return
	}
	var req struct {
		ID         string `json:"id"`
		AuthID     string `json:"auth_id"`
		Generation uint64 `json:"expected_generation"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.ID == "" || req.AuthID == "" || req.Generation == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id, auth_id and expected_generation are required"})
		return
	}
	if err := router.RequestMove(req.ID, req.AuthID, req.Generation); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "pending", "message": "move applies at the next safe request; stateful continuations must reconnect and replay"})
}

func (h *Handler) DrainRoutingAccount(c *gin.Context) {
	router := h.balancedRouter()
	if router == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "enable routing.strategy: session-balanced first"})
		return
	}
	var req struct {
		AuthID   string `json:"auth_id"`
		Draining *bool  `json:"draining"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.AuthID == "" || req.Draining == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth_id and draining are required"})
		return
	}
	if err := router.SetDraining(req.AuthID, *req.Draining); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
