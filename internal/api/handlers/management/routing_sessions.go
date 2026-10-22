package management

import (
	"errors"
	"io"
	"net/http"
	"strings"

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
		// Report the configured reserves so the dashboard can still explain them.
		disabled := coreauth.BalancedRoutingSnapshot{Sessions: []coreauth.SessionBinding{}, Accounts: []coreauth.RoutingAccount{}}
		if h != nil && h.cfg != nil {
			disabled.ShortWindowReservePercent = h.cfg.Routing.SessionQuota.ShortReservePercent()
			disabled.LongWindowReservePercent = h.cfg.Routing.SessionQuota.LongReservePercent()
		}
		c.JSON(http.StatusOK, disabled)
		return
	}
	c.JSON(http.StatusOK, router.Snapshot())
}

// RefreshRoutingQuota polls provider usage now for one account ({"auth_id":"..."})
// or every pollable account ({}), waits for the polls, and returns the updated
// account entries. A poll that finished moments ago is reused, and an account
// already being polled is joined, so repeated clicks do not multiply provider calls.
func (h *Handler) RefreshRoutingQuota(c *gin.Context) {
	router := h.balancedRouter()
	if router == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "enable routing.strategy: session-balanced first"})
		return
	}
	poller := h.authManager.QuotaPoller()
	if poller == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "quota polling is unavailable"})
		return
	}
	var req struct {
		AuthID string `json:"auth_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	var ids []string
	if id := strings.TrimSpace(req.AuthID); id != "" {
		ids = []string{id}
	}
	results, err := poller.RefreshQuota(c.Request.Context(), ids...)
	switch {
	case errors.Is(err, coreauth.ErrQuotaPollAuthNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "account not found"})
		return
	case errors.Is(err, coreauth.ErrQuotaPollUnsupported):
		c.JSON(http.StatusBadRequest, gin.H{"error": "account does not support quota polling"})
		return
	case err != nil:
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "quota refresh was interrupted"})
		return
	}
	polled := make([]string, 0, len(results))
	coalesced := []string{}
	for _, result := range results {
		polled = append(polled, result.AuthID)
		if result.Coalesced {
			coalesced = append(coalesced, result.AuthID)
		}
	}
	accounts := []coreauth.RoutingAccount{}
	if len(polled) > 0 {
		accounts = router.AccountSnapshots(polled...)
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "coalesced_auth_ids": coalesced, "accounts": accounts})
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
