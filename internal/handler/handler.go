package handler

import (
	"net/http"
	"os"
	"strconv"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"ipgard/config"
	"ipgard/internal/auth"
	"ipgard/internal/db"
	"ipgard/internal/logdiscover"
)

const sessionKey = "authenticated"

type Handler struct {
	cfg  *config.Config
	store *db.Store
	auth *auth.Manager
}

func New(cfg *config.Config, store *db.Store, authMgr *auth.Manager) *Handler {
	return &Handler{cfg: cfg, store: store, auth: authMgr}
}

func (h *Handler) Register(r *gin.RouterGroup) {
	r.POST("/api/login", h.login)
	r.POST("/api/logout", h.logout)

	api := r.Group("/api")
	api.Use(h.requireAuth)
	{
		api.GET("/me", h.me)
		api.GET("/records", h.listRecords)
		api.GET("/stats", h.stats)
		api.GET("/settings", h.getSettings)
		api.PUT("/settings/password", h.changePassword)
		api.GET("/logs/monitored", h.listMonitoredLogs)
		api.POST("/logs/monitored", h.addMonitoredLog)
		api.PATCH("/logs/monitored/:id", h.patchMonitoredLog)
		api.DELETE("/logs/monitored/:id", h.deleteMonitoredLog)
		api.GET("/logs/discover", h.discoverLogs)
	}
}

func (h *Handler) requireAuth(c *gin.Context) {
	s := sessions.Default(c)
	if v := s.Get(sessionKey); v != true {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	c.Next()
}

type loginReq struct {
	Password string `json:"password"`
}

func (h *Handler) login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password required"})
		return
	}
	if err := h.auth.Verify(req.Password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
		return
	}
	s := sessions.Default(c)
	s.Set(sessionKey, true)
	if err := s.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Handler) logout(c *gin.Context) {
	s := sessions.Default(c)
	s.Clear()
	_ = s.Save()
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Handler) me(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"authenticated": true})
}

func (h *Handler) listRecords(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	filter := db.RecordFilter{
		IP:        c.Query("ip"),
		LogSource: c.Query("log_source"),
		Limit:     limit,
		Offset:    offset,
	}
	records, total, err := h.store.ListAccessRecords(filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"records": records, "total": total})
}

func (h *Handler) stats(c *gin.Context) {
	total, err := h.store.RecordCount()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	top, err := h.store.TopIPs(20)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"total_records": total, "top_ips": top})
}

func (h *Handler) getSettings(c *gin.Context) {
	logs, err := h.store.ListMonitoredLogs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"server": gin.H{
			"port":      h.cfg.Server.Port,
			"base_path": h.cfg.NormalizedBasePath(),
		},
		"scanner": gin.H{
			"interval_seconds": h.cfg.Scanner.IntervalSeconds,
		},
		"monitored_logs": logs,
	})
}

type changePasswordReq struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (h *Handler) changePassword(c *gin.Context) {
	var req changePasswordReq
	if err := c.ShouldBindJSON(&req); err != nil || req.NewPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new password required"})
		return
	}
	if err := h.auth.Verify(req.OldPassword); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid old password"})
		return
	}
	if err := h.auth.ChangePassword(req.NewPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Handler) listMonitoredLogs(c *gin.Context) {
	logs, err := h.store.ListMonitoredLogs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"logs": logs})
}

type addLogReq struct {
	Path   string `json:"path"`
	Format string `json:"format"`
}

func (h *Handler) addMonitoredLog(c *gin.Context) {
	var req addLogReq
	if err := c.ShouldBindJSON(&req); err != nil || req.Path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path required"})
		return
	}
	if _, err := os.Stat(req.Path); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file not accessible"})
		return
	}
	if req.Format == "" {
		req.Format = "auto"
	}
	log, err := h.store.AddMonitoredLog(req.Path, req.Format)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"log": log})
}

type patchLogReq struct {
	Enabled *bool `json:"enabled"`
}

func (h *Handler) patchMonitoredLog(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var req patchLogReq
	if err := c.ShouldBindJSON(&req); err != nil || req.Enabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enabled required"})
		return
	}
	if err := h.store.SetMonitoredLogEnabled(id, *req.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log, err := h.store.GetMonitoredLog(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"log": log})
}

func (h *Handler) deleteMonitoredLog(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := h.store.DeleteMonitoredLog(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Handler) discoverLogs(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"candidates": logdiscover.Discover()})
}
