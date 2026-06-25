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
	"ipgard/internal/firewall"
	"ipgard/internal/geoip"
	"ipgard/internal/logdiscover"
	"ipgard/internal/scanner"
)

const sessionKey = "authenticated"

type Handler struct {
	cfg      *config.Config
	store    *db.Store
	auth     *auth.Manager
	firewall firewall.Manager
	geo      geoip.Resolver
	scanner  *scanner.Scanner
}

func New(cfg *config.Config, store *db.Store, authMgr *auth.Manager, fw firewall.Manager, geo geoip.Resolver, scan *scanner.Scanner) *Handler {
	return &Handler{cfg: cfg, store: store, auth: authMgr, firewall: fw, geo: geo, scanner: scan}
}

func (h *Handler) Register(r *gin.RouterGroup) {
	r.POST("/api/login", h.login)
	r.POST("/api/logout", h.logout)

	api := r.Group("/api")
	api.Use(h.requireAuth)
	{
		api.GET("/me", h.me)
		api.GET("/ips", h.listIPs)
		api.GET("/ips/:ip", h.getIP)
		api.GET("/stats", h.stats)
		api.POST("/firewall/block", h.blockIP)
		api.POST("/firewall/unblock", h.unblockIP)
		api.GET("/firewall/iptables", h.listIptablesRules)
		api.POST("/firewall/iptables/block", h.iptablesBlock)
		api.POST("/firewall/iptables/unblock", h.iptablesUnblock)
		api.GET("/firewall/cidrs", h.listCIDRs)
		api.POST("/firewall/cidrs", h.addCIDR)
		api.POST("/firewall/cidrs/remove", h.removeCIDR)
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
	c.JSON(http.StatusOK, gin.H{
		"authenticated":    true,
		"firewall_enabled": h.firewall.Available(),
	})
}

func (h *Handler) listIPs(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	filter := db.IPFilter{
		IP:        c.Query("ip"),
		Sort:      c.DefaultQuery("sort", "visit_count"),
		Limit:     limit,
		Offset:    offset,
		SkipTotal: c.Query("skip_total") == "1",
	}
	if b := c.Query("blocked"); b == "1" || b == "true" {
		v := true
		filter.Blocked = &v
	} else if b == "0" || b == "false" {
		v := false
		filter.Blocked = &v
	}

	ips, total, err := h.store.ListIPStats(filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ips": ips, "total": total})
}

func (h *Handler) getIP(c *gin.Context) {
	ip := c.Param("ip")
	row, err := h.store.GetIPStat(ip)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ip not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ip": row})
}

func (h *Handler) stats(c *gin.Context) {
	totalIPs, blockedIPs, totalVisits, err := h.store.IPStatsSummary()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"total_ips":      totalIPs,
		"blocked_ips":    blockedIPs,
		"total_visits":   totalVisits,
		"firewall_ready": h.firewall.Available(),
		"geoip_ready":    h.geo.Available(),
		"scanner":        h.scannerStatus(),
	})
}

func (h *Handler) scannerStatus() gin.H {
	if h.scanner == nil {
		return gin.H{"scanning": false}
	}
	st := h.scanner.Status()
	out := gin.H{
		"scanning":     st.Scanning,
		"current_path": st.CurrentPath,
		"file_index":   st.FileIndex,
		"file_count":   st.FileCount,
		"bytes_read":   st.BytesRead,
		"bytes_total":  st.BytesTotal,
		"progress":     st.Progress(),
	}
	if !st.StartedAt.IsZero() {
		out["started_at"] = st.StartedAt
	}
	return out
}

type firewallReq struct {
	IP string `json:"ip"`
}

func (h *Handler) blockIP(c *gin.Context) {
	var req firewallReq
	if err := c.ShouldBindJSON(&req); err != nil || req.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip required"})
		return
	}
	if h.firewall.Available() {
		if err := h.firewall.Block(req.IP); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	if err := h.store.SetIPBlocked(req.IP, true); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "blocked": true, "iptables": h.firewall.Available()})
}

func (h *Handler) unblockIP(c *gin.Context) {
	var req firewallReq
	if err := c.ShouldBindJSON(&req); err != nil || req.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip required"})
		return
	}
	if h.firewall.Available() {
		if err := h.firewall.Unblock(req.IP); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	if err := h.store.SetIPBlocked(req.IP, false); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "blocked": false})
}

func (h *Handler) listIptablesRules(c *gin.Context) {
	if !h.firewall.Available() {
		c.JSON(http.StatusOK, gin.H{"available": false, "rules": []firewall.BlockRule{}})
		return
	}
	rules, err := h.firewall.ListBlockRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if rules == nil {
		rules = []firewall.BlockRule{}
	}
	c.JSON(http.StatusOK, gin.H{
		"available":      true,
		"chain":          h.cfg.Firewall.Chain,
		"rules":          rules,
		"managed_chain":  h.cfg.Firewall.Chain,
	})
}

func (h *Handler) iptablesBlock(c *gin.Context) {
	var req firewallReq
	if err := c.ShouldBindJSON(&req); err != nil || req.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip required"})
		return
	}
	if !h.firewall.Available() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "iptables not available"})
		return
	}
	if err := h.firewall.Block(req.IP); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.syncDBBlocked(req.IP, true)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type iptablesRuleReq struct {
	IP     string `json:"ip"`
	Chain  string `json:"chain"`
	Action string `json:"action"`
}

func (h *Handler) iptablesUnblock(c *gin.Context) {
	var req iptablesRuleReq
	if err := c.ShouldBindJSON(&req); err != nil || req.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip required"})
		return
	}
	if !h.firewall.Available() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "iptables not available"})
		return
	}
	if req.Chain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "chain required"})
		return
	}
	if err := h.firewall.UnblockRule(req.Chain, req.IP, req.Action); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if req.Chain == h.cfg.Firewall.Chain {
		h.syncDBBlocked(req.IP, false)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Handler) listCIDRs(c *gin.Context) {
	blocks, err := h.store.ListCIDRBlocks()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if blocks == nil {
		blocks = []db.CIDRBlock{}
	}
	c.JSON(http.StatusOK, gin.H{
		"available": h.firewall.CIDRSupported(),
		"ipset":     h.firewall.CIDRIpSetName(),
		"cidrs":     blocks,
	})
}

func (h *Handler) addCIDR(c *gin.Context) {
	var req struct {
		CIDR string `json:"cidr"`
		Note string `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.CIDR == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cidr required"})
		return
	}
	if !h.firewall.CIDRSupported() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ipset/iptables not available"})
		return
	}
	normalized, err := firewall.ParseCIDR(req.CIDR)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	exists, err := h.store.HasCIDRBlock(normalized)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "cidr already exists"})
		return
	}
	if err := h.firewall.AddCIDR(normalized); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.store.AddCIDRBlock(normalized, req.Note); err != nil {
		_ = h.firewall.RemoveCIDR(normalized)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "cidr": normalized})
}

func (h *Handler) removeCIDR(c *gin.Context) {
	var req struct {
		CIDR string `json:"cidr"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.CIDR == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cidr required"})
		return
	}
	normalized, err := firewall.ParseCIDR(req.CIDR)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if h.firewall.CIDRSupported() {
		if err := h.firewall.RemoveCIDR(normalized); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	if err := h.store.DeleteCIDRBlock(normalized); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "cidr not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Handler) syncDBBlocked(ip string, blocked bool) {
	if _, err := h.store.GetIPStat(ip); err != nil {
		return
	}
	_ = h.store.SetIPBlocked(ip, blocked)
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
		"firewall": gin.H{
			"enabled": h.cfg.Firewall.Enabled,
			"chain":   h.cfg.Firewall.Chain,
			"ready":   h.firewall.Available(),
		},
		"geoip": gin.H{
			"enabled": h.cfg.GeoIP.Enabled,
			"db_path": h.cfg.GeoIP.DBPath,
			"ready":   h.geo.Available(),
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
