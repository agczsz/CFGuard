package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sort"
	"time"

	"dns-failover/internal/config"
	"dns-failover/internal/monitor"
	"dns-failover/internal/service"

	"github.com/cloudflare/cloudflare-go"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	engine    *monitor.Engine
	store     *config.Store
	rootCtx   context.Context
	startedAt time.Time
}

func NewHandler(engine *monitor.Engine, store *config.Store, rootCtx context.Context) *Handler {
	if rootCtx == nil {
		rootCtx = context.Background()
	}
	return &Handler{engine: engine, store: store, rootCtx: rootCtx, startedAt: time.Now()}
}

func (h *Handler) RegisterRoutes(r *gin.Engine) {
	api := r.Group("/api")
	{
		// 认证相关（无需认证）
		api.POST("/auth/login", h.Login)
		api.GET("/auth/check", h.CheckAuth)
		api.GET("/auth/status", h.AuthStatus)

		// 需要认证的路由
		authenticated := api.Group("")
		authenticated.Use(h.AuthMiddleware())
		{
			// 状态总览
			authenticated.GET("/status", h.GetStatus)

			// 域名管理 (Cloudflare)
			authenticated.GET("/zones", h.ListZones)
			authenticated.GET("/zones/:id/records", h.ListRecords)
			authenticated.POST("/zones/:id/records", h.CreateRecord)
			authenticated.PUT("/zones/:id/records/:record_id", h.UpdateRecord)
			authenticated.DELETE("/zones/:id/records/:record_id", h.DeleteRecord)

			// 监控策略管理
			authenticated.GET("/monitors", h.ListMonitors)
			authenticated.POST("/monitors", h.AddMonitor)
			authenticated.PUT("/monitors/:id", h.UpdateMonitor)
			authenticated.DELETE("/monitors/:id", h.DeleteMonitor)
			authenticated.POST("/monitors/:id/restore", h.RestoreMonitor)

			// 全局配置
			authenticated.GET("/config", h.GetGlobalConfig)
			authenticated.POST("/config", h.UpdateGlobalConfig)

			// Cloudflare 凭证管理
			authenticated.GET("/cloudflare-accounts", h.ListCloudflareAccounts)
			authenticated.POST("/cloudflare-accounts", h.AddCloudflareAccount)
			authenticated.PUT("/cloudflare-accounts/:id", h.UpdateCloudflareAccount)
			authenticated.DELETE("/cloudflare-accounts/:id", h.DeleteCloudflareAccount)
			authenticated.POST("/cloudflare-accounts/:id/activate", h.ActivateCloudflareAccount)
		}
	}
}

// --- 认证相关 ---

// AuthMiddleware 认证中间件
func (h *Handler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 如果没有配置token，允许通过（首次使用）
		if !h.store.HasAuthToken() {
			c.Next()
			return
		}

		// 检查cookie中的token
		token, err := c.Cookie("auth_token")
		if err != nil || token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "未登录"})
			c.Abort()
			return
		}

		// 验证token
		if token != h.store.GetAuthToken() {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "登录已过期"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// AuthStatus 获取认证状态
func (h *Handler) AuthStatus(c *gin.Context) {
	hasToken := h.store.HasAuthToken()
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": gin.H{
			"has_token":  hasToken,
			"need_setup": !hasToken,
		},
	})
}

// CheckAuth 检查当前登录状态
func (h *Handler) CheckAuth(c *gin.Context) {
	// 如果没有配置token，返回需要设置
	if !h.store.HasAuthToken() {
		c.JSON(http.StatusOK, gin.H{
			"code": 200,
			"data": gin.H{
				"authenticated": true,
				"need_setup":    true,
			},
		})
		return
	}

	// 检查cookie
	token, err := c.Cookie("auth_token")
	if err != nil || token == "" {
		c.JSON(http.StatusOK, gin.H{
			"code": 200,
			"data": gin.H{
				"authenticated": false,
				"need_setup":    false,
			},
		})
		return
	}

	// 验证token
	authenticated := token == h.store.GetAuthToken()
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": gin.H{
			"authenticated": authenticated,
			"need_setup":    false,
		},
	})
}

// Login 登录
func (h *Handler) Login(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "请输入令牌"})
		return
	}

	// 如果是首次设置，保存token
	if !h.store.HasAuthToken() {
		if err := h.store.SetAuthToken(req.Token); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": "保存令牌失败"})
			return
		}
	} else {
		// 验证token
		if req.Token != h.store.GetAuthToken() {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "令牌错误"})
			return
		}
	}

	// 设置cookie，有效期24小时
	c.SetCookie("auth_token", req.Token, 86400, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"msg":  "登录成功",
	})
}

// GenerateToken 生成随机token（用于CLI命令）
func GenerateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// --- 域名管理 ---

func (h *Handler) getDNSService() (*service.DNSService, error) {
	cfg := h.store.GetCloudflareConfig()
	if cfg.APIToken == "" && (cfg.APIKey == "" || cfg.Email == "") {
		return nil, fmt.Errorf("Cloudflare credentials not configured (api_token OR api_key+email required)")
	}
	return service.NewDNSService(cfg)
}

func (h *Handler) ListZones(c *gin.Context) {
	svc, err := h.getDNSService()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	zones, err := svc.ListZones(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "data": zones})
}

func (h *Handler) ListRecords(c *gin.Context) {
	svc, err := h.getDNSService()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	zoneID := c.Param("id")
	records, err := svc.ListRecords(c.Request.Context(), zoneID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "data": records})
}

func (h *Handler) CreateRecord(c *gin.Context) {
	svc, err := h.getDNSService()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	zoneID := c.Param("id")
	var params cloudflare.CreateDNSRecordParams
	if err := c.ShouldBindJSON(&params); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": err.Error()})
		return
	}
	record, err := svc.CreateRecord(c.Request.Context(), zoneID, params)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "data": record})
}

func (h *Handler) UpdateRecord(c *gin.Context) {
	svc, err := h.getDNSService()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	zoneID := c.Param("id")
	recordID := c.Param("record_id")
	var params cloudflare.UpdateDNSRecordParams
	if err := c.ShouldBindJSON(&params); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": err.Error()})
		return
	}
	params.ID = recordID
	record, err := svc.UpdateRecord(c.Request.Context(), zoneID, params)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "data": record})
}

func (h *Handler) DeleteRecord(c *gin.Context) {
	svc, err := h.getDNSService()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	zoneID := c.Param("id")
	recordID := c.Param("record_id")
	err = svc.DeleteRecord(c.Request.Context(), zoneID, recordID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "success"})
}

// --- 监控策略管理 ---

func (h *Handler) ListMonitors(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": 200, "data": h.store.ListMonitors()})
}

func (h *Handler) AddMonitor(c *gin.Context) {
	var m config.MonitorConfig
	if err := c.ShouldBindJSON(&m); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": err.Error()})
		return
	}
	if m.ID == "" {
		m.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	if m.CheckType == "" {
		m.CheckType = "ping"
	}
	if err := h.store.UpsertMonitor(m); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	h.engine.StartMonitor(h.rootCtx, m)
	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "success"})
}

func (h *Handler) UpdateMonitor(c *gin.Context) {
	var m config.MonitorConfig
	if err := c.ShouldBindJSON(&m); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": err.Error()})
		return
	}
	m.ID = c.Param("id")
	if m.CheckType == "" {
		m.CheckType = "ping"
	}
	if err := h.store.UpsertMonitor(m); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	h.engine.StartMonitor(h.rootCtx, m)
	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "success"})
}

func (h *Handler) DeleteMonitor(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.DeleteMonitor(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	h.engine.StopMonitor(id)
	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "success"})
}

// --- 全局配置 ---

func (h *Handler) GetGlobalConfig(c *gin.Context) {
	cloudflare := h.store.GetCloudflareConfig()
	dingtalk := h.store.GetDingTalkConfig()
	email := h.store.GetEmailConfig()
	telegram := h.store.GetTelegramConfig()
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": gin.H{
			"cloudflare": cloudflare,
			"dingtalk":   dingtalk,
			"email":      email,
			"telegram":   telegram,
		},
	})
}

func (h *Handler) UpdateGlobalConfig(c *gin.Context) {
	var req struct {
		Cloudflare config.CloudflareConfig `json:"cloudflare"`
		DingTalk   config.DingTalkConfig   `json:"dingtalk"`
		Email      config.EmailConfig      `json:"email"`
		Telegram   config.TelegramConfig   `json:"telegram"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": err.Error()})
		return
	}
	if err := h.store.UpdateGlobalConfig(req.Cloudflare, req.DingTalk, req.Email, req.Telegram); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "success"})
}

func (h *Handler) RestoreMonitor(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Proxied *bool `json:"proxied"`
	}
	if err := c.ShouldBindJSON(&req); err != nil && err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": err.Error()})
		return
	}

	mCfg, ok := h.store.GetMonitor(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "msg": "monitor not found"})
		return
	}
	if mCfg.ZoneID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "zone_id is required"})
		return
	}

	fromIP, _ := h.engine.ForceRestore(id)
	if fromIP == "" {
		fromIP = mCfg.BackupIP
	}

	proxied := mCfg.OriginalIPCDNEnabled
	if req.Proxied != nil {
		proxied = *req.Proxied
	}

	d, err := h.getDNSService()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}

	ctx := c.Request.Context()
	for _, sub := range mCfg.Subdomains {
		if err := d.UpdateRecordBySubdomain(ctx, mCfg.ZoneID, sub, mCfg.OriginalIP, proxied); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
			return
		}
	}

	_ = h.store.AppendSwitchEvent(config.SwitchEvent{
		Timestamp: time.Now().UnixMilli(),
		MonitorID: mCfg.ID,
		Name:      mCfg.Name,
		FromIP:    fromIP,
		ToIP:      mCfg.OriginalIP,
		ToBackup:  false,
		CheckType: mCfg.CheckType,
		Reason:    "restore",
	}, 200)

	msg := fmt.Sprintf("手动恢复：%s 切回主 IP: %s", mCfg.Name, mCfg.OriginalIP)
	service.NewNotificationService(h.store.GetDingTalkConfig(), h.store.GetEmailConfig(), h.store.GetTelegramConfig()).Notify(msg)

	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "success"})
}

func (h *Handler) GetStatus(c *gin.Context) {
	status := h.engine.GetStatus()
	history := h.store.ListSwitchHistory(50)
	ipDown := h.store.ListIPDownEvents(2000)

	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	type downKey struct {
		monitorID string
		ip        string
		role      string
	}
	type downAgg struct {
		MonitorID string `json:"monitor_id"`
		Name      string `json:"name"`
		IP        string `json:"ip"`
		Role      string `json:"role"`
		Count     int    `json:"count"`
		LastAt    int64  `json:"last_at"`
	}

	agg := make(map[downKey]*downAgg)
	for _, evt := range ipDown {
		t := time.UnixMilli(evt.Timestamp)
		if t.Before(startOfDay) {
			break
		}
		k := downKey{monitorID: evt.MonitorID, ip: evt.IP, role: evt.Role}
		item := agg[k]
		if item == nil {
			item = &downAgg{
				MonitorID: evt.MonitorID,
				Name:      evt.Name,
				IP:        evt.IP,
				Role:      evt.Role,
			}
			agg[k] = item
		}
		item.Count++
		if evt.Timestamp > item.LastAt {
			item.LastAt = evt.Timestamp
		}
	}

	offlineHot := make([]downAgg, 0)
	for _, v := range agg {
		if v.Count >= 3 {
			offlineHot = append(offlineHot, *v)
		}
	}
	sort.Slice(offlineHot, func(i, j int) bool {
		if offlineHot[i].Count != offlineHot[j].Count {
			return offlineHot[i].Count > offlineHot[j].Count
		}
		return offlineHot[i].LastAt > offlineHot[j].LastAt
	})

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	system := gin.H{
		"uptime_seconds": int64(time.Since(h.startedAt).Seconds()),
		"goroutines":     runtime.NumGoroutine(),
		"mem_alloc":      ms.Alloc,
		"mem_sys":        ms.Sys,
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": gin.H{
			"monitors":    status,
			"history":     history,
			"system":      system,
			"offline_hot": offlineHot,
		},
	})
}

// --- Cloudflare 凭证管理 ---

func (h *Handler) ListCloudflareAccounts(c *gin.Context) {
	accounts := h.store.ListCloudflareAccounts()
	activeIndex := h.store.GetActiveAccountIndex()
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": gin.H{
			"accounts":     accounts,
			"active_index": activeIndex,
		},
	})
}

func (h *Handler) AddCloudflareAccount(c *gin.Context) {
	var account config.CloudflareAccount
	if err := c.ShouldBindJSON(&account); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": err.Error()})
		return
	}
	if account.ID == "" {
		account.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	if err := h.store.AddCloudflareAccount(account); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "success"})
}

func (h *Handler) UpdateCloudflareAccount(c *gin.Context) {
	id := c.Param("id")
	var account config.CloudflareAccount
	if err := c.ShouldBindJSON(&account); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": err.Error()})
		return
	}
	account.ID = id
	if err := h.store.UpdateCloudflareAccount(account); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "success"})
}

func (h *Handler) DeleteCloudflareAccount(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.DeleteCloudflareAccount(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "success"})
}

func (h *Handler) ActivateCloudflareAccount(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.ActivateCloudflareAccount(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "success"})
}
