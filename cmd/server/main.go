package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/viper"

	"dns-failover/internal/api"
	"dns-failover/internal/config"
	"dns-failover/internal/monitor"
	"dns-failover/internal/service"

	"github.com/gin-gonic/gin"
)

func main() {
	// 解析命令行参数
	resetToken := flag.Bool("reset-token", false, "重置认证令牌")
	flag.Parse()

	// 初始化持久化存储
	store := config.NewStore("data.json")
	if err := store.Load(); err != nil {
		log.Printf("Failed to load data.json: %v", err)
	}

	// 如果是重置令牌模式
	if *resetToken {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("=== 重置认证令牌 ===")
		fmt.Print("请输入新的令牌: ")
		newToken, _ := reader.ReadString('\n')
		newToken = strings.TrimSpace(newToken)

		if newToken == "" {
			log.Fatal("令牌不能为空")
		}

		if err := store.SetAuthToken(newToken); err != nil {
			log.Fatalf("设置令牌失败: %v", err)
		}

		fmt.Println("✓ 令牌已成功重置！")
		fmt.Println("请重新启动服务并使用新令牌登录。")
		return
	}

	// 加载配置
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("Warning: config file not found, using env vars")
	}

	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("Failed to unmarshal config: %v", err)
	}

	// 如果 data.json 为空，则从 config.yaml 导入初始配置
	if len(store.ListMonitors()) == 0 && len(cfg.Monitors) > 0 {
		log.Println("Importing initial monitors from config.yaml")
		for _, m := range cfg.Monitors {
			if err := store.UpsertMonitor(m); err != nil {
				log.Printf("Failed to import monitor %s: %v", m.Name, err)
			}
		}
		if err := store.UpdateGlobalConfig(cfg.Cloudflare, cfg.DingTalk, cfg.Email, cfg.Telegram); err != nil {
			log.Printf("Failed to import global config: %v", err)
		}
	}

	// 使用 store 中的配置
	// currentCfg := store.GetSnapshot() // 不再需要，使用 cfg 替代

	engine := monitor.NewEngine()
	engine.OnSwitch = func(m *monitor.Monitor, toBackup bool) {
		targetIP := m.Config.OriginalIP
		proxied := m.Config.OriginalIPCDNEnabled
		msg := fmt.Sprintf("服务器 %s 已恢复，切回原始 IP: %s", m.Config.Name, targetIP)

		if toBackup {
			targetIP = m.Config.BackupIP
			proxied = m.Config.BackupIPCDNEnabled
			msg = fmt.Sprintf("服务器 %s 宕机，切换到备用 IP: %s", m.Config.Name, targetIP)
		}

		log.Println(msg)
		service.NewNotificationService(store.GetDingTalkConfig(), store.GetEmailConfig(), store.GetTelegramConfig()).Notify(msg)

		fromIP := m.Config.BackupIP
		toIP := m.Config.OriginalIP
		reason := "restore"
		if toBackup {
			fromIP = m.Config.OriginalIP
			toIP = m.Config.BackupIP
			reason = "failover"
		}
		_ = store.AppendSwitchEvent(config.SwitchEvent{
			Timestamp: time.Now().UnixMilli(),
			MonitorID: m.Config.ID,
			Name:      m.Config.Name,
			FromIP:    fromIP,
			ToIP:      toIP,
			ToBackup:  toBackup,
			CheckType: m.Config.CheckType,
			Reason:    reason,
		}, 200)

		ctx := context.Background()
		for _, sub := range m.Config.Subdomains {
			// 每次切换时重新获取最新的 DNS 服务实例，以防配置变更
			latestCF := store.GetCloudflareConfig()
			d, err := service.NewDNSService(latestCF)
			if err != nil {
				log.Printf("Failed to init DNS service for switch: %v", err)
				continue
			}
			if err := d.UpdateRecordBySubdomain(ctx, m.Config.ZoneID, sub, targetIP, proxied); err != nil {
				log.Printf("Failed to update DNS for %s: %v", sub, err)
			}
		}
	}
	engine.OnScheduledSwitch = func(m *monitor.Monitor, fromIP, toIP string) {
		if m.Config.ZoneID == "" {
			return
		}

		proxied := false
		switch toIP {
		case m.Config.OriginalIP:
			proxied = m.Config.OriginalIPCDNEnabled
		case m.Config.BackupIP:
			proxied = m.Config.BackupIPCDNEnabled
		}

		msg := fmt.Sprintf("定时切换：%s %s -> %s", m.Config.Name, fromIP, toIP)
		log.Println(msg)
		service.NewNotificationService(store.GetDingTalkConfig(), store.GetEmailConfig(), store.GetTelegramConfig()).Notify(msg)

		_ = store.AppendSwitchEvent(config.SwitchEvent{
			Timestamp: time.Now().UnixMilli(),
			MonitorID: m.Config.ID,
			Name:      m.Config.Name,
			FromIP:    fromIP,
			ToIP:      toIP,
			ToBackup:  toIP == m.Config.BackupIP,
			CheckType: m.Config.CheckType,
			Reason:    "schedule",
		}, 200)

		ctx := context.Background()
		for _, sub := range m.Config.Subdomains {
			latestCF := store.GetCloudflareConfig()
			d, err := service.NewDNSService(latestCF)
			if err != nil {
				log.Printf("Failed to init DNS service for scheduled switch: %v", err)
				continue
			}
			if err := d.UpdateRecordBySubdomain(ctx, m.Config.ZoneID, sub, toIP, proxied); err != nil {
				log.Printf("Failed to update DNS for %s: %v", sub, err)
			}
		}
	}
	engine.OnIPDown = func(m *monitor.Monitor, ip, role string) {
		_ = store.AppendIPDownEvent(config.IPDownEvent{
			Timestamp: time.Now().UnixMilli(),
			MonitorID: m.Config.ID,
			Name:      m.Config.Name,
			IP:        ip,
			Role:      role,
		}, 2000)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, mCfg := range store.ListMonitors() {
		engine.StartMonitor(ctx, mCfg)
	}

	// 启动 API 服务
	r := gin.Default()

	// CORS (支持 file:// 或不同端口访问前端)
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// 静态文件服务
	r.StaticFile("/", "./web/index.html")
	r.StaticFile("/index.html", "./web/index.html")
	r.StaticFile("/login.html", "./web/login.html")
	r.StaticFile("/app.js", "./web/app.js")
	r.StaticFile("/favicon.ico", "./web/favicon.ico")

	handler := api.NewHandler(engine, store, ctx)
	handler.RegisterRoutes(r)

	go func() {
		port := cfg.Server.Port
		if port == 0 {
			port = 8081
		}
		if err := r.Run(fmt.Sprintf(":%d", port)); err != nil {
			log.Fatalf("Failed to run server: %v", err)
		}
	}()

	log.Printf("DNS Failover Server started")

	// 等待退出信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down...")
}
