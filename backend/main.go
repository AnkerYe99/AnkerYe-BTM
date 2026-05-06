package main

import (
	"compress/gzip"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"ankerye-flow/config"
	"ankerye-flow/db"
	"ankerye-flow/engine"
	"ankerye-flow/handler"
	"ankerye-flow/health"
	"ankerye-flow/middleware"
	"ankerye-flow/util"
)

//go:embed all:frontend/dist
var frontendFS embed.FS

func main() {
	cfgPath := flag.String("config", "/opt/AnkerYe-BTM/config.yaml", "config file path")
	flag.Parse()

	if err := config.Load(*cfgPath); err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := os.MkdirAll(config.Global.Nginx.LogDir, 0755); err != nil {
		log.Fatalf("create log dir: %v", err)
	}
	if err := db.Init(config.Global.Database.Path); err != nil {
		log.Fatalf("db init: %v", err)
	}
	if err := handler.EnsureAdmin(); err != nil {
		log.Printf("EnsureAdmin: %v", err)
	}

	util.InitGeo(config.Global.GeoIPDB)

	engine.EnsureFilterConf()
	if err := engine.ApplyAll(); err != nil {
		log.Printf("[engine] ApplyAll warning: %v", err)
	}
	health.StartAll()
	log.Println("[health] workers started")
	engine.StartStatsWorker()
	go engine.StartAutoBlockWorker()
	go startCertAutoRenew()
	go engine.StartSlaveSyncAgent()
	go engine.StartSlaveRulesSyncAgent()
	go engine.StartSlaveCertsSyncAgent()
	go engine.StartSlaveFilterSyncAgent()

	r := gin.Default()
	r.Use(corsMiddleware())
	r.Use(gzipMiddleware())

	// SSE（无需 JWT，通过 ?token= 鉴权）
	r.GET("/api/v1/rules/:id/logs/stream", handler.StreamRuleLogs)

	// 无需 JWT
	r.GET("/api/v1/version", handler.GetVersion)
	r.POST("/api/v1/auth/login", handler.Login)
	r.GET("/api/v1/sync/export", handler.SyncExport)
	r.GET("/api/v1/sync/rules_export", handler.SyncRulesExport)
	r.GET("/api/v1/sync/certs_export", handler.SyncCertsExport)
	r.GET("/api/v1/sync/filter_export", handler.SyncFilterExport)
	r.GET("/api/v1/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"code": 0, "msg": "ok", "service": "ankerye-流量管理"})
	})

	// 需要 JWT
	auth := r.Group("/api/v1")
	auth.Use(middleware.JWT())
	{
		auth.GET("/auth/profile", handler.Profile)
		auth.PUT("/auth/password", handler.ChangePassword)
		auth.PUT("/auth/profile", handler.ChangeProfile)

		auth.GET("/rules", handler.ListRules)
		auth.POST("/rules", handler.CreateRule)
		auth.GET("/rules/:id", handler.GetRule)
		auth.PUT("/rules/:id", handler.UpdateRule)
		auth.DELETE("/rules/:id", handler.DeleteRule)
		auth.POST("/rules/:id/enable", handler.EnableRule)
		auth.POST("/rules/:id/disable", handler.DisableRule)
		auth.GET("/rules/:id/preview", handler.PreviewRule)

		auth.GET("/rules/:id/servers", handler.ListServers)
		auth.POST("/rules/:id/servers", handler.AddServer)
		auth.PUT("/rules/:id/servers/:sid", handler.UpdateServer)
		auth.DELETE("/rules/:id/servers/:sid", handler.DeleteServer)
		auth.POST("/rules/:id/servers/:sid/enable", handler.EnableServer)
		auth.POST("/rules/:id/servers/:sid/disable", handler.DisableServer)
		auth.GET("/rules/:id/servers/:sid/logs", handler.ServerLogs)
		auth.GET("/rules/:id/logs/download", handler.DownloadRuleLog)

		auth.GET("/certs", handler.ListCerts)
		auth.POST("/certs", handler.UploadCert)
		auth.POST("/certs/apply", handler.ApplyCert)
		auth.GET("/certs/:id", handler.GetCert)
		auth.PUT("/certs/:id", handler.EditCert)
		auth.DELETE("/certs/:id", handler.DeleteCert)
		auth.PUT("/certs/:id/auto_renew", handler.ToggleAutoRenew)
		auth.POST("/certs/:id/renew", handler.ManualRenew)
		auth.GET("/certs/:id/renew_log", handler.GetRenewLog)

		auth.GET("/stats/overview", handler.Overview)
		auth.GET("/stats/health", handler.Health)
		auth.GET("/stats/system", handler.System)
		auth.GET("/stats/traffic", handler.RuleTraffic)
		auth.GET("/stats/server_health", handler.ServerHealth)
		auth.GET("/stats/errors", handler.ListErrorLogs)
		auth.GET("/rules/simple", handler.ListRulesSimple)
		auth.GET("/rules/:id/capture", handler.ListCapture)

		auth.GET("/update/check", handler.CheckUpdate)
		auth.POST("/update/apply", handler.ApplyUpdate)

		auth.GET("/settings", handler.GetSettings)
		auth.PUT("/settings", handler.UpdateSettings)
		auth.POST("/settings/nginx_test", handler.TestNginx)
		auth.POST("/settings/nginx_reload", handler.ReloadNginx)
		auth.GET("/settings/backup", handler.Backup)
		auth.POST("/settings/restore", handler.Restore)
		auth.POST("/settings/test_email", handler.TestEmail)

		// 黑白名单过滤
		auth.GET("/filter/blacklist", handler.ListBlacklist)
		auth.POST("/filter/blacklist", handler.AddBlacklist)
		auth.DELETE("/filter/blacklist/:id", handler.DeleteBlacklist)
		auth.POST("/filter/blacklist/:id/enable", handler.EnableBlacklist)
		auth.POST("/filter/blacklist/:id/disable", handler.DisableBlacklist)
		auth.GET("/filter/whitelist", handler.ListWhitelist)
		auth.POST("/filter/whitelist", handler.AddWhitelist)
		auth.DELETE("/filter/whitelist/:id", handler.DeleteWhitelist)
		auth.POST("/filter/whitelist/:id/enable", handler.EnableWhitelist)
		auth.POST("/filter/whitelist/:id/disable", handler.DisableWhitelist)
		auth.POST("/filter/apply", handler.ApplyFilterNow)

		auth.GET("/sync/nodes", handler.ListSyncNodes)
		auth.POST("/sync/nodes", handler.AddSyncNode)
		auth.DELETE("/sync/nodes/:id", handler.DeleteSyncNode)
		auth.POST("/sync/trigger_rules", handler.TriggerRulesSync)
		auth.POST("/sync/trigger_certs", handler.TriggerCertsSync)
		auth.POST("/sync/trigger_filter", handler.TriggerFilterSync)
	}

	// 前端静态文件（SPA 模式，未匹配路由回退 index.html）
	distFS, _ := fs.Sub(frontendFS, "frontend/dist")
	fileServer := http.FileServer(http.FS(distFS))
	r.NoRoute(func(c *gin.Context) {
		urlPath := strings.TrimPrefix(c.Request.URL.Path, "/")
		// 根路径或文件不存在 → 直接输出 index.html（no-cache，确保始终拿到最新版本）
		if urlPath == "" {
			c.Header("Cache-Control", "no-cache")
			data, _ := fs.ReadFile(distFS, "index.html")
			c.Data(http.StatusOK, "text/html; charset=utf-8", data)
			return
		}
		_, err := fs.Stat(distFS, urlPath)
		if err != nil {
			c.Header("Cache-Control", "no-cache")
			data, _ := fs.ReadFile(distFS, "index.html")
			c.Data(http.StatusOK, "text/html; charset=utf-8", data)
			return
		}
		// /assets/ 下的文件名含 hash，永久缓存；其余文件 no-cache
		if strings.HasPrefix(c.Request.URL.Path, "/assets/") {
			c.Header("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			c.Header("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(c.Writer, c.Request)
	})

	addr := fmt.Sprintf(":%d", config.Global.Server.Port)
	log.Printf("[AnkerYe - 流量管理] listening on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatal(err)
	}
}

// startCertAutoRenew 每天凌晨 2 点检查并自动续签到期证书
func startCertAutoRenew() {
	for {
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
		if !next.After(now) {
			next = next.Add(24 * time.Hour)
		}
		time.Sleep(time.Until(next))
		log.Println("[cert] running auto-renew check")
		engine.AutoRenewCheck()
	}
}

func gzipMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !strings.Contains(c.Request.Header.Get("Accept-Encoding"), "gzip") {
			c.Next()
			return
		}
		ext := strings.ToLower(c.Request.URL.Path)
		if !strings.HasSuffix(ext, ".js") && !strings.HasSuffix(ext, ".css") &&
			!strings.HasSuffix(ext, ".json") && !strings.HasSuffix(ext, ".svg") {
			c.Next()
			return
		}
		c.Header("Content-Encoding", "gzip")
		c.Header("Vary", "Accept-Encoding")
		gz, _ := gzip.NewWriterLevel(c.Writer, gzip.BestSpeed)
		defer gz.Close()
		c.Writer = &gzipWriter{ResponseWriter: c.Writer, gz: gz}
		c.Next()
	}
}

type gzipWriter struct {
	gin.ResponseWriter
	gz *gzip.Writer
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	return g.gz.Write(b)
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
