package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"

	"nginxflow/config"
	"nginxflow/db"
	"nginxflow/engine"
	"nginxflow/handler"
	"nginxflow/health"
	"nginxflow/middleware"
)

//go:embed all:frontend/dist
var frontendFS embed.FS

func main() {
	cfgPath := flag.String("config", "/opt/nginxflow/config.yaml", "config file path")
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

	if err := engine.ApplyAll(); err != nil {
		log.Printf("[engine] ApplyAll warning: %v", err)
	}
	health.StartAll()
	log.Println("[health] workers started")

	r := gin.Default()
	r.Use(corsMiddleware())

	// SSE（无需 JWT，通过 ?token= 鉴权）
	r.GET("/api/v1/rules/:id/logs/stream", handler.StreamRuleLogs)

	// 无需 JWT
	r.POST("/api/v1/auth/login", handler.Login)
	r.GET("/api/v1/sync/export", handler.SyncExport)
	r.GET("/api/v1/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"code": 0, "msg": "ok", "service": "nginxflow"})
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

		auth.GET("/certs", handler.ListCerts)
		auth.POST("/certs", handler.UploadCert)
		auth.GET("/certs/:id", handler.GetCert)
		auth.DELETE("/certs/:id", handler.DeleteCert)
		auth.PUT("/certs/:id/auto_renew", handler.ToggleAutoRenew)
		auth.POST("/certs/:id/renew", handler.ManualRenew)

		auth.GET("/stats/overview", handler.Overview)
		auth.GET("/stats/health", handler.Health)
		auth.GET("/stats/system", handler.System)

		auth.GET("/settings", handler.GetSettings)
		auth.PUT("/settings", handler.UpdateSettings)
		auth.POST("/settings/nginx_test", handler.TestNginx)
		auth.POST("/settings/nginx_reload", handler.ReloadNginx)
		auth.GET("/settings/backup", handler.Backup)
		auth.POST("/settings/restore", handler.Restore)

		auth.GET("/sync/nodes", handler.ListSyncNodes)
		auth.POST("/sync/nodes", handler.AddSyncNode)
		auth.DELETE("/sync/nodes/:id", handler.DeleteSyncNode)
	}

	// 前端静态文件（SPA 模式，未匹配路由回退 index.html）
	distFS, _ := fs.Sub(frontendFS, "frontend/dist")
	fileServer := http.FileServer(http.FS(distFS))
	r.NoRoute(func(c *gin.Context) {
		urlPath := strings.TrimPrefix(c.Request.URL.Path, "/")
		// 根路径或文件不存在 → 直接输出 index.html 内容（避免重定向死循环）
		if urlPath == "" {
			data, _ := fs.ReadFile(distFS, "index.html")
			c.Data(http.StatusOK, "text/html; charset=utf-8", data)
			return
		}
		_, err := fs.Stat(distFS, urlPath)
		if err != nil {
			data, _ := fs.ReadFile(distFS, "index.html")
			c.Data(http.StatusOK, "text/html; charset=utf-8", data)
			return
		}
		fileServer.ServeHTTP(c.Writer, c.Request)
	})

	addr := fmt.Sprintf(":%d", config.Global.Server.Port)
	log.Printf("[nginxflow] listening on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatal(err)
	}
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
