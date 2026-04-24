package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"nginxflow/config"
	"nginxflow/db"
	"nginxflow/engine"
	"nginxflow/handler"
	"nginxflow/health"
	"nginxflow/middleware"
)

func main() {
	cfgPath := flag.String("config", "/opt/nginxflow/config.yaml", "config file path")
	flag.Parse()

	if err := config.Load(*cfgPath); err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := db.Init(config.Global.Database.Path); err != nil {
		log.Fatalf("db init: %v", err)
	}
	if err := handler.EnsureAdmin(); err != nil {
		log.Printf("EnsureAdmin: %v", err)
	}

	// 启动时应用所有规则 + 启动健康检查
	if err := engine.ApplyAll(); err != nil {
		log.Printf("[engine] ApplyAll warning: %v", err)
	}
	health.StartAll()
	log.Println("[health] workers started")

	r := gin.Default()
	r.Use(corsMiddleware())

	// 无需 JWT（SSE 通过 ?token= 自行鉴权）
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
