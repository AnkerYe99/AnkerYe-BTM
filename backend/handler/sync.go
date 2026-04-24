package handler

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"nginxflow/db"
	"nginxflow/engine"
	"nginxflow/util"
)

// 从节点拉取配置（无 JWT，用 sync_token 鉴权）
func SyncExport(c *gin.Context) {
	token := c.Query("token")
	var saved string
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='sync_token'`).Scan(&saved)
	if saved == "" || token != saved {
		util.Fail(c, 403, "token 无效")
		return
	}

	configs, version, err := engine.ExportAll()
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}

	// 收集证书
	certs := map[string]gin.H{}
	rows, _ := db.DB.Query(`SELECT domain,cert_pem,key_pem FROM ssl_certs`)
	if rows != nil {
		for rows.Next() {
			var domain, cert, key string
			rows.Scan(&domain, &cert, &key)
			certs[domain] = gin.H{"cert_pem": cert, "key_pem": key}
		}
		rows.Close()
	}

	// 导出通知/SMTP 等系统设置（排除敏感和主节点专属字段）
	settings := map[string]string{}
	skipKeys := map[string]bool{
		"tencent_secret_id": true, "tencent_secret_key": true,
		"sync_token": true, "slave_master_url": true, "slave_sync_token": true,
		"slave_interval": true, "slave_last_sync_at": true, "slave_last_status": true, "slave_last_msg": true,
	}
	rows2, _ := db.DB.Query(`SELECT k,v FROM system_settings`)
	if rows2 != nil {
		for rows2.Next() {
			var k, v string
			rows2.Scan(&k, &v)
			if !skipKeys[k] {
				settings[k] = v
			}
		}
		rows2.Close()
	}

	// 客户端上报自己的地址（可选）
	fromAddr := c.ClientIP()

	// 记录/更新从节点
	db.DB.Exec(`INSERT INTO sync_nodes(name,address,last_sync_at,last_version,status)
		VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING`,
		fromAddr, fromAddr, time.Now().Format("2006-01-02 15:04:05"), version, "ok")
	db.DB.Exec(`UPDATE sync_nodes SET last_sync_at=?,last_version=?,status='ok',last_err=''
		WHERE address=?`, time.Now().Format("2006-01-02 15:04:05"), version, fromAddr)

	util.OK(c, gin.H{
		"version":       version,
		"generated_at":  time.Now().Format(time.RFC3339),
		"nginx_configs": configs,
		"certs":         certs,
		"settings":      settings,
	})
}

func ListSyncNodes(c *gin.Context) {
	rows, _ := db.DB.Query(`SELECT id,name,address,IFNULL(last_sync_at,''),IFNULL(last_version,''),
		status,IFNULL(last_err,''),created_at FROM sync_nodes ORDER BY id DESC`)
	defer rows.Close()
	list := []gin.H{}
	for rows.Next() {
		var id int64
		var name, addr, lastSync, lastVer, status, lastErr, createdAt string
		rows.Scan(&id, &name, &addr, &lastSync, &lastVer, &status, &lastErr, &createdAt)
		list = append(list, gin.H{
			"id": id, "name": name, "address": addr,
			"last_sync_at": lastSync, "last_version": lastVer,
			"status": status, "last_err": lastErr, "created_at": createdAt,
		})
	}
	util.OK(c, list)
}

func AddSyncNode(c *gin.Context) {
	var req struct {
		Name    string `json:"name" binding:"required"`
		Address string `json:"address" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		util.Fail(c, 400, "参数错误")
		return
	}
	res, err := db.DB.Exec(`INSERT INTO sync_nodes(name,address) VALUES(?,?)`, req.Name, req.Address)
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	id, _ := res.LastInsertId()
	util.OK(c, gin.H{"id": id})
}

func DeleteSyncNode(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	db.DB.Exec(`DELETE FROM sync_nodes WHERE id=?`, id)
	util.OK(c, nil)
}
