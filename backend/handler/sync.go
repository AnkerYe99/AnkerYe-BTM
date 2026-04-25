package handler

import (
	"crypto/sha256"
	"fmt"
	"sort"
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

	// 导出完整规则数据（含后端节点），从节点写入本地 DB 以便 UI 显示
	rules := []gin.H{}
	rrows, _ := db.DB.Query(`SELECT id,name,protocol,listen_port,IFNULL(listen_stack,'both'),
		https_enabled,IFNULL(https_port,0),IFNULL(server_name,''),lb_method,
		IFNULL(ssl_cert_id,0),ssl_redirect,hc_enabled,hc_interval,hc_timeout,
		IFNULL(hc_path,'/'),hc_fall,hc_rise,IFNULL(log_max_size,'5M'),
		IFNULL(custom_config,''),status FROM rules ORDER BY id`)
	if rrows != nil {
		for rrows.Next() {
			var id, listenPort, httpsEnabled, httpsPort, sslCertID, sslRedirect int64
			var hcEnabled, hcInterval, hcTimeout, hcFall, hcRise, status int64
			var name, protocol, listenStack, serverName, lbMethod, hcPath, logMaxSize, customConfig string
			rrows.Scan(&id, &name, &protocol, &listenPort, &listenStack,
				&httpsEnabled, &httpsPort, &serverName, &lbMethod,
				&sslCertID, &sslRedirect, &hcEnabled, &hcInterval, &hcTimeout,
				&hcPath, &hcFall, &hcRise, &logMaxSize, &customConfig, &status)

			// 查该规则的后端节点
			servers := []gin.H{}
			srows, _ := db.DB.Query(`SELECT address,port,weight,state FROM upstream_servers WHERE rule_id=? ORDER BY id`, id)
			if srows != nil {
				for srows.Next() {
					var addr, state string
					var port, weight int64
					srows.Scan(&addr, &port, &weight, &state)
					servers = append(servers, gin.H{"address": addr, "port": port, "weight": weight, "state": state})
				}
				srows.Close()
			}

			rules = append(rules, gin.H{
				"id": id, "name": name, "protocol": protocol,
				"listen_port": listenPort, "listen_stack": listenStack,
				"https_enabled": httpsEnabled, "https_port": httpsPort,
				"server_name": serverName, "lb_method": lbMethod,
				"ssl_cert_id": sslCertID, "ssl_redirect": sslRedirect,
				"hc_enabled": hcEnabled, "hc_interval": hcInterval, "hc_timeout": hcTimeout,
				"hc_path": hcPath, "hc_fall": hcFall, "hc_rise": hcRise,
				"log_max_size": logMaxSize, "custom_config": customConfig, "status": status,
				"servers": servers,
			})
		}
		rrows.Close()
	}

	// 导出完整证书数据
	certs := []gin.H{}
	certMap := map[string]gin.H{} // 兼容旧版从节点的 map 格式
	crows, _ := db.DB.Query(`SELECT domain,cert_pem,key_pem,IFNULL(expire_at,''),IFNULL(auto_renew,0) FROM ssl_certs ORDER BY id`)
	if crows != nil {
		for crows.Next() {
			var domain, certPEM, keyPEM, expireAt string
			var autoRenew int64
			crows.Scan(&domain, &certPEM, &keyPEM, &expireAt, &autoRenew)
			certs = append(certs, gin.H{
				"domain": domain, "cert_pem": certPEM, "key_pem": keyPEM,
				"expire_at": expireAt, "auto_renew": autoRenew,
			})
			certMap[domain] = gin.H{"cert_pem": certPEM, "key_pem": keyPEM}
		}
		crows.Close()
	}

	// 导出通知/SMTP 等系统设置（排除敏感和主节点专属字段）
	settings := map[string]string{}
	skipKeys := map[string]bool{
		"tencent_secret_id": true, "tencent_secret_key": true,
		"acme_email": true, "acme_account_json": true, "acme_account_key": true,
		"dnspod_id": true, "dnspod_key": true,
		"sync_token": true, "slave_master_url": true, "slave_sync_token": true,
		"slave_interval": true, "slave_last_sync_at": true, "slave_last_status": true, "slave_last_msg": true,
	}
	srows2, _ := db.DB.Query(`SELECT k,v FROM system_settings`)
	if srows2 != nil {
		for srows2.Next() {
			var k, v string
			srows2.Scan(&k, &v)
			if !skipKeys[k] {
				settings[k] = v
			}
		}
		srows2.Close()
	}

	// 记录/更新从节点
	fromAddr := c.ClientIP()
	db.DB.Exec(`INSERT INTO sync_nodes(name,address,last_sync_at,last_version,status)
		VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING`,
		fromAddr, fromAddr, time.Now().Format("2006-01-02 15:04:05"), version, "ok")
	db.DB.Exec(`UPDATE sync_nodes SET last_sync_at=?,last_version=?,status='ok',last_err=''
		WHERE address=?`, time.Now().Format("2006-01-02 15:04:05"), version, fromAddr)

	util.OK(c, gin.H{
		"version":       version,
		"generated_at":  time.Now().Format(time.RFC3339),
		"nginx_configs": configs,
		"rules":         rules,
		"certs":         certs,
		"cert_map":      certMap,
		"settings":      settings,
	})
}

// SyncRulesExport 仅导出规则+节点（使用 sync_rules_token 鉴权）
func SyncRulesExport(c *gin.Context) {
	token := c.Query("token")
	var saved string
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='sync_rules_token'`).Scan(&saved)
	if saved == "" || token != saved {
		util.Fail(c, 403, "token 无效")
		return
	}

	configs, version, err := engine.ExportAll()
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}

	rules := []gin.H{}
	rrows, _ := db.DB.Query(`SELECT id,name,protocol,listen_port,IFNULL(listen_stack,'both'),
		https_enabled,IFNULL(https_port,0),IFNULL(server_name,''),lb_method,
		IFNULL(ssl_cert_id,0),ssl_redirect,hc_enabled,hc_interval,hc_timeout,
		IFNULL(hc_path,'/'),hc_fall,hc_rise,IFNULL(log_max_size,'5M'),
		IFNULL(custom_config,''),status FROM rules ORDER BY id`)
	if rrows != nil {
		for rrows.Next() {
			var id, listenPort, httpsEnabled, httpsPort, sslCertID, sslRedirect int64
			var hcEnabled, hcInterval, hcTimeout, hcFall, hcRise, status int64
			var name, protocol, listenStack, serverName, lbMethod, hcPath, logMaxSize, customConfig string
			rrows.Scan(&id, &name, &protocol, &listenPort, &listenStack,
				&httpsEnabled, &httpsPort, &serverName, &lbMethod,
				&sslCertID, &sslRedirect, &hcEnabled, &hcInterval, &hcTimeout,
				&hcPath, &hcFall, &hcRise, &logMaxSize, &customConfig, &status)
			servers := []gin.H{}
			srows, _ := db.DB.Query(`SELECT address,port,weight,state FROM upstream_servers WHERE rule_id=? ORDER BY id`, id)
			if srows != nil {
				for srows.Next() {
					var addr, state string
					var port, weight int64
					srows.Scan(&addr, &port, &weight, &state)
					servers = append(servers, gin.H{"address": addr, "port": port, "weight": weight, "state": state})
				}
				srows.Close()
			}
			rules = append(rules, gin.H{
				"id": id, "name": name, "protocol": protocol,
				"listen_port": listenPort, "listen_stack": listenStack,
				"https_enabled": httpsEnabled, "https_port": httpsPort,
				"server_name": serverName, "lb_method": lbMethod,
				"ssl_cert_id": sslCertID, "ssl_redirect": sslRedirect,
				"hc_enabled": hcEnabled, "hc_interval": hcInterval, "hc_timeout": hcTimeout,
				"hc_path": hcPath, "hc_fall": hcFall, "hc_rise": hcRise,
				"log_max_size": logMaxSize, "custom_config": customConfig, "status": status,
				"servers": servers,
			})
		}
		rrows.Close()
	}

	fromAddr := c.ClientIP()
	db.DB.Exec(`INSERT INTO sync_nodes(name,address,last_sync_at,last_version,status)
		VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING`,
		fromAddr, fromAddr, time.Now().Format("2006-01-02 15:04:05"), version, "ok")
	db.DB.Exec(`UPDATE sync_nodes SET last_sync_at=?,last_version=?,status='ok',last_err=''
		WHERE address=?`, time.Now().Format("2006-01-02 15:04:05"), version, fromAddr)

	util.OK(c, gin.H{
		"version":       version,
		"generated_at":  time.Now().Format(time.RFC3339),
		"nginx_configs": configs,
		"rules":         rules,
	})
}

// SyncCertsExport 仅导出证书（使用 sync_certs_token 鉴权）
func SyncCertsExport(c *gin.Context) {
	token := c.Query("token")
	var saved string
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='sync_certs_token'`).Scan(&saved)
	if saved == "" || token != saved {
		util.Fail(c, 403, "token 无效")
		return
	}

	type certRow struct {
		domain, certPEM, keyPEM, expireAt string
		autoRenew                         int64
	}
	var rows []certRow
	crows, _ := db.DB.Query(`SELECT domain,cert_pem,key_pem,IFNULL(expire_at,''),IFNULL(auto_renew,0) FROM ssl_certs ORDER BY id`)
	if crows != nil {
		for crows.Next() {
			var r certRow
			crows.Scan(&r.domain, &r.certPEM, &r.keyPEM, &r.expireAt, &r.autoRenew)
			rows = append(rows, r)
		}
		crows.Close()
	}

	// 用证书内容哈希作为版本，无变化时从节点可跳过写盘
	h := sha256.New()
	domains := make([]string, len(rows))
	for i, r := range rows {
		domains[i] = r.domain
	}
	sort.Strings(domains)
	domainMap := make(map[string]certRow, len(rows))
	for _, r := range rows {
		domainMap[r.domain] = r
	}
	for _, d := range domains {
		r := domainMap[d]
		fmt.Fprintf(h, "%s|%s|%s\n", r.domain, r.expireAt, r.certPEM[:min(64, len(r.certPEM))])
	}
	version := fmt.Sprintf("%x", h.Sum(nil))[:16]

	certs := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		certs = append(certs, gin.H{
			"domain": r.domain, "cert_pem": r.certPEM, "key_pem": r.keyPEM,
			"expire_at": r.expireAt, "auto_renew": r.autoRenew,
		})
	}

	util.OK(c, gin.H{
		"version":      version,
		"generated_at": time.Now().Format(time.RFC3339),
		"certs":        certs,
	})
}

func TriggerRulesSync(c *gin.Context) {
	engine.TriggerRulesSync()
	util.OK(c, gin.H{"msg": "已触发规则同步"})
}

func TriggerCertsSync(c *gin.Context) {
	engine.TriggerCertsSync()
	util.OK(c, gin.H{"msg": "已触发证书同步"})
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
