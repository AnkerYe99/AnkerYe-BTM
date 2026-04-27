package handler

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"ankerye-flow/db"
	"ankerye-flow/engine"
	"ankerye-flow/util"
)

// upsertSyncNode 按 address 做 upsert，更新对应类型的最后同步时间。
// syncType: "rules" | "certs" | "filter" | "" (全量)
func upsertSyncNode(addr, version, syncType string) {
	now := time.Now().Format("2006-01-02 15:04:05")
	var q string
	switch syncType {
	case "rules":
		q = `INSERT INTO sync_nodes(name,address,last_sync_at,last_version,last_rules_sync_at,status,last_err)
			VALUES(?,?,?,?,?,?,?)
			ON CONFLICT(address) DO UPDATE SET
			last_sync_at=excluded.last_sync_at, last_version=excluded.last_version,
			last_rules_sync_at=excluded.last_rules_sync_at, status='ok', last_err=''`
	case "certs":
		q = `INSERT INTO sync_nodes(name,address,last_sync_at,last_version,last_certs_sync_at,status,last_err)
			VALUES(?,?,?,?,?,?,?)
			ON CONFLICT(address) DO UPDATE SET
			last_sync_at=excluded.last_sync_at, last_version=excluded.last_version,
			last_certs_sync_at=excluded.last_certs_sync_at, status='ok', last_err=''`
	case "filter":
		q = `INSERT INTO sync_nodes(name,address,last_sync_at,last_version,last_filter_sync_at,status,last_err)
			VALUES(?,?,?,?,?,?,?)
			ON CONFLICT(address) DO UPDATE SET
			last_sync_at=excluded.last_sync_at,
			last_filter_sync_at=excluded.last_filter_sync_at, status='ok', last_err=''`
	default:
		q = `INSERT INTO sync_nodes(name,address,last_sync_at,last_version,status,last_err)
			VALUES(?,?,?,?,?,?)
			ON CONFLICT(address) DO UPDATE SET
			last_sync_at=excluded.last_sync_at, last_version=excluded.last_version,
			status='ok', last_err=''`
		db.DB.Exec(q, addr, addr, now, version, "ok", "")
		return
	}
	db.DB.Exec(q, addr, addr, now, version, now, "ok", "")
}

// syncTombstones 返回指定表在 since 之后删除的 record_key 列表
func syncTombstones(tableName, since string) []string {
	var keys []string
	rows, _ := db.DB.Query(`SELECT record_key FROM sync_tombstones
		WHERE table_name=? AND deleted_at > ? ORDER BY id`, tableName, since)
	if rows != nil {
		for rows.Next() {
			var k string
			rows.Scan(&k)
			keys = append(keys, k)
		}
		rows.Close()
	}
	return keys
}

// ── 全量同步（兼容旧从节点）─────────────────────────────────────────

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

	certs := []gin.H{}
	certMap := map[string]gin.H{}
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

	fromAddr := c.ClientIP()
	upsertSyncNode(fromAddr, version, "")

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

// ── 规则同步（支持 ?since= 增量）──────────────────────────────────

func SyncRulesExport(c *gin.Context) {
	token := c.Query("token")
	var saved string
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='sync_rules_token'`).Scan(&saved)
	if saved == "" {
		db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='sync_token'`).Scan(&saved)
	}
	if saved == "" || token != saved {
		util.Fail(c, 403, "token 无效")
		return
	}

	since := strings.TrimSpace(c.Query("since"))
	fromAddr := c.ClientIP()

	// ── 增量模式 ────────────────────────────────────────────────────
	if since != "" {
		// 变更的规则
		changedRules := []gin.H{}
		rrows, _ := db.DB.Query(`SELECT id,name,protocol,listen_port,IFNULL(listen_stack,'both'),
			https_enabled,IFNULL(https_port,0),IFNULL(server_name,''),lb_method,
			IFNULL(ssl_cert_id,0),ssl_redirect,hc_enabled,hc_interval,hc_timeout,
			IFNULL(hc_path,'/'),hc_fall,hc_rise,IFNULL(log_max_size,'5M'),
			IFNULL(custom_config,''),status FROM rules WHERE updated_at > ? ORDER BY id`, since)
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
				changedRules = append(changedRules, gin.H{
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

		deletedIDs := syncTombstones("rules", since)

		// 即使规则无变化，也返回最新的 nginx 配置（保证文件一致）
		configs, version, _ := engine.ExportAll()

		upsertSyncNode(fromAddr, version, "rules")

		util.OK(c, gin.H{
			"is_incremental": true,
			"since":          since,
			"version":        version,
			"generated_at":   time.Now().Format(time.RFC3339),
			"nginx_configs":  configs,
			"changed_rules":  changedRules,
			"deleted_ids":    deletedIDs,
		})
		return
	}

	// ── 全量模式 ────────────────────────────────────────────────────
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

	filterBL := []gin.H{}
	blrows, _ := db.DB.Query(`SELECT type,value,note,hits,auto_added,enabled FROM filter_blacklist ORDER BY id`)
	if blrows != nil {
		for blrows.Next() {
			var typ, value, note string
			var hits, autoAdded, enabled int64
			blrows.Scan(&typ, &value, &note, &hits, &autoAdded, &enabled)
			filterBL = append(filterBL, gin.H{
				"type": typ, "value": value, "note": note,
				"hits": hits, "auto_added": autoAdded, "enabled": enabled,
			})
		}
		blrows.Close()
	}
	filterWL := []gin.H{}
	wlrows, _ := db.DB.Query(`SELECT type,value,note,enabled FROM filter_whitelist ORDER BY id`)
	if wlrows != nil {
		for wlrows.Next() {
			var typ, value, note string
			var enabled int64
			wlrows.Scan(&typ, &value, &note, &enabled)
			filterWL = append(filterWL, gin.H{
				"type": typ, "value": value, "note": note, "enabled": enabled,
			})
		}
		wlrows.Close()
	}

	upsertSyncNode(fromAddr, version, "rules")

	util.OK(c, gin.H{
		"is_incremental":   false,
		"version":          version,
		"generated_at":     time.Now().Format(time.RFC3339),
		"nginx_configs":    configs,
		"rules":            rules,
		"filter_blacklist": filterBL,
		"filter_whitelist": filterWL,
	})
}

// ── 证书同步（支持 ?since= 增量）──────────────────────────────────

func SyncCertsExport(c *gin.Context) {
	token := c.Query("token")
	var saved string
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='sync_certs_token'`).Scan(&saved)
	if saved == "" {
		db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='sync_token'`).Scan(&saved)
	}
	if saved == "" || token != saved {
		util.Fail(c, 403, "token 无效")
		return
	}

	since := strings.TrimSpace(c.Query("since"))
	fromAddr := c.ClientIP()

	// ── 增量模式 ────────────────────────────────────────────────────
	if since != "" {
		changedCerts := []gin.H{}
		crows, _ := db.DB.Query(`SELECT domain,cert_pem,key_pem,IFNULL(expire_at,''),IFNULL(auto_renew,0)
			FROM ssl_certs WHERE updated_at > ? ORDER BY id`, since)
		if crows != nil {
			for crows.Next() {
				var domain, certPEM, keyPEM, expireAt string
				var autoRenew int64
				crows.Scan(&domain, &certPEM, &keyPEM, &expireAt, &autoRenew)
				changedCerts = append(changedCerts, gin.H{
					"domain": domain, "cert_pem": certPEM, "key_pem": keyPEM,
					"expire_at": expireAt, "auto_renew": autoRenew,
				})
			}
			crows.Close()
		}

		deletedDomains := syncTombstones("ssl_certs", since)

		upsertSyncNode(fromAddr, "", "certs")

		util.OK(c, gin.H{
			"is_incremental":  true,
			"since":           since,
			"generated_at":    time.Now().Format(time.RFC3339),
			"changed_certs":   changedCerts,
			"deleted_domains": deletedDomains,
		})
		return
	}

	// ── 全量模式 ────────────────────────────────────────────────────
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

	upsertSyncNode(fromAddr, version, "certs")

	util.OK(c, gin.H{
		"is_incremental":  false,
		"version":         version,
		"generated_at":    time.Now().Format(time.RFC3339),
		"certs":           certs,
		"deleted_domains": nil,
	})
}

// ── 黑白名单同步（支持 ?since= 增量）─────────────────────────────

func SyncFilterExport(c *gin.Context) {
	token := c.Query("token")
	var expected string
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='sync_filter_token'`).Scan(&expected)
	if expected == "" {
		db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='sync_token'`).Scan(&expected)
	}
	if expected == "" || token != expected {
		util.Fail(c, 403, "token 无效")
		return
	}

	since := strings.TrimSpace(c.Query("since"))
	fromAddr := c.ClientIP()

	// ── 增量模式 ────────────────────────────────────────────────────
	if since != "" {
		changedBL := []gin.H{}
		blrows, _ := db.DB.Query(`SELECT type,value,note,hits,auto_added,enabled FROM filter_blacklist
			WHERE updated_at > ? ORDER BY id`, since)
		if blrows != nil {
			for blrows.Next() {
				var typ, value, note string
				var hits, autoAdded, enabled int64
				blrows.Scan(&typ, &value, &note, &hits, &autoAdded, &enabled)
				changedBL = append(changedBL, gin.H{
					"type": typ, "value": value, "note": note,
					"hits": hits, "auto_added": autoAdded, "enabled": enabled,
				})
			}
			blrows.Close()
		}
		changedWL := []gin.H{}
		wlrows, _ := db.DB.Query(`SELECT type,value,note,enabled FROM filter_whitelist
			WHERE updated_at > ? ORDER BY id`, since)
		if wlrows != nil {
			for wlrows.Next() {
				var typ, value, note string
				var enabled int64
				wlrows.Scan(&typ, &value, &note, &enabled)
				changedWL = append(changedWL, gin.H{
					"type": typ, "value": value, "note": note, "enabled": enabled,
				})
			}
			wlrows.Close()
		}
		deletedBL := syncTombstones("filter_blacklist", since)
		deletedWL := syncTombstones("filter_whitelist", since)

		upsertSyncNode(fromAddr, "", "filter")

		util.OK(c, gin.H{
			"is_incremental":         true,
			"since":                  since,
			"generated_at":           time.Now().Format(time.RFC3339),
			"changed_blacklist":      changedBL,
			"changed_whitelist":      changedWL,
			"deleted_blacklist_keys": deletedBL,
			"deleted_whitelist_keys": deletedWL,
		})
		return
	}

	// ── 全量模式 ────────────────────────────────────────────────────
	filterBL := []gin.H{}
	blrows, _ := db.DB.Query(`SELECT type,value,note,hits,auto_added,enabled FROM filter_blacklist ORDER BY id`)
	if blrows != nil {
		for blrows.Next() {
			var typ, value, note string
			var hits, autoAdded, enabled int64
			blrows.Scan(&typ, &value, &note, &hits, &autoAdded, &enabled)
			filterBL = append(filterBL, gin.H{
				"type": typ, "value": value, "note": note,
				"hits": hits, "auto_added": autoAdded, "enabled": enabled,
			})
		}
		blrows.Close()
	}

	filterWL := []gin.H{}
	wlrows, _ := db.DB.Query(`SELECT type,value,note,enabled FROM filter_whitelist ORDER BY id`)
	if wlrows != nil {
		for wlrows.Next() {
			var typ, value, note string
			var enabled int64
			wlrows.Scan(&typ, &value, &note, &enabled)
			filterWL = append(filterWL, gin.H{
				"type": typ, "value": value, "note": note, "enabled": enabled,
			})
		}
		wlrows.Close()
	}

	upsertSyncNode(fromAddr, "", "filter")

	util.OK(c, gin.H{
		"is_incremental":   false,
		"generated_at":     time.Now().Format(time.RFC3339),
		"filter_blacklist": filterBL,
		"filter_whitelist": filterWL,
	})
}

// ── 触发接口 ───────────────────────────────────────────────────────

func TriggerRulesSync(c *gin.Context) {
	engine.TriggerRulesSync()
	util.OK(c, gin.H{"msg": "已触发规则同步"})
}

func TriggerCertsSync(c *gin.Context) {
	engine.TriggerCertsSync()
	util.OK(c, gin.H{"msg": "已触发证书同步"})
}

func TriggerFilterSync(c *gin.Context) {
	engine.TriggerFilterSync()
	util.OK(c, gin.H{"msg": "已触发黑名单同步"})
}

// ── 从节点管理 ────────────────────────────────────────────────────

func ListSyncNodes(c *gin.Context) {
	rows, _ := db.DB.Query(`SELECT id,name,address,
		IFNULL(last_sync_at,''),IFNULL(last_version,''),
		IFNULL(last_rules_sync_at,''),IFNULL(last_certs_sync_at,''),IFNULL(last_filter_sync_at,''),
		status,IFNULL(last_err,''),created_at
		FROM sync_nodes ORDER BY last_sync_at DESC`)
	if rows == nil {
		util.OK(c, []gin.H{})
		return
	}
	defer rows.Close()
	list := []gin.H{}
	for rows.Next() {
		var id int64
		var name, addr, lastSync, lastVer, lastRules, lastCerts, lastFilter, status, lastErr, createdAt string
		rows.Scan(&id, &name, &addr, &lastSync, &lastVer, &lastRules, &lastCerts, &lastFilter, &status, &lastErr, &createdAt)
		list = append(list, gin.H{
			"id": id, "name": name, "address": addr,
			"last_sync_at":        lastSync,
			"last_version":        lastVer,
			"last_rules_sync_at":  lastRules,
			"last_certs_sync_at":  lastCerts,
			"last_filter_sync_at": lastFilter,
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
	res, err := db.DB.Exec(`INSERT INTO sync_nodes(name,address) VALUES(?,?)
		ON CONFLICT(address) DO UPDATE SET name=excluded.name`, req.Name, req.Address)
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
