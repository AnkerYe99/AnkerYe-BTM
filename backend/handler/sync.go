package handler

import (
	"crypto/md5"
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"ankerye-flow/db"
	"ankerye-flow/engine"
	"ankerye-flow/util"
)

// ── Token 工具 ────────────────────────────────────────────────────────────────

func getSyncToken(specificKey string) string {
	var v string
	if specificKey != "" {
		db.DB.QueryRow(`SELECT v FROM system_settings WHERE k=?`, specificKey).Scan(&v)
	}
	if v == "" {
		db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='sync_token'`).Scan(&v)
	}
	return v
}

// ── upsertSyncNode ────────────────────────────────────────────────────────────

func upsertSyncNode(addr, version, syncType string) {
	now := time.Now().Format("2006-01-02 15:04:05")
	var col string
	switch syncType {
	case "rules":
		col = "last_rules_sync_at"
	case "certs":
		col = "last_certs_sync_at"
	case "filter":
		col = "last_filter_sync_at"
	}

	if col != "" {
		q := fmt.Sprintf(`INSERT INTO sync_nodes(name,address,last_sync_at,last_version,%s,status,last_err)
			VALUES(?,?,?,?,?,?,?)
			ON CONFLICT(address) DO UPDATE SET
			last_sync_at=excluded.last_sync_at, last_version=excluded.last_version,
			%s=excluded.%s, status='ok', last_err=''`, col, col, col)
		db.DB.Exec(q, addr, addr, now, version, now, "ok", "")
	} else {
		db.DB.Exec(`INSERT INTO sync_nodes(name,address,last_sync_at,last_version,status,last_err)
			VALUES(?,?,?,?,?,?)
			ON CONFLICT(address) DO UPDATE SET
			last_sync_at=excluded.last_sync_at, last_version=excluded.last_version,
			status='ok', last_err=''`, addr, addr, now, version, "ok", "")
	}
}

// ── MD5 计算 ─────────────────────────────────────────────────────────────────
//
// 规则规范格式（主从两侧必须完全一致）：
//   规则按 id ASC 排序，每条写一行：
//     R:{id}|{name}|{protocol}|{listen_port}|{listen_stack}|{https_enabled}|{https_port}|
//       {server_name}|{lb_method}|{ssl_cert_id}|{ssl_redirect}|{hc_enabled}|{hc_interval}|
//       {hc_timeout}|{hc_path}|{hc_fall}|{hc_rise}|{log_max_size}|{custom_config}|{status}
//   上游服务器按 address ASC, port ASC 排序，紧跟其所属规则行之后：
//     S:{address}|{port}|{weight}|{state}

type ruleForExport struct {
	ID             int64
	Name           string
	Protocol       string
	ListenPort     int64
	ListenStack    string
	HttpsEnabled   int64
	HttpsPort      int64
	ServerName     string
	LbMethod       string
	SslCertID      int64
	SslRedirect    int64
	HcEnabled      int64
	HcInterval     int64
	HcTimeout      int64
	HcPath         string
	HcHost         string
	HcFall         int64
	HcRise         int64
	LogMaxSize     string
	CaptureMaxSize string
	CustomConfig   string
	CaptureBody    int64
	Status         int64
	Servers        []serverForExport
}

type serverForExport struct {
	Address string
	Port    int64
	Weight  int64
	State   string
}

func queryRulesForExport() []ruleForExport {
	var rules []ruleForExport
	rrows, _ := db.DB.Query(`SELECT id,name,protocol,listen_port,IFNULL(listen_stack,'both'),
		https_enabled,IFNULL(https_port,0),IFNULL(server_name,''),lb_method,
		IFNULL(ssl_cert_id,0),ssl_redirect,hc_enabled,hc_interval,hc_timeout,
		IFNULL(hc_path,'/'),IFNULL(hc_host,''),hc_fall,hc_rise,IFNULL(log_max_size,'5M'),
		IFNULL(capture_max_size,'5M'),IFNULL(custom_config,''),IFNULL(capture_body,0),status
		FROM rules ORDER BY id ASC`)
	if rrows == nil {
		return rules
	}
	defer rrows.Close()
	for rrows.Next() {
		var r ruleForExport
		rrows.Scan(&r.ID, &r.Name, &r.Protocol, &r.ListenPort, &r.ListenStack,
			&r.HttpsEnabled, &r.HttpsPort, &r.ServerName, &r.LbMethod,
			&r.SslCertID, &r.SslRedirect, &r.HcEnabled, &r.HcInterval, &r.HcTimeout,
			&r.HcPath, &r.HcHost, &r.HcFall, &r.HcRise, &r.LogMaxSize, &r.CaptureMaxSize,
			&r.CustomConfig, &r.CaptureBody, &r.Status)
		rules = append(rules, r)
	}
	for i := range rules {
		srows, _ := db.DB.Query(`SELECT address,port,weight,state FROM upstream_servers
			WHERE rule_id=? ORDER BY address ASC, port ASC`, rules[i].ID)
		if srows != nil {
			for srows.Next() {
				var s serverForExport
				srows.Scan(&s.Address, &s.Port, &s.Weight, &s.State)
				rules[i].Servers = append(rules[i].Servers, s)
			}
			srows.Close()
		}
	}
	return rules
}

func hashRules(rules []ruleForExport) string {
	h := md5.New()
	for _, r := range rules {
		fmt.Fprintf(h, "R:%d|%q|%q|%d|%q|%d|%d|%q|%q|%d|%d|%d|%d|%d|%q|%q|%d|%d|%q|%q|%q|%d|%d\n",
			r.ID, r.Name, r.Protocol, r.ListenPort, r.ListenStack,
			r.HttpsEnabled, r.HttpsPort, r.ServerName, r.LbMethod,
			r.SslCertID, r.SslRedirect, r.HcEnabled, r.HcInterval, r.HcTimeout,
			r.HcPath, r.HcHost, r.HcFall, r.HcRise, r.LogMaxSize, r.CaptureMaxSize, r.CustomConfig, r.CaptureBody, r.Status)
		for _, s := range r.Servers {
			fmt.Fprintf(h, "S:%q|%d|%d|%q\n", s.Address, s.Port, s.Weight, s.State)
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// 证书规范格式：按 domain ASC 排序，每条：C:{domain}|{cert_pem}

type certForExport struct {
	Domain    string
	CertPEM   string
	KeyPEM    string
	ExpireAt  string
	AutoRenew int64
}

func queryCertsForExport() []certForExport {
	var certs []certForExport
	rows, _ := db.DB.Query(`SELECT domain,cert_pem,key_pem,IFNULL(expire_at,''),IFNULL(auto_renew,0)
		FROM ssl_certs ORDER BY domain ASC`)
	if rows == nil {
		return certs
	}
	defer rows.Close()
	for rows.Next() {
		var c certForExport
		rows.Scan(&c.Domain, &c.CertPEM, &c.KeyPEM, &c.ExpireAt, &c.AutoRenew)
		certs = append(certs, c)
	}
	return certs
}

func hashCerts(certs []certForExport) string {
	h := md5.New()
	for _, c := range certs {
		fmt.Fprintf(h, "C:%q|%q\n", c.Domain, c.CertPEM)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// 过滤规范格式：
//   黑名单按 type ASC, value ASC：B:{type}|{value}|{note}|{enabled}
//   白名单按 type ASC, value ASC：W:{type}|{value}|{note}|{enabled}

type blItemForExport struct {
	Type      string
	Value     string
	Note      string
	Hits      int64
	AutoAdded int64
	Enabled   int64
}

type wlItemForExport struct {
	Type    string
	Value   string
	Note    string
	Enabled int64
}

func queryFilterForExport() ([]blItemForExport, []wlItemForExport) {
	var bl []blItemForExport
	blrows, _ := db.DB.Query(`SELECT type,value,note,hits,auto_added,enabled
		FROM filter_blacklist ORDER BY type ASC, value ASC`)
	if blrows != nil {
		for blrows.Next() {
			var item blItemForExport
			blrows.Scan(&item.Type, &item.Value, &item.Note, &item.Hits, &item.AutoAdded, &item.Enabled)
			bl = append(bl, item)
		}
		blrows.Close()
	}

	var wl []wlItemForExport
	wlrows, _ := db.DB.Query(`SELECT type,value,note,enabled
		FROM filter_whitelist ORDER BY type ASC, value ASC`)
	if wlrows != nil {
		for wlrows.Next() {
			var item wlItemForExport
			wlrows.Scan(&item.Type, &item.Value, &item.Note, &item.Enabled)
			wl = append(wl, item)
		}
		wlrows.Close()
	}
	return bl, wl
}

func hashFilter(bl []blItemForExport, wl []wlItemForExport) string {
	h := md5.New()
	for _, item := range bl {
		fmt.Fprintf(h, "B:%q|%q|%q|%d\n", item.Type, item.Value, item.Note, item.Enabled)
	}
	for _, item := range wl {
		fmt.Fprintf(h, "W:%q|%q|%q|%d\n", item.Type, item.Value, item.Note, item.Enabled)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ── 全量同步（兼容旧从节点）──────────────────────────────────────────────────

func SyncExport(c *gin.Context) {
	token := c.Query("token")
	saved := getSyncToken("")
	if saved == "" || token != saved {
		util.Fail(c, 403, "token 无效")
		return
	}

	configs, version, err := engine.ExportAll()
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}

	rules := queryRulesForExport()
	rulesJSON := make([]gin.H, 0, len(rules))
	for _, r := range rules {
		servers := make([]gin.H, 0, len(r.Servers))
		for _, s := range r.Servers {
			servers = append(servers, gin.H{"address": s.Address, "port": s.Port, "weight": s.Weight, "state": s.State})
		}
		rulesJSON = append(rulesJSON, gin.H{
			"id": r.ID, "name": r.Name, "protocol": r.Protocol,
			"listen_port": r.ListenPort, "listen_stack": r.ListenStack,
			"https_enabled": r.HttpsEnabled, "https_port": r.HttpsPort,
			"server_name": r.ServerName, "lb_method": r.LbMethod,
			"ssl_cert_id": r.SslCertID, "ssl_redirect": r.SslRedirect,
			"hc_enabled": r.HcEnabled, "hc_interval": r.HcInterval, "hc_timeout": r.HcTimeout,
			"hc_path": r.HcPath, "hc_host": r.HcHost, "hc_fall": r.HcFall, "hc_rise": r.HcRise,
			"log_max_size": r.LogMaxSize, "capture_max_size": r.CaptureMaxSize,
			"custom_config": r.CustomConfig, "capture_body": r.CaptureBody, "status": r.Status,
			"servers": servers,
		})
	}

	certs := queryCertsForExport()
	certsJSON := make([]gin.H, 0, len(certs))
	certMap := map[string]gin.H{}
	for _, c2 := range certs {
		certsJSON = append(certsJSON, gin.H{
			"domain": c2.Domain, "cert_pem": c2.CertPEM, "key_pem": c2.KeyPEM,
			"expire_at": c2.ExpireAt, "auto_renew": c2.AutoRenew,
		})
		certMap[c2.Domain] = gin.H{"cert_pem": c2.CertPEM, "key_pem": c2.KeyPEM}
	}

	fromAddr := c.ClientIP()
	upsertSyncNode(fromAddr, version, "")

	util.OK(c, gin.H{
		"version":       version,
		"generated_at":  time.Now().Format(time.RFC3339),
		"nginx_configs": configs,
		"rules":         rulesJSON,
		"certs":         certsJSON,
		"cert_map":      certMap,
	})
}

// ── 规则同步（MD5 比对，不一致则全量下发）────────────────────────────────────

func SyncRulesExport(c *gin.Context) {
	token := c.Query("token")
	saved := getSyncToken("sync_rules_token")
	if saved == "" || token != saved {
		util.Fail(c, 403, "token 无效")
		return
	}

	slaveMD5 := c.Query("md5")
	fromAddr := c.ClientIP()

	rules := queryRulesForExport()
	masterMD5 := hashRules(rules)

	if slaveMD5 != "" && slaveMD5 == masterMD5 {
		upsertSyncNode(fromAddr, masterMD5, "rules")
		util.OK(c, gin.H{"match": true, "master_md5": masterMD5})
		return
	}

	configs, version, _ := engine.ExportAll()

	bl, wl := queryFilterForExport()

	rulesJSON := make([]gin.H, 0, len(rules))
	for _, r := range rules {
		servers := make([]gin.H, 0, len(r.Servers))
		for _, s := range r.Servers {
			servers = append(servers, gin.H{"address": s.Address, "port": s.Port, "weight": s.Weight, "state": s.State})
		}
		rulesJSON = append(rulesJSON, gin.H{
			"id": r.ID, "name": r.Name, "protocol": r.Protocol,
			"listen_port": r.ListenPort, "listen_stack": r.ListenStack,
			"https_enabled": r.HttpsEnabled, "https_port": r.HttpsPort,
			"server_name": r.ServerName, "lb_method": r.LbMethod,
			"ssl_cert_id": r.SslCertID, "ssl_redirect": r.SslRedirect,
			"hc_enabled": r.HcEnabled, "hc_interval": r.HcInterval, "hc_timeout": r.HcTimeout,
			"hc_path": r.HcPath, "hc_host": r.HcHost, "hc_fall": r.HcFall, "hc_rise": r.HcRise,
			"log_max_size": r.LogMaxSize, "capture_max_size": r.CaptureMaxSize,
			"custom_config": r.CustomConfig, "capture_body": r.CaptureBody, "status": r.Status,
			"servers": servers,
		})
	}

	blJSON := make([]gin.H, 0, len(bl))
	for _, item := range bl {
		blJSON = append(blJSON, gin.H{
			"type": item.Type, "value": item.Value, "note": item.Note,
			"hits": item.Hits, "auto_added": item.AutoAdded, "enabled": item.Enabled,
		})
	}
	wlJSON := make([]gin.H, 0, len(wl))
	for _, item := range wl {
		wlJSON = append(wlJSON, gin.H{
			"type": item.Type, "value": item.Value, "note": item.Note, "enabled": item.Enabled,
		})
	}

	upsertSyncNode(fromAddr, version, "rules")

	util.OK(c, gin.H{
		"match":            false,
		"master_md5":       masterMD5,
		"version":          version,
		"generated_at":     time.Now().Format(time.RFC3339),
		"nginx_configs":    configs,
		"rules":            rulesJSON,
		"filter_blacklist": blJSON,
		"filter_whitelist": wlJSON,
	})
}

// ── 证书同步（MD5 比对）──────────────────────────────────────────────────────

func SyncCertsExport(c *gin.Context) {
	token := c.Query("token")
	saved := getSyncToken("sync_certs_token")
	if saved == "" || token != saved {
		util.Fail(c, 403, "token 无效")
		return
	}

	slaveMD5 := c.Query("md5")
	fromAddr := c.ClientIP()

	certs := queryCertsForExport()
	masterMD5 := hashCerts(certs)

	if slaveMD5 != "" && slaveMD5 == masterMD5 {
		upsertSyncNode(fromAddr, masterMD5, "certs")
		util.OK(c, gin.H{"match": true, "master_md5": masterMD5})
		return
	}

	certsJSON := make([]gin.H, 0, len(certs))
	for _, c2 := range certs {
		certsJSON = append(certsJSON, gin.H{
			"domain": c2.Domain, "cert_pem": c2.CertPEM, "key_pem": c2.KeyPEM,
			"expire_at": c2.ExpireAt, "auto_renew": c2.AutoRenew,
		})
	}

	upsertSyncNode(fromAddr, masterMD5, "certs")

	util.OK(c, gin.H{
		"match":        false,
		"master_md5":   masterMD5,
		"generated_at": time.Now().Format(time.RFC3339),
		"certs":        certsJSON,
	})
}

// ── 黑白名单同步（MD5 比对）──────────────────────────────────────────────────

func SyncFilterExport(c *gin.Context) {
	token := c.Query("token")
	saved := getSyncToken("sync_filter_token")
	if saved == "" || token != saved {
		util.Fail(c, 403, "token 无效")
		return
	}

	slaveMD5 := c.Query("md5")
	fromAddr := c.ClientIP()

	bl, wl := queryFilterForExport()
	masterMD5 := hashFilter(bl, wl)

	if slaveMD5 != "" && slaveMD5 == masterMD5 {
		upsertSyncNode(fromAddr, masterMD5, "filter")
		util.OK(c, gin.H{"match": true, "master_md5": masterMD5})
		return
	}

	blJSON := make([]gin.H, 0, len(bl))
	for _, item := range bl {
		blJSON = append(blJSON, gin.H{
			"type": item.Type, "value": item.Value, "note": item.Note,
			"hits": item.Hits, "auto_added": item.AutoAdded, "enabled": item.Enabled,
		})
	}
	wlJSON := make([]gin.H, 0, len(wl))
	for _, item := range wl {
		wlJSON = append(wlJSON, gin.H{
			"type": item.Type, "value": item.Value, "note": item.Note, "enabled": item.Enabled,
		})
	}

	upsertSyncNode(fromAddr, masterMD5, "filter")

	util.OK(c, gin.H{
		"match":            false,
		"master_md5":       masterMD5,
		"generated_at":     time.Now().Format(time.RFC3339),
		"filter_blacklist": blJSON,
		"filter_whitelist": wlJSON,
	})
}

// ── 触发接口 ──────────────────────────────────────────────────────────────────

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

// ── 从节点管理 ────────────────────────────────────────────────────────────────

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
