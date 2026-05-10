package engine

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ankerye-flow/config"
	"ankerye-flow/db"
)

// ── 触发通道 ──────────────────────────────────────────────────────────────────

var rulesForceSync = make(chan struct{}, 1)
var certsForceSync = make(chan struct{}, 1)
var filterForceSync = make(chan struct{}, 1)

var syncHTTPClient = &http.Client{Timeout: 120 * time.Second}

func TriggerRulesSync() {
	select {
	case rulesForceSync <- struct{}{}:
	default:
	}
}

func TriggerCertsSync() {
	select {
	case certsForceSync <- struct{}{}:
	default:
	}
}

func TriggerFilterSync() {
	select {
	case filterForceSync <- struct{}{}:
	default:
	}
}

// ── 数据结构 ──────────────────────────────────────────────────────────────────

type syncServer struct {
	Address string `json:"address"`
	Port    int64  `json:"port"`
	Weight  int64  `json:"weight"`
	State   string `json:"state"`
}

type syncRule struct {
	ID             int64        `json:"id"`
	Name           string       `json:"name"`
	Protocol       string       `json:"protocol"`
	ListenPort     int64        `json:"listen_port"`
	ListenStack    string       `json:"listen_stack"`
	HttpsEnabled   int64        `json:"https_enabled"`
	HttpsPort      int64        `json:"https_port"`
	ServerName     string       `json:"server_name"`
	LbMethod       string       `json:"lb_method"`
	SslCertID      int64        `json:"ssl_cert_id"`
	SslRedirect    int64        `json:"ssl_redirect"`
	HcEnabled      int64        `json:"hc_enabled"`
	HcInterval     int64        `json:"hc_interval"`
	HcTimeout      int64        `json:"hc_timeout"`
	HcPath         string       `json:"hc_path"`
	HcHost         string       `json:"hc_host"`
	HcFall         int64        `json:"hc_fall"`
	HcRise         int64        `json:"hc_rise"`
	LogMaxSize     string       `json:"log_max_size"`
	CaptureMaxSize string       `json:"capture_max_size"`
	CustomConfig   string       `json:"custom_config"`
	CaptureBody    int64        `json:"capture_body"`
	Status         int64        `json:"status"`
	Servers        []syncServer `json:"servers"`
}

type syncCert struct {
	Domain    string `json:"domain"`
	CertPEM   string `json:"cert_pem"`
	KeyPEM    string `json:"key_pem"`
	ExpireAt  string `json:"expire_at"`
	AutoRenew int64  `json:"auto_renew"`
}

type syncFilterItem struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Note      string `json:"note"`
	Hits      int64  `json:"hits"`
	AutoAdded int64  `json:"auto_added"`
	Enabled   int64  `json:"enabled"`
}

type syncFilterWLItem struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Note    string `json:"note"`
	Enabled int64  `json:"enabled"`
}

// ── 响应结构 ──────────────────────────────────────────────────────────────────

type syncRulesResp struct {
	Code int `json:"code"`
	Data struct {
		Match           bool              `json:"match"`
		MasterMD5       string            `json:"master_md5"`
		Version         string            `json:"version"`
		NginxConfigs    map[string]string `json:"nginx_configs"`
		Rules           []syncRule        `json:"rules"`
		FilterBlacklist []syncFilterItem  `json:"filter_blacklist"`
		FilterWhitelist []syncFilterWLItem `json:"filter_whitelist"`
	} `json:"data"`
}

type syncCertsResp struct {
	Code int `json:"code"`
	Data struct {
		Match     bool       `json:"match"`
		MasterMD5 string     `json:"master_md5"`
		Certs     []syncCert `json:"certs"`
	} `json:"data"`
}

type syncFilterResp struct {
	Code int `json:"code"`
	Data struct {
		Match           bool               `json:"match"`
		MasterMD5       string             `json:"master_md5"`
		FilterBlacklist []syncFilterItem   `json:"filter_blacklist"`
		FilterWhitelist []syncFilterWLItem `json:"filter_whitelist"`
	} `json:"data"`
}

// 旧版全量同步响应（兼容）
type syncExportResp struct {
	Code int `json:"code"`
	Data struct {
		Version      string            `json:"version"`
		GeneratedAt  string            `json:"generated_at"`
		NginxConfigs map[string]string `json:"nginx_configs"`
		Rules        []syncRule        `json:"rules"`
		Certs        json.RawMessage   `json:"certs"`
		Settings     map[string]string `json:"settings"`
	} `json:"data"`
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

func getSetting(k string) string {
	var v string
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k=?`, k).Scan(&v)
	return v
}

func setSyncStatus(prefix, status, msg string) {
	now := time.Now().Format("2006-01-02 15:04:05")
	for _, kv := range [][2]string{
		{prefix + "_last_sync_at", now},
		{prefix + "_last_status", status},
		{prefix + "_last_msg", msg},
	} {
		db.AsyncExec(`INSERT INTO system_settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, kv[0], kv[1])
	}
}

func getInterval(val string) time.Duration {
	n, _ := strconv.Atoi(val)
	if n < 10 {
		n = 60
	}
	return time.Duration(n) * time.Second
}

func shortV(v string) string {
	if len(v) > 16 {
		return v[:16]
	}
	return v
}

// ── 本地 MD5 计算（格式必须与 handler/sync.go 完全一致）────────────────────────
//
// 规则：按 id ASC；服务器按 address ASC, port ASC
//   R:{id}|{name}|{protocol}|{listen_port}|...（%q 字符串，%d 整数）
//   S:{address}|{port}|{weight}|{state}
// 证书：按 domain ASC
//   C:{domain}|{cert_pem}
// 过滤：黑名单按 type,value ASC；白名单按 type,value ASC
//   B:{type}|{value}|{note}|{enabled}
//   W:{type}|{value}|{note}|{enabled}

func localRulesMD5() string {
	h := md5.New()

	type row struct {
		id, listenPort, httpsEnabled, httpsPort, sslCertID, sslRedirect int64
		hcEnabled, hcInterval, hcTimeout, hcFall, hcRise, status        int64
		captureBody                                                       int64
		name, protocol, listenStack, serverName, lbMethod                string
		hcPath, logMaxSize, captureMaxSize, customConfig                  string
	}

	var rules []row
	rrows, _ := db.DB.Query(`SELECT id,name,protocol,listen_port,IFNULL(listen_stack,'both'),
		https_enabled,IFNULL(https_port,0),IFNULL(server_name,''),lb_method,
		IFNULL(ssl_cert_id,0),ssl_redirect,hc_enabled,hc_interval,hc_timeout,
		IFNULL(hc_path,'/'),hc_fall,hc_rise,IFNULL(log_max_size,'5M'),
		IFNULL(capture_max_size,'5M'),IFNULL(custom_config,''),IFNULL(capture_body,0),status FROM rules ORDER BY id ASC`)
	if rrows != nil {
		for rrows.Next() {
			var r row
			rrows.Scan(&r.id, &r.name, &r.protocol, &r.listenPort, &r.listenStack,
				&r.httpsEnabled, &r.httpsPort, &r.serverName, &r.lbMethod,
				&r.sslCertID, &r.sslRedirect, &r.hcEnabled, &r.hcInterval, &r.hcTimeout,
				&r.hcPath, &r.hcFall, &r.hcRise, &r.logMaxSize,
				&r.captureMaxSize, &r.customConfig, &r.captureBody, &r.status)
			rules = append(rules, r)
		}
		rrows.Close()
	}

	type srow struct{ address, state string; port, weight int64 }
	for _, r := range rules {
		fmt.Fprintf(h, "R:%d|%q|%q|%d|%q|%d|%d|%q|%q|%d|%d|%d|%d|%d|%q|%d|%d|%q|%q|%q|%d|%d\n",
			r.id, r.name, r.protocol, r.listenPort, r.listenStack,
			r.httpsEnabled, r.httpsPort, r.serverName, r.lbMethod,
			r.sslCertID, r.sslRedirect, r.hcEnabled, r.hcInterval, r.hcTimeout,
			r.hcPath, r.hcFall, r.hcRise, r.logMaxSize, r.captureMaxSize, r.customConfig, r.captureBody, r.status)

		srows, _ := db.DB.Query(`SELECT address,port,weight,state FROM upstream_servers
			WHERE rule_id=? ORDER BY address ASC, port ASC`, r.id)
		if srows != nil {
			for srows.Next() {
				var s srow
				srows.Scan(&s.address, &s.port, &s.weight, &s.state)
				fmt.Fprintf(h, "S:%q|%d|%d|%q\n", s.address, s.port, s.weight, s.state)
			}
			srows.Close()
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func localCertsMD5() string {
	h := md5.New()
	rows, _ := db.DB.Query(`SELECT domain,cert_pem FROM ssl_certs ORDER BY domain ASC`)
	if rows != nil {
		for rows.Next() {
			var domain, certPEM string
			rows.Scan(&domain, &certPEM)
			fmt.Fprintf(h, "C:%q|%q\n", domain, certPEM)
		}
		rows.Close()
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func localFilterMD5() string {
	h := md5.New()
	blrows, _ := db.DB.Query(`SELECT type,value,note,enabled FROM filter_blacklist ORDER BY type ASC, value ASC`)
	if blrows != nil {
		for blrows.Next() {
			var typ, value, note string
			var enabled int64
			blrows.Scan(&typ, &value, &note, &enabled)
			fmt.Fprintf(h, "B:%q|%q|%q|%d\n", typ, value, note, enabled)
		}
		blrows.Close()
	}
	wlrows, _ := db.DB.Query(`SELECT type,value,note,enabled FROM filter_whitelist ORDER BY type ASC, value ASC`)
	if wlrows != nil {
		for wlrows.Next() {
			var typ, value, note string
			var enabled int64
			wlrows.Scan(&typ, &value, &note, &enabled)
			fmt.Fprintf(h, "W:%q|%q|%q|%d\n", typ, value, note, enabled)
		}
		wlrows.Close()
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ── 规则同步 agent ────────────────────────────────────────────────────────────

func StartSlaveRulesSyncAgent() {
	for {
		masterURL := getSetting("slave_rules_url")
		token := getSetting("slave_rules_token")
		interval := getInterval(getSetting("slave_rules_interval"))

		if masterURL != "" && token != "" && getSetting("slave_rules_enabled") != "0" {
			if err := pullAndApplyRules(masterURL, token); err != nil {
				log.Printf("[slave-rules] 同步失败: %v", err)
				setSyncStatus("slave_rules", "error", err.Error())
			}
		}
		select {
		case <-rulesForceSync:
		case <-time.After(interval):
		}
	}
}

func pullAndApplyRules(masterURL, token string) error {
	masterURL = strings.TrimRight(masterURL, "/")

	localMD5 := localRulesMD5()
	reqURL := fmt.Sprintf("%s/api/v1/sync/rules_export?token=%s&md5=%s", masterURL, token, localMD5)

	resp, err := syncHTTPClient.Get(reqURL)
	if err != nil {
		return fmt.Errorf("请求主节点失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("主节点返回 %d: %s", resp.StatusCode, string(body))
	}

	var result syncRulesResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("解析响应失败: %v", err)
	}
	if result.Code != 0 {
		return fmt.Errorf("主节点返回错误码 %d", result.Code)
	}

	if result.Data.Match {
		setSyncStatus("slave_rules", "ok", "规则已是最新")
		return nil
	}

	return applyRulesFull(result)
}

func applyRulesFull(result syncRulesResp) error {
	confDir := config.Global.Nginx.ConfDir
	if err := os.MkdirAll(confDir, 0755); err != nil {
		return fmt.Errorf("创建 conf 目录失败: %v", err)
	}
	for filename, content := range result.Data.NginxConfigs {
		if err := os.WriteFile(filepath.Join(confDir, filename), []byte(content), 0644); err != nil {
			return fmt.Errorf("写入 %s 失败: %v", filename, err)
		}
	}

	masterCount := len(result.Data.Rules)
	if masterCount > 0 {
		masterIDs := make([]interface{}, masterCount)
		ph := make([]string, masterCount)
		for i, r := range result.Data.Rules {
			masterIDs[i] = r.ID
			ph[i] = "?"
		}
		db.DB.Exec("DELETE FROM rules WHERE id NOT IN ("+strings.Join(ph, ",")+
			") AND id IS NOT NULL", masterIDs...)
		upsertRules(result.Data.Rules)
	} else {
		db.DB.Exec(`DELETE FROM rules`)
		db.DB.Exec(`DELETE FROM upstream_servers`)
	}

	applyFilterFromRulesResp(result)

	if err := Reload(); err != nil {
		return fmt.Errorf("nginx 重载失败: %v", err)
	}

	msg := fmt.Sprintf("同步完成，规则 %d 条（MD5: %s）", masterCount, shortV(result.Data.MasterMD5))
	setSyncStatus("slave_rules", "ok", msg)
	log.Printf("[slave-rules] %s", msg)
	return nil
}

func upsertRules(rules []syncRule) {
	for _, r := range rules {
		var sslCertID interface{}
		if r.SslCertID > 0 {
			sslCertID = r.SslCertID
		}
		captureMaxSize := r.CaptureMaxSize
		if captureMaxSize == "" {
			captureMaxSize = "5M"
		}
		db.DB.Exec(`INSERT INTO rules(id,name,protocol,listen_port,listen_stack,
			https_enabled,https_port,server_name,lb_method,ssl_cert_id,ssl_redirect,
			hc_enabled,hc_interval,hc_timeout,hc_path,hc_host,hc_fall,hc_rise,
			log_max_size,capture_max_size,custom_config,capture_body,status)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, protocol=excluded.protocol, listen_port=excluded.listen_port,
			listen_stack=excluded.listen_stack, https_enabled=excluded.https_enabled,
			https_port=excluded.https_port, server_name=excluded.server_name,
			lb_method=excluded.lb_method, ssl_cert_id=excluded.ssl_cert_id,
			ssl_redirect=excluded.ssl_redirect, hc_enabled=excluded.hc_enabled,
			hc_interval=excluded.hc_interval, hc_timeout=excluded.hc_timeout,
			hc_path=excluded.hc_path, hc_host=excluded.hc_host,
			hc_fall=excluded.hc_fall, hc_rise=excluded.hc_rise,
			log_max_size=excluded.log_max_size, capture_max_size=excluded.capture_max_size,
			custom_config=excluded.custom_config, capture_body=excluded.capture_body,
			status=excluded.status`,
			r.ID, r.Name, r.Protocol, r.ListenPort, r.ListenStack,
			r.HttpsEnabled, r.HttpsPort, r.ServerName, r.LbMethod, sslCertID, r.SslRedirect,
			r.HcEnabled, r.HcInterval, r.HcTimeout, r.HcPath, r.HcHost, r.HcFall, r.HcRise,
			r.LogMaxSize, captureMaxSize, r.CustomConfig, r.CaptureBody, r.Status)

		db.DB.Exec(`DELETE FROM upstream_servers WHERE rule_id=?`, r.ID)
		for _, s := range r.Servers {
			db.DB.Exec(`INSERT INTO upstream_servers(rule_id,address,port,weight,state) VALUES(?,?,?,?,?)`,
				r.ID, s.Address, s.Port, s.Weight, s.State)
		}
	}
}

func applyFilterFromRulesResp(result syncRulesResp) {
	if len(result.Data.FilterBlacklist) == 0 && len(result.Data.FilterWhitelist) == 0 {
		return
	}
	db.DB.Exec(`DELETE FROM filter_blacklist WHERE auto_added=0`)
	for _, item := range result.Data.FilterBlacklist {
		db.DB.Exec(`INSERT OR IGNORE INTO filter_blacklist(type,value,note,hits,auto_added,enabled) VALUES(?,?,?,?,?,?)`,
			item.Type, item.Value, item.Note, item.Hits, item.AutoAdded, item.Enabled)
	}
	db.DB.Exec(`DELETE FROM filter_whitelist`)
	for _, item := range result.Data.FilterWhitelist {
		db.DB.Exec(`INSERT OR IGNORE INTO filter_whitelist(type,value,note,enabled) VALUES(?,?,?,?)`,
			item.Type, item.Value, item.Note, item.Enabled)
	}
	go ApplyFilter()
	log.Printf("[slave-rules] 顺带同步黑名单 %d 条，白名单 %d 条",
		len(result.Data.FilterBlacklist), len(result.Data.FilterWhitelist))
}

// ── 证书同步 agent ────────────────────────────────────────────────────────────

func StartSlaveCertsSyncAgent() {
	for {
		masterURL := getSetting("slave_certs_url")
		token := getSetting("slave_certs_token")
		interval := getInterval(getSetting("slave_certs_interval"))

		if masterURL != "" && token != "" && getSetting("slave_certs_enabled") != "0" {
			if err := pullAndApplyCerts(masterURL, token); err != nil {
				log.Printf("[slave-certs] 同步失败: %v", err)
				setSyncStatus("slave_certs", "error", err.Error())
			}
		}
		select {
		case <-certsForceSync:
		case <-time.After(interval):
		}
	}
}

func pullAndApplyCerts(masterURL, token string) error {
	masterURL = strings.TrimRight(masterURL, "/")

	localMD5 := localCertsMD5()
	reqURL := fmt.Sprintf("%s/api/v1/sync/certs_export?token=%s&md5=%s", masterURL, token, localMD5)

	resp, err := syncHTTPClient.Get(reqURL)
	if err != nil {
		return fmt.Errorf("请求主节点失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("主节点返回 %d: %s", resp.StatusCode, string(body))
	}

	var result syncCertsResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("解析响应失败: %v", err)
	}
	if result.Code != 0 {
		return fmt.Errorf("主节点返回错误码 %d", result.Code)
	}

	if result.Data.Match {
		setSyncStatus("slave_certs", "ok", "证书已是最新")
		return nil
	}

	return applyCertsFull(result)
}

func applyCertsFull(result syncCertsResp) error {
	masterCount := len(result.Data.Certs)

	for _, cert := range result.Data.Certs {
		expireAt := cert.ExpireAt
		if expireAt == "" {
			expireAt = "2099-01-01 00:00:00"
		}
		db.DB.Exec(`INSERT INTO ssl_certs(domain,cert_pem,key_pem,expire_at,auto_renew)
			VALUES(?,?,?,?,0)
			ON CONFLICT(domain) DO UPDATE SET
			cert_pem=excluded.cert_pem, key_pem=excluded.key_pem,
			expire_at=excluded.expire_at, auto_renew=0`,
			cert.Domain, cert.CertPEM, cert.KeyPEM, expireAt)
		if err := WriteCert(cert.Domain, cert.CertPEM, cert.KeyPEM); err != nil {
			log.Printf("[slave-certs] 写入证书文件 %s 失败: %v", cert.Domain, err)
		}
	}

	if masterCount > 0 {
		masterDomains := make([]interface{}, masterCount)
		ph := make([]string, masterCount)
		for i, c := range result.Data.Certs {
			masterDomains[i] = c.Domain
			ph[i] = "?"
		}
		db.DB.Exec("DELETE FROM ssl_certs WHERE domain NOT IN ("+strings.Join(ph, ",")+")", masterDomains...)
	} else {
		db.DB.Exec(`DELETE FROM ssl_certs`)
	}

	if err := Reload(); err != nil {
		log.Printf("[slave-certs] nginx 重载失败: %v", err)
	}

	msg := fmt.Sprintf("同步完成，证书 %d 个（MD5: %s）", masterCount, shortV(result.Data.MasterMD5))
	setSyncStatus("slave_certs", "ok", msg)
	log.Printf("[slave-certs] %s", msg)
	return nil
}

// ── 旧版全量同步（兼容保留）──────────────────────────────────────────────────

var lastSyncVersion string

func StartSlaveSyncAgent() {
	for {
		masterURL := getSetting("slave_master_url")
		token := getSetting("slave_sync_token")
		interval := getInterval(getSetting("slave_interval"))

		if masterURL != "" && token != "" && getSetting("slave_enabled") == "1" {
			if err := pullAndApply(masterURL, token); err != nil {
				log.Printf("[slave-sync] 同步失败: %v", err)
				setSyncStatus("slave", "error", err.Error())
			}
		}
		time.Sleep(interval)
	}
}

func pullAndApply(masterURL, token string) error {
	masterURL = strings.TrimRight(masterURL, "/")
	reqURL := fmt.Sprintf("%s/api/v1/sync/export?token=%s", masterURL, token)
	resp, err := syncHTTPClient.Get(reqURL)
	if err != nil {
		return fmt.Errorf("请求主节点失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("主节点返回 %d: %s", resp.StatusCode, string(body))
	}

	var result syncExportResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("解析响应失败: %v", err)
	}
	if result.Code != 0 {
		return fmt.Errorf("主节点返回错误码 %d", result.Code)
	}

	newVersion := result.Data.Version
	if newVersion == lastSyncVersion {
		return nil
	}

	confDir := config.Global.Nginx.ConfDir
	if err := os.MkdirAll(confDir, 0755); err != nil {
		return fmt.Errorf("创建 conf 目录失败: %v", err)
	}
	for filename, content := range result.Data.NginxConfigs {
		if err := os.WriteFile(filepath.Join(confDir, filename), []byte(content), 0644); err != nil {
			return fmt.Errorf("写入 %s 失败: %v", filename, err)
		}
	}

	if len(result.Data.Rules) > 0 {
		masterIDs := make([]interface{}, len(result.Data.Rules))
		ph := make([]string, len(result.Data.Rules))
		for i, r := range result.Data.Rules {
			masterIDs[i] = r.ID
			ph[i] = "?"
		}
		db.DB.Exec("DELETE FROM rules WHERE id NOT IN ("+strings.Join(ph, ",")+")", masterIDs...)
		upsertRules(result.Data.Rules)
	}

	// parseCerts 兼容旧主节点 map 格式和新 array 格式
	var certs []syncCert
	if err := json.Unmarshal(result.Data.Certs, &certs); err != nil {
		var m map[string]struct {
			CertPEM string `json:"cert_pem"`
			KeyPEM  string `json:"key_pem"`
		}
		if json.Unmarshal(result.Data.Certs, &m) == nil {
			for domain, v := range m {
				certs = append(certs, syncCert{Domain: domain, CertPEM: v.CertPEM, KeyPEM: v.KeyPEM})
			}
		}
	}
	for _, cert := range certs {
		expireAt := cert.ExpireAt
		if expireAt == "" {
			expireAt = "2099-01-01 00:00:00"
		}
		db.DB.Exec(`INSERT INTO ssl_certs(domain,cert_pem,key_pem,expire_at,auto_renew)
			VALUES(?,?,?,?,0)
			ON CONFLICT(domain) DO UPDATE SET
			cert_pem=excluded.cert_pem, key_pem=excluded.key_pem, expire_at=excluded.expire_at, auto_renew=0`,
			cert.Domain, cert.CertPEM, cert.KeyPEM, expireAt)
		if err := WriteCert(cert.Domain, cert.CertPEM, cert.KeyPEM); err != nil {
			log.Printf("[slave-sync] 写入证书文件 %s 失败: %v", cert.Domain, err)
		}
	}

	if err := Reload(); err != nil {
		return fmt.Errorf("nginx 重载失败: %v", err)
	}

	lastSyncVersion = newVersion
	setSyncStatus("slave", "ok", fmt.Sprintf("同步成功，版本 %s", shortV(newVersion)))
	log.Printf("[slave-sync] 同步完成，版本 %s，规则 %d 条", shortV(newVersion), len(result.Data.Rules))
	return nil
}

// ── 黑白名单同步 agent ────────────────────────────────────────────────────────

func nextOccurrence(hhmm string) time.Time {
	now := time.Now()
	var h, m int
	fmt.Sscanf(hhmm, "%d:%d", &h, &m)
	t := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	if !t.After(now) {
		t = t.Add(24 * time.Hour)
	}
	return t
}

func StartSlaveFilterSyncAgent() {
	for {
		masterURL := getSetting("slave_filter_url")
		token := getSetting("slave_filter_token")
		syncTime := getSetting("slave_filter_time")
		if syncTime == "" {
			syncTime = "03:00"
		}

		if masterURL == "" || token == "" || getSetting("slave_filter_enabled") == "0" {
			time.Sleep(60 * time.Second)
			continue
		}

		next := nextOccurrence(syncTime)
		waitDur := time.Until(next)
		log.Printf("[slave-filter] 下次同步时间: %s（等待 %.0f 分钟）", next.Format("2006-01-02 15:04"), waitDur.Minutes())

		select {
		case <-time.After(waitDur):
		case <-filterForceSync:
			log.Printf("[slave-filter] 手动触发同步")
		}

		masterURL = getSetting("slave_filter_url")
		token = getSetting("slave_filter_token")
		if masterURL == "" || token == "" {
			continue
		}

		if err := pullAndApplyFilter(masterURL, token); err != nil {
			setSyncStatus("slave_filter", "error", err.Error())
			log.Printf("[slave-filter] 同步失败: %v", err)
		}
	}
}

func pullAndApplyFilter(masterURL, token string) error {
	masterURL = strings.TrimRight(masterURL, "/")

	localMD5 := localFilterMD5()
	reqURL := fmt.Sprintf("%s/api/v1/sync/filter_export?token=%s&md5=%s", masterURL, token, localMD5)

	resp, err := syncHTTPClient.Get(reqURL)
	if err != nil {
		return fmt.Errorf("请求主节点失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("主节点返回 %d: %s", resp.StatusCode, string(body))
	}

	var result syncFilterResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("解析响应失败: %v", err)
	}
	if result.Code != 0 {
		return fmt.Errorf("主节点返回错误码 %d", result.Code)
	}

	if result.Data.Match {
		setSyncStatus("slave_filter", "ok", "过滤规则已是最新")
		return nil
	}

	return applyFilterFull(result)
}

func applyFilterFull(result syncFilterResp) error {
	db.DB.Exec(`DELETE FROM filter_blacklist WHERE auto_added=0`)
	for _, item := range result.Data.FilterBlacklist {
		db.DB.Exec(`INSERT OR IGNORE INTO filter_blacklist(type,value,note,hits,auto_added,enabled) VALUES(?,?,?,?,?,?)`,
			item.Type, item.Value, item.Note, item.Hits, item.AutoAdded, item.Enabled)
	}
	db.DB.Exec(`DELETE FROM filter_whitelist`)
	for _, item := range result.Data.FilterWhitelist {
		db.DB.Exec(`INSERT OR IGNORE INTO filter_whitelist(type,value,note,enabled) VALUES(?,?,?,?)`,
			item.Type, item.Value, item.Note, item.Enabled)
	}

	if err := ApplyFilter(); err != nil {
		return fmt.Errorf("应用过滤规则失败: %v", err)
	}

	msg := fmt.Sprintf("同步完成，黑名单 %d 条，白名单 %d 条（MD5: %s）",
		len(result.Data.FilterBlacklist), len(result.Data.FilterWhitelist), shortV(result.Data.MasterMD5))
	setSyncStatus("slave_filter", "ok", msg)
	log.Printf("[slave-filter] %s", msg)
	return nil
}
