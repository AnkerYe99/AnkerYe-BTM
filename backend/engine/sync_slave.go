package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"ankerye-flow/config"
	"ankerye-flow/db"
)

// 强制触发同步通道（缓冲1，防止堆积）
var rulesForceSync = make(chan struct{}, 1)
var certsForceSync = make(chan struct{}, 1)
var filterForceSync = make(chan struct{}, 1)

// 带30s超时的HTTP客户端
var syncHTTPClient = &http.Client{Timeout: 30 * time.Second}

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

// ── 数据结构 ──────────────────────────────────────────────────────

type syncServer struct {
	Address string `json:"address"`
	Port    int64  `json:"port"`
	Weight  int64  `json:"weight"`
	State   string `json:"state"`
}

type syncRule struct {
	ID           int64        `json:"id"`
	Name         string       `json:"name"`
	Protocol     string       `json:"protocol"`
	ListenPort   int64        `json:"listen_port"`
	ListenStack  string       `json:"listen_stack"`
	HttpsEnabled int64        `json:"https_enabled"`
	HttpsPort    int64        `json:"https_port"`
	ServerName   string       `json:"server_name"`
	LbMethod     string       `json:"lb_method"`
	SslCertID    int64        `json:"ssl_cert_id"`
	SslRedirect  int64        `json:"ssl_redirect"`
	HcEnabled    int64        `json:"hc_enabled"`
	HcInterval   int64        `json:"hc_interval"`
	HcTimeout    int64        `json:"hc_timeout"`
	HcPath       string       `json:"hc_path"`
	HcFall       int64        `json:"hc_fall"`
	HcRise       int64        `json:"hc_rise"`
	LogMaxSize   string       `json:"log_max_size"`
	CustomConfig string       `json:"custom_config"`
	Status       int64        `json:"status"`
	Servers      []syncServer `json:"servers"`
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

// ── 全量同步响应（兼容旧版）──────────────────────────────────────

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

// ── 规则同步响应（支持全量+增量）────────────────────────────────

type syncRulesResp struct {
	Code int `json:"code"`
	Data struct {
		IsIncremental   bool               `json:"is_incremental"`
		Version         string             `json:"version"`
		Since           string             `json:"since"`
		NginxConfigs    map[string]string  `json:"nginx_configs"`
		// 全量
		Rules           []syncRule         `json:"rules"`
		FilterBlacklist []syncFilterItem   `json:"filter_blacklist"`
		FilterWhitelist []syncFilterWLItem `json:"filter_whitelist"`
		// 增量
		ChangedRules []syncRule `json:"changed_rules"`
		DeletedIDs   []string   `json:"deleted_ids"`
	} `json:"data"`
}

// ── 证书同步响应（支持全量+增量）────────────────────────────────

type syncCertsResp struct {
	Code int `json:"code"`
	Data struct {
		IsIncremental  bool       `json:"is_incremental"`
		Version        string     `json:"version"`
		Since          string     `json:"since"`
		// 全量
		Certs          []syncCert `json:"certs"`
		// 增量
		ChangedCerts   []syncCert `json:"changed_certs"`
		DeletedDomains []string   `json:"deleted_domains"`
	} `json:"data"`
}

// ── 黑白名单同步响应（支持全量+增量）────────────────────────────

type syncFilterResp struct {
	Code int `json:"code"`
	Data struct {
		IsIncremental        bool               `json:"is_incremental"`
		Since                string             `json:"since"`
		GeneratedAt          string             `json:"generated_at"`
		// 全量
		FilterBlacklist      []syncFilterItem   `json:"filter_blacklist"`
		FilterWhitelist      []syncFilterWLItem `json:"filter_whitelist"`
		// 增量
		ChangedBlacklist     []syncFilterItem   `json:"changed_blacklist"`
		ChangedWhitelist     []syncFilterWLItem `json:"changed_whitelist"`
		DeletedBlacklistKeys []string           `json:"deleted_blacklist_keys"`
		DeletedWhitelistKeys []string           `json:"deleted_whitelist_keys"`
	} `json:"data"`
}

// parseCerts 兼容旧主节点（map 格式）和新主节点（array 格式）
func parseCerts(raw json.RawMessage) []syncCert {
	if len(raw) == 0 {
		return nil
	}
	var arr []syncCert
	if json.Unmarshal(raw, &arr) == nil {
		return arr
	}
	var m map[string]struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if json.Unmarshal(raw, &m) == nil {
		certs := make([]syncCert, 0, len(m))
		for domain, v := range m {
			certs = append(certs, syncCert{Domain: domain, CertPEM: v.CertPEM, KeyPEM: v.KeyPEM})
		}
		return certs
	}
	return nil
}

// ── 辅助函数 ──────────────────────────────────────────────────────

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

// saveSyncTime 更新从节点本地记录的最后成功同步时间（用于下次 since 参数）
func saveSyncTime(key string) {
	now := time.Now().Format("2006-01-02 15:04:05")
	db.AsyncExec(`INSERT INTO system_settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, key, now)
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── 规则同步 agent ────────────────────────────────────────────────

var lastRulesVersion string

func StartSlaveRulesSyncAgent() {
	for {
		masterURL := getSetting("slave_rules_url")
		token := getSetting("slave_rules_token")
		interval := getInterval(getSetting("slave_rules_interval"))

		if masterURL != "" && token != "" {
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
	lastSync := getSetting("slave_rules_last_sync_at")

	reqURL := fmt.Sprintf("%s/api/v1/sync/rules_export?token=%s", masterURL, token)
	if lastSync != "" {
		reqURL += "&since=" + url.QueryEscape(lastSync)
	}

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

	newVersion := result.Data.Version
	confDir := config.Global.Nginx.ConfDir
	if err := os.MkdirAll(confDir, 0755); err != nil {
		return fmt.Errorf("创建 conf 目录失败: %v", err)
	}
	for filename, content := range result.Data.NginxConfigs {
		path := filepath.Join(confDir, filename)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return fmt.Errorf("写入 %s 失败: %v", filename, err)
		}
	}

	if result.Data.IsIncremental {
		return applyRulesIncremental(result, newVersion)
	}
	return applyRulesFull(result, newVersion)
}

func applyRulesFull(result syncRulesResp, newVersion string) error {
	var localRuleCount int
	db.DB.QueryRow(`SELECT COUNT(*) FROM rules`).Scan(&localRuleCount)
	masterRuleCount := len(result.Data.Rules)
	if newVersion == lastRulesVersion && newVersion != "" && localRuleCount == masterRuleCount {
		setSyncStatus("slave_rules", "ok", fmt.Sprintf("规则已是最新（%d 条）", masterRuleCount))
		return nil
	}

	if len(result.Data.Rules) > 0 {
		masterIDs := make([]interface{}, 0, len(result.Data.Rules))
		placeholders := ""
		for i, r := range result.Data.Rules {
			masterIDs = append(masterIDs, r.ID)
			if i > 0 {
				placeholders += ","
			}
			placeholders += "?"
		}
		db.DB.Exec("DELETE FROM rules WHERE id NOT IN ("+placeholders+")", masterIDs...)
		upsertRules(result.Data.Rules)
		log.Printf("[slave-rules] 全量同步规则 %d 条", masterRuleCount)
	}

	applyFilterFromRulesResp(result)

	if err := Reload(); err != nil {
		return fmt.Errorf("nginx 重载失败: %v", err)
	}
	lastRulesVersion = newVersion
	saveSyncTime("slave_rules_last_sync_at")
	setSyncStatus("slave_rules", "ok", fmt.Sprintf("全量同步完成，版本 %s，规则 %d 条", shortV(newVersion), masterRuleCount))
	log.Printf("[slave-rules] 全量同步完成，版本 %s，规则 %d 条", shortV(newVersion), masterRuleCount)
	return nil
}

func applyRulesIncremental(result syncRulesResp, newVersion string) error {
	changed := result.Data.ChangedRules
	deleted := result.Data.DeletedIDs

	if len(changed) == 0 && len(deleted) == 0 {
		setSyncStatus("slave_rules", "ok", "规则已是最新（增量无变化）")
		saveSyncTime("slave_rules_last_sync_at")
		return nil
	}

	upsertRules(changed)

	for _, idStr := range deleted {
		id, _ := strconv.ParseInt(idStr, 10, 64)
		db.DB.Exec(`DELETE FROM upstream_servers WHERE rule_id=?`, id)
		db.DB.Exec(`DELETE FROM rules WHERE id=?`, id)
		// 清理对应 nginx 配置文件（http 和 stream 两种后缀都尝试删除）
		for _, suffix := range []string{"http", "stream"} {
			fname := filepath.Join(config.Global.Nginx.ConfDir, fmt.Sprintf("%d-%s.conf", id, suffix))
			os.Remove(fname)
		}
	}

	if err := Reload(); err != nil {
		return fmt.Errorf("nginx 重载失败: %v", err)
	}

	lastRulesVersion = newVersion
	saveSyncTime("slave_rules_last_sync_at")
	msg := fmt.Sprintf("增量同步完成，变更 %d 条，删除 %d 条", len(changed), len(deleted))
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
		db.DB.Exec(`INSERT INTO rules(id,name,protocol,listen_port,listen_stack,
			https_enabled,https_port,server_name,lb_method,ssl_cert_id,ssl_redirect,
			hc_enabled,hc_interval,hc_timeout,hc_path,hc_fall,hc_rise,
			log_max_size,custom_config,status)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, protocol=excluded.protocol, listen_port=excluded.listen_port,
			listen_stack=excluded.listen_stack, https_enabled=excluded.https_enabled,
			https_port=excluded.https_port, server_name=excluded.server_name,
			lb_method=excluded.lb_method, ssl_cert_id=excluded.ssl_cert_id,
			ssl_redirect=excluded.ssl_redirect, hc_enabled=excluded.hc_enabled,
			hc_interval=excluded.hc_interval, hc_timeout=excluded.hc_timeout,
			hc_path=excluded.hc_path, hc_fall=excluded.hc_fall, hc_rise=excluded.hc_rise,
			log_max_size=excluded.log_max_size, custom_config=excluded.custom_config,
			status=excluded.status, updated_at=datetime('now','localtime')`,
			r.ID, r.Name, r.Protocol, r.ListenPort, r.ListenStack,
			r.HttpsEnabled, r.HttpsPort, r.ServerName, r.LbMethod, sslCertID, r.SslRedirect,
			r.HcEnabled, r.HcInterval, r.HcTimeout, r.HcPath, r.HcFall, r.HcRise,
			r.LogMaxSize, r.CustomConfig, r.Status)

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

// ── 证书同步 agent ────────────────────────────────────────────────

var lastCertsVersion string

func StartSlaveCertsSyncAgent() {
	for {
		masterURL := getSetting("slave_certs_url")
		token := getSetting("slave_certs_token")
		interval := getInterval(getSetting("slave_certs_interval"))

		if masterURL != "" && token != "" {
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
	lastSync := getSetting("slave_certs_last_sync_at")

	reqURL := fmt.Sprintf("%s/api/v1/sync/certs_export?token=%s", masterURL, token)
	if lastSync != "" {
		reqURL += "&since=" + url.QueryEscape(lastSync)
	}

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

	if result.Data.IsIncremental {
		return applyCertsIncremental(result)
	}
	return applyCertsFull(result)
}

func applyCertsFull(result syncCertsResp) error {
	var localCount int
	db.DB.QueryRow(`SELECT COUNT(*) FROM ssl_certs`).Scan(&localCount)
	masterCount := len(result.Data.Certs)
	newVersion := result.Data.Version
	versionSame := newVersion == lastCertsVersion && newVersion != ""

	if versionSame && localCount == masterCount {
		setSyncStatus("slave_certs", "ok", fmt.Sprintf("证书已是最新（%d 个）", masterCount))
		return nil
	}

	for _, cert := range result.Data.Certs {
		expireAt := cert.ExpireAt
		if expireAt == "" {
			expireAt = "2099-01-01 00:00:00"
		}
		db.DB.Exec(`INSERT INTO ssl_certs(domain,cert_pem,key_pem,expire_at,auto_renew)
			VALUES(?,?,?,?,0)
			ON CONFLICT(domain) DO UPDATE SET
			cert_pem=excluded.cert_pem, key_pem=excluded.key_pem,
			expire_at=excluded.expire_at, auto_renew=0,
			updated_at=datetime('now','localtime')`,
			cert.Domain, cert.CertPEM, cert.KeyPEM, expireAt)
		if err := WriteCert(cert.Domain, cert.CertPEM, cert.KeyPEM); err != nil {
			log.Printf("[slave-certs] 写入证书文件 %s 失败: %v", cert.Domain, err)
		}
	}

	if masterCount > 0 {
		masterDomains := make([]interface{}, masterCount)
		placeholders := ""
		for i, c := range result.Data.Certs {
			masterDomains[i] = c.Domain
			if i > 0 {
				placeholders += ","
			}
			placeholders += "?"
		}
		db.DB.Exec("DELETE FROM ssl_certs WHERE domain NOT IN ("+placeholders+")", masterDomains...)
	}

	if err := Reload(); err != nil {
		log.Printf("[slave-certs] nginx 重载失败: %v", err)
	}

	lastCertsVersion = newVersion
	saveSyncTime("slave_certs_last_sync_at")
	setSyncStatus("slave_certs", "ok", fmt.Sprintf("全量同步完成，证书 %d 个", masterCount))
	log.Printf("[slave-certs] 全量同步完成，证书 %d 个（版本 %s）", masterCount, shortV(newVersion))
	return nil
}

func applyCertsIncremental(result syncCertsResp) error {
	changed := result.Data.ChangedCerts
	deleted := result.Data.DeletedDomains

	if len(changed) == 0 && len(deleted) == 0 {
		setSyncStatus("slave_certs", "ok", "证书已是最新（增量无变化）")
		saveSyncTime("slave_certs_last_sync_at")
		return nil
	}

	for _, cert := range changed {
		expireAt := cert.ExpireAt
		if expireAt == "" {
			expireAt = "2099-01-01 00:00:00"
		}
		db.DB.Exec(`INSERT INTO ssl_certs(domain,cert_pem,key_pem,expire_at,auto_renew)
			VALUES(?,?,?,?,0)
			ON CONFLICT(domain) DO UPDATE SET
			cert_pem=excluded.cert_pem, key_pem=excluded.key_pem,
			expire_at=excluded.expire_at, auto_renew=0,
			updated_at=datetime('now','localtime')`,
			cert.Domain, cert.CertPEM, cert.KeyPEM, expireAt)
		if err := WriteCert(cert.Domain, cert.CertPEM, cert.KeyPEM); err != nil {
			log.Printf("[slave-certs] 写入证书文件 %s 失败: %v", cert.Domain, err)
		}
	}

	for _, domain := range deleted {
		db.DB.Exec(`DELETE FROM ssl_certs WHERE domain=?`, domain)
		certDir := config.Global.Nginx.CertDir
		os.Remove(filepath.Join(certDir, domain+".crt"))
		os.Remove(filepath.Join(certDir, domain+".key"))
		log.Printf("[slave-certs] 删除证书 %s", domain)
	}

	if err := Reload(); err != nil {
		log.Printf("[slave-certs] nginx 重载失败: %v", err)
	}

	saveSyncTime("slave_certs_last_sync_at")
	msg := fmt.Sprintf("增量同步完成，变更 %d 个，删除 %d 个", len(changed), len(deleted))
	setSyncStatus("slave_certs", "ok", msg)
	log.Printf("[slave-certs] %s", msg)
	return nil
}

// ── 旧版全量同步（兼容保留）─────────────────────────────────────

var lastSyncVersion string

func StartSlaveSyncAgent() {
	for {
		masterURL := getSetting("slave_master_url")
		token := getSetting("slave_sync_token")
		interval := getInterval(getSetting("slave_interval"))

		if masterURL != "" && token != "" {
			if err := pullAndApply(masterURL, token); err != nil {
				log.Printf("[slave-sync] 同步失败: %v", err)
				setSyncStatus("slave", "error", err.Error())
			}
		}
		time.Sleep(interval)
	}
}

func pullAndApply(masterURL, token string) error {
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
		log.Printf("[slave-sync] 版本未变化，跳过")
		return nil
	}

	confDir := config.Global.Nginx.ConfDir
	if err := os.MkdirAll(confDir, 0755); err != nil {
		return fmt.Errorf("创建 conf 目录失败: %v", err)
	}
	for filename, content := range result.Data.NginxConfigs {
		path := filepath.Join(confDir, filename)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return fmt.Errorf("写入 %s 失败: %v", filename, err)
		}
	}

	if len(result.Data.Rules) > 0 {
		masterIDs := make([]interface{}, 0, len(result.Data.Rules))
		placeholders := ""
		for i, r := range result.Data.Rules {
			masterIDs = append(masterIDs, r.ID)
			if i > 0 {
				placeholders += ","
			}
			placeholders += "?"
		}
		db.DB.Exec("DELETE FROM rules WHERE id NOT IN ("+placeholders+")", masterIDs...)
		upsertRules(result.Data.Rules)
		log.Printf("[slave-sync] 同步规则 %d 条", len(result.Data.Rules))
	}

	for _, cert := range parseCerts(result.Data.Certs) {
		expireAt := cert.ExpireAt
		if expireAt == "" {
			expireAt = "2099-01-01 00:00:00"
		}
		db.DB.Exec(`INSERT INTO ssl_certs(domain,cert_pem,key_pem,expire_at,auto_renew)
			VALUES(?,?,?,?,0)
			ON CONFLICT(domain) DO UPDATE SET
			cert_pem=excluded.cert_pem, key_pem=excluded.key_pem,
			expire_at=excluded.expire_at, auto_renew=0,
			updated_at=datetime('now','localtime')`,
			cert.Domain, cert.CertPEM, cert.KeyPEM, expireAt)
		if err := WriteCert(cert.Domain, cert.CertPEM, cert.KeyPEM); err != nil {
			log.Printf("[slave-sync] 写入证书文件 %s 失败: %v", cert.Domain, err)
		}
	}

	skipSync := map[string]bool{
		"slave_master_url": true, "slave_sync_token": true, "slave_interval": true,
		"slave_last_sync_at": true, "slave_last_status": true, "slave_last_msg": true,
		"slave_rules_url": true, "slave_rules_token": true, "slave_rules_interval": true,
		"slave_certs_url": true, "slave_certs_token": true, "slave_certs_interval": true,
		"acme_email": true, "acme_account_json": true, "acme_account_key": true,
		"dnspod_id": true, "dnspod_key": true,
		"tencent_secret_id": true, "tencent_secret_key": true,
	}
	for k, v := range result.Data.Settings {
		if skipSync[k] {
			continue
		}
		db.DB.Exec(`INSERT INTO system_settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	}

	if err := Reload(); err != nil {
		return fmt.Errorf("nginx 重载失败: %v", err)
	}

	lastSyncVersion = newVersion
	setSyncStatus("slave", "ok", fmt.Sprintf("同步成功，版本 %s", shortV(newVersion)))
	log.Printf("[slave-sync] 同步完成，版本 %s，规则 %d 条", shortV(newVersion), len(result.Data.Rules))
	return nil
}

// ── 黑白名单独立同步 agent ────────────────────────────────────────

// nextOccurrence 计算下一次 "HH:MM" 出现的时间点（今天或明天）
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

		if masterURL == "" || token == "" {
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
	lastSync := getSetting("slave_filter_last_sync_at")

	reqURL := fmt.Sprintf("%s/api/v1/sync/filter_export?token=%s", masterURL, token)
	if lastSync != "" {
		reqURL += "&since=" + url.QueryEscape(lastSync)
	}

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

	if result.Data.IsIncremental {
		return applyFilterIncremental(result)
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

	saveSyncTime("slave_filter_last_sync_at")
	msg := fmt.Sprintf("全量同步成功，黑名单 %d 条，白名单 %d 条",
		len(result.Data.FilterBlacklist), len(result.Data.FilterWhitelist))
	setSyncStatus("slave_filter", "ok", msg)
	log.Printf("[slave-filter] %s", msg)
	return nil
}

func applyFilterIncremental(result syncFilterResp) error {
	changedBL := result.Data.ChangedBlacklist
	changedWL := result.Data.ChangedWhitelist
	deletedBL := result.Data.DeletedBlacklistKeys
	deletedWL := result.Data.DeletedWhitelistKeys

	if len(changedBL) == 0 && len(changedWL) == 0 && len(deletedBL) == 0 && len(deletedWL) == 0 {
		setSyncStatus("slave_filter", "ok", "过滤规则已是最新（增量无变化）")
		saveSyncTime("slave_filter_last_sync_at")
		return nil
	}

	// tombstone key 格式: "type:value"
	for _, key := range deletedBL {
		parts := splitKey(key)
		if len(parts) == 2 {
			db.DB.Exec(`DELETE FROM filter_blacklist WHERE type=? AND value=?`, parts[0], parts[1])
		}
	}
	for _, key := range deletedWL {
		parts := splitKey(key)
		if len(parts) == 2 {
			db.DB.Exec(`DELETE FROM filter_whitelist WHERE type=? AND value=?`, parts[0], parts[1])
		}
	}

	for _, item := range changedBL {
		db.DB.Exec(`INSERT INTO filter_blacklist(type,value,note,hits,auto_added,enabled)
			VALUES(?,?,?,?,?,?)
			ON CONFLICT(type,value) DO UPDATE SET
			note=excluded.note, hits=excluded.hits, auto_added=excluded.auto_added,
			enabled=excluded.enabled, updated_at=datetime('now','localtime')`,
			item.Type, item.Value, item.Note, item.Hits, item.AutoAdded, item.Enabled)
	}
	for _, item := range changedWL {
		db.DB.Exec(`INSERT INTO filter_whitelist(type,value,note,enabled)
			VALUES(?,?,?,?)
			ON CONFLICT(type,value) DO UPDATE SET
			note=excluded.note, enabled=excluded.enabled,
			updated_at=datetime('now','localtime')`,
			item.Type, item.Value, item.Note, item.Enabled)
	}

	if err := ApplyFilter(); err != nil {
		return fmt.Errorf("应用过滤规则失败: %v", err)
	}

	saveSyncTime("slave_filter_last_sync_at")
	msg := fmt.Sprintf("增量同步成功，变更黑名单 %d，变更白名单 %d，删除黑名单 %d，删除白名单 %d",
		len(changedBL), len(changedWL), len(deletedBL), len(deletedWL))
	setSyncStatus("slave_filter", "ok", msg)
	log.Printf("[slave-filter] %s", msg)
	return nil
}

// splitKey 解析 tombstone record_key 格式 "type:value"
func splitKey(key string) []string {
	idx := -1
	for i, ch := range key {
		if ch == ':' {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}
	return []string{key[:idx], key[idx+1:]}
}
