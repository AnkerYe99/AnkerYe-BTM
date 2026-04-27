package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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

// TriggerRulesSync 立即触发一次规则同步
func TriggerRulesSync() {
	select {
	case rulesForceSync <- struct{}{}:
	default:
	}
}

// TriggerCertsSync 立即触发一次证书同步
func TriggerCertsSync() {
	select {
	case certsForceSync <- struct{}{}:
	default:
	}
}

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

type syncRulesResp struct {
	Code int `json:"code"`
	Data struct {
		Version         string             `json:"version"`
		NginxConfigs    map[string]string  `json:"nginx_configs"`
		Rules           []syncRule         `json:"rules"`
		FilterBlacklist []syncFilterItem   `json:"filter_blacklist"`
		FilterWhitelist []syncFilterWLItem `json:"filter_whitelist"`
	} `json:"data"`
}

type syncCertsResp struct {
	Code int `json:"code"`
	Data struct {
		Version string     `json:"version"`
		Certs   []syncCert `json:"certs"`
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

// ── 规则同步 agent ──────────────────────────────────────────────

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
	url := fmt.Sprintf("%s/api/v1/sync/rules_export?token=%s", masterURL, token)
	resp, err := syncHTTPClient.Get(url)
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

	// 对比版本与本地规则数量，两者都相同才跳过，否则强制应用
	var localRuleCount int
	db.DB.QueryRow(`SELECT COUNT(*) FROM rules`).Scan(&localRuleCount)
	masterRuleCount := len(result.Data.Rules)
	if newVersion == lastRulesVersion && newVersion != "" && localRuleCount == masterRuleCount {
		setSyncStatus("slave_rules", "ok", fmt.Sprintf("规则已是最新（%d 条）", masterRuleCount))
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

		for _, r := range result.Data.Rules {
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
		log.Printf("[slave-rules] 同步规则 %d 条", len(result.Data.Rules))
	}

	// 顺带同步黑白名单（主节点 v2.0.1+ 会在同一接口返回）
	if len(result.Data.FilterBlacklist) > 0 || len(result.Data.FilterWhitelist) > 0 {
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
		log.Printf("[slave-rules] 顺带同步黑名单 %d 条，白名单 %d 条", len(result.Data.FilterBlacklist), len(result.Data.FilterWhitelist))
	}

	if err := Reload(); err != nil {
		return fmt.Errorf("nginx 重载失败: %v", err)
	}

	lastRulesVersion = newVersion
	setSyncStatus("slave_rules", "ok", fmt.Sprintf("同步成功，版本 %s，规则 %d 条", shortV(newVersion), len(result.Data.Rules)))
	log.Printf("[slave-rules] 同步完成，版本 %s，规则 %d 条", shortV(newVersion), len(result.Data.Rules))
	return nil
}

// ── 证书同步 agent ──────────────────────────────────────────────

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
	url := fmt.Sprintf("%s/api/v1/sync/certs_export?token=%s", masterURL, token)
	resp, err := syncHTTPClient.Get(url)
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

	newVersion := result.Data.Version

	// 对比主节点版本与上次同步版本，以及从节点本地证书数量
	// 注意：不能仅凭版本相同就跳过——从节点本地可能删了证书，必须始终应用主节点状态
	var localCount int
	db.DB.QueryRow(`SELECT COUNT(*) FROM ssl_certs`).Scan(&localCount)
	masterCount := len(result.Data.Certs)
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

	// 删除从节点多出来的证书（主节点已无该域名）
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
	setSyncStatus("slave_certs", "ok", fmt.Sprintf("同步完成，证书 %d 个", masterCount))
	log.Printf("[slave-certs] 同步完成，证书 %d 个（主节点版本 %s）", masterCount, shortV(newVersion))
	return nil
}

// ── 旧版全量同步（兼容保留）──────────────────────────────────────

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
	url := fmt.Sprintf("%s/api/v1/sync/export?token=%s", masterURL, token)
	resp, err := syncHTTPClient.Get(url)
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

		for _, r := range result.Data.Rules {
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

// ── 黑白名单独立同步 agent ──────────────────────────────────────

func TriggerFilterSync() {
	select {
	case filterForceSync <- struct{}{}:
	default:
	}
}

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

		// 重新读取配置（可能在等待期间被修改）
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

type syncFilterResp struct {
	Code int `json:"code"`
	Data struct {
		GeneratedAt     string             `json:"generated_at"`
		FilterBlacklist []syncFilterItem   `json:"filter_blacklist"`
		FilterWhitelist []syncFilterWLItem `json:"filter_whitelist"`
	} `json:"data"`
}

func pullAndApplyFilter(masterURL, token string) error {
	url := fmt.Sprintf("%s/api/v1/sync/filter_export?token=%s", masterURL, token)
	resp, err := syncHTTPClient.Get(url)
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

	// 仅替换手动添加的规则，保留本机自动封禁的 IP
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

	msg := fmt.Sprintf("同步成功，黑名单 %d 条，白名单 %d 条", len(result.Data.FilterBlacklist), len(result.Data.FilterWhitelist))
	setSyncStatus("slave_filter", "ok", msg)
	log.Printf("[slave-filter] %s", msg)
	return nil
}
