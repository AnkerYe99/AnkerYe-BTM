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

	"nginxflow/config"
	"nginxflow/db"
)

type syncExportResp struct {
	Code int `json:"code"`
	Data struct {
		Version      string            `json:"version"`
		GeneratedAt  string            `json:"generated_at"`
		NginxConfigs map[string]string `json:"nginx_configs"`
		Certs        map[string]struct {
			CertPEM string `json:"cert_pem"`
			KeyPEM  string `json:"key_pem"`
		} `json:"certs"`
		Settings map[string]string `json:"settings"`
	} `json:"data"`
}

var lastSyncVersion string

// StartSlaveSyncAgent 从节点定时拉取主节点配置并应用
func StartSlaveSyncAgent() {
	for {
		masterURL, token, intervalStr := getSlaveConfig()
		if masterURL != "" && token != "" {
			interval, _ := strconv.Atoi(intervalStr)
			if interval < 10 {
				interval = 60
			}
			if err := pullAndApply(masterURL, token); err != nil {
				log.Printf("[slave-sync] 同步失败: %v", err)
				setSyncStatus("error", err.Error())
			}
			time.Sleep(time.Duration(interval) * time.Second)
		} else {
			time.Sleep(30 * time.Second) // 未配置时低频轮询等待配置
		}
	}
}

func getSlaveConfig() (masterURL, token, interval string) {
	rows, _ := db.DB.Query(`SELECT k,v FROM system_settings WHERE k IN ('slave_master_url','slave_sync_token','slave_interval')`)
	if rows == nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		switch k {
		case "slave_master_url":
			masterURL = v
		case "slave_sync_token":
			token = v
		case "slave_interval":
			interval = v
		}
	}
	return
}

func pullAndApply(masterURL, token string) error {
	url := fmt.Sprintf("%s/api/v1/sync/export?token=%s", masterURL, token)
	resp, err := http.Get(url)
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
		log.Printf("[slave-sync] 版本未变化 (%s)，跳过", newVersion[:min(16, len(newVersion))])
		return nil
	}

	log.Printf("[slave-sync] 检测到新版本 %s，开始同步...", newVersion[:min(16, len(newVersion))])

	// 写入 nginx 配置文件
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

	// 写入证书文件
	certDir := config.Global.Nginx.CertDir
	for domain, pem := range result.Data.Certs {
		if err := WriteCert(domain, pem.CertPEM, pem.KeyPEM); err != nil {
			log.Printf("[slave-sync] 写入证书 %s 失败: %v", domain, err)
		} else {
			// 同步更新本地 DB 中的证书内容（仅更新 pem，不触发续签）
			db.DB.Exec(`INSERT INTO ssl_certs(domain,cert_pem,key_pem,auto_renew)
				VALUES(?,?,?,0)
				ON CONFLICT(domain) DO UPDATE SET cert_pem=excluded.cert_pem, key_pem=excluded.key_pem,
				updated_at=datetime('now','localtime')`,
				domain, pem.CertPEM, pem.KeyPEM)
			_ = certDir
		}
	}

	// 同步系统设置（SMTP/通知类型等，跳过从节点专属配置）
	skipSync := map[string]bool{
		"slave_master_url": true, "slave_sync_token": true, "slave_interval": true,
		"slave_last_sync_at": true, "slave_last_status": true, "slave_last_msg": true,
	}
	for k, v := range result.Data.Settings {
		if skipSync[k] {
			continue
		}
		db.DB.Exec(`INSERT INTO system_settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	}

	// 重载 nginx
	if err := Reload(); err != nil {
		return fmt.Errorf("nginx 重载失败: %v", err)
	}

	lastSyncVersion = newVersion
	setSyncStatus("ok", fmt.Sprintf("同步成功，版本 %s", newVersion[:min(16, len(newVersion))]))
	log.Printf("[slave-sync] 同步完成，版本 %s，配置 %d 个，证书 %d 个",
		newVersion[:min(16, len(newVersion))], len(result.Data.NginxConfigs), len(result.Data.Certs))
	return nil
}

func setSyncStatus(status, msg string) {
	now := time.Now().Format("2006-01-02 15:04:05")
	db.DB.Exec(`INSERT INTO system_settings(k,v) VALUES('slave_last_sync_at',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, now)
	db.DB.Exec(`INSERT INTO system_settings(k,v) VALUES('slave_last_status',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, status)
	db.DB.Exec(`INSERT INTO system_settings(k,v) VALUES('slave_last_msg',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, msg)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
