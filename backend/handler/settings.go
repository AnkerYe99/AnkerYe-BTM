package handler

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/gin-gonic/gin"

	"ankerye-flow/db"
	"ankerye-flow/engine"
	"ankerye-flow/util"
)

var backupMagic = []byte("ANKBAK01")

// 应用级固定密钥，所有实例统一，支持跨机器/重装恢复
var appBackupKey = sha256.Sum256([]byte("AnkerYe::NginxFlow::Backup::SecretKey::2026"))

func backupKey() []byte {
	return appBackupKey[:]
}

func encryptBackup(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(backupKey())
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	encrypted := gcm.Seal(nonce, nonce, plain, nil)
	return append(backupMagic, encrypted...), nil
}

func decryptBackup(data []byte) ([]byte, error) {
	if len(data) >= 8 && string(data[:8]) == "ANKBAK01" {
		data = data[8:]
		block, err := aes.NewCipher(backupKey())
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		ns := gcm.NonceSize()
		if len(data) < ns {
			return nil, fmt.Errorf("备份文件损坏")
		}
		return gcm.Open(nil, data[:ns], data[ns:], nil)
	}
	// 兼容旧版明文 JSON
	return data, nil
}

func GetSettings(c *gin.Context) {
	rows, _ := db.DB.Query(`SELECT k,v FROM system_settings`)
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		// 敏感字段仅返回是否已配置（同步 token 不再遮掩）
		if k == "tencent_secret_key" || k == "smtp_password" || k == "dnspod_key" ||
			k == "acme_account_key" || k == "acme_account_json" {
			if v != "" {
				m[k] = "***"
			} else {
				m[k] = ""
			}
			continue
		}
		m[k] = v
	}
	util.OK(c, m)
}

func UpdateSettings(c *gin.Context) {
	var req map[string]string
	if err := c.ShouldBindJSON(&req); err != nil {
		util.Fail(c, 400, "参数错误")
		return
	}
	for k, v := range req {
		// 跳过值为 *** 的敏感字段（表示未修改）
		if v == "***" {
			continue
		}
		db.DB.Exec(`INSERT INTO system_settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
		// 修改主同步 token 时，清空各类型独立 token 让验证统一走 sync_token
		if k == "sync_token" {
			for _, sub := range []string{"sync_rules_token", "sync_certs_token", "sync_filter_token"} {
				db.DB.Exec(`INSERT INTO system_settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, sub, "")
			}
		}
	}
	util.OK(c, nil)
}

func TestNginx(c *gin.Context) {
	out, err := engine.TestConfig()
	if err != nil {
		util.Fail(c, 500, out)
		return
	}
	util.OK(c, gin.H{"output": out})
}

func ReloadNginx(c *gin.Context) {
	if err := engine.Reload(); err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	util.OK(c, nil)
}

type backupData struct {
	Rules           []map[string]interface{} `json:"rules"`
	Servers         []map[string]interface{} `json:"servers"`
	Certs           []map[string]interface{} `json:"certs"`
	Settings        map[string]string        `json:"settings"`
	FilterBlacklist []map[string]interface{} `json:"filter_blacklist"`
	FilterWhitelist []map[string]interface{} `json:"filter_whitelist"`
}

func Backup(c *gin.Context) {
	data := backupData{Settings: map[string]string{}}
	// Rules
	rows, _ := db.DB.Query(`SELECT id,name,protocol,listen_port,
		IFNULL(listen_stack,'both'),IFNULL(https_enabled,0),IFNULL(https_port,0),
		IFNULL(server_name,''),lb_method,ssl_cert_id,ssl_redirect,hc_enabled,hc_interval,hc_timeout,
		IFNULL(hc_path,''),IFNULL(hc_rise,0),IFNULL(hc_fall,0),
		IFNULL(log_max_size,''),IFNULL(custom_config,''),status FROM rules ORDER BY id`)
	for rows.Next() {
		var id int64
		var name, proto, stack, srvName, lbm, hcPath, logSize, custom string
		var port, httpsEn, httpsPort, sslRed, hcEn, hcInt, hcTo, hcRise, hcFall, status int
		var sslCert interface{}
		rows.Scan(&id, &name, &proto, &port, &stack, &httpsEn, &httpsPort, &srvName, &lbm, &sslCert,
			&sslRed, &hcEn, &hcInt, &hcTo, &hcPath, &hcRise, &hcFall, &logSize, &custom, &status)
		data.Rules = append(data.Rules, map[string]interface{}{
			"id": id, "name": name, "protocol": proto, "listen_port": port,
			"listen_stack": stack, "https_enabled": httpsEn, "https_port": httpsPort,
			"server_name": srvName, "lb_method": lbm, "ssl_cert_id": sslCert,
			"ssl_redirect": sslRed, "hc_enabled": hcEn, "hc_interval": hcInt, "hc_timeout": hcTo,
			"hc_path": hcPath, "hc_rise": hcRise, "hc_fall": hcFall,
			"log_max_size": logSize, "custom_config": custom, "status": status,
		})
	}
	rows.Close()
	// Servers
	rows2, _ := db.DB.Query(`SELECT id,rule_id,address,port,weight,state FROM upstream_servers ORDER BY id`)
	for rows2.Next() {
		var id, rid int64
		var addr, state string
		var port, weight int
		rows2.Scan(&id, &rid, &addr, &port, &weight, &state)
		data.Servers = append(data.Servers, map[string]interface{}{
			"id": id, "rule_id": rid, "address": addr, "port": port, "weight": weight, "state": state,
		})
	}
	rows2.Close()
	// Certs
	rows3, _ := db.DB.Query(`SELECT id,domain,cert_pem,key_pem,expire_at,auto_renew FROM ssl_certs ORDER BY id`)
	for rows3.Next() {
		var id int64
		var domain, cert, key, expire string
		var ar int
		rows3.Scan(&id, &domain, &cert, &key, &expire, &ar)
		data.Certs = append(data.Certs, map[string]interface{}{
			"id": id, "domain": domain, "cert_pem": cert, "key_pem": key, "expire_at": expire, "auto_renew": ar,
		})
	}
	rows3.Close()
	// Settings
	rows4, _ := db.DB.Query(`SELECT k,v FROM system_settings`)
	for rows4.Next() {
		var k, v string
		rows4.Scan(&k, &v)
		data.Settings[k] = v
	}
	rows4.Close()
	// 黑名单
	rows5, _ := db.DB.Query(`SELECT id,type,value,note,hits,auto_added,enabled FROM filter_blacklist ORDER BY id`)
	if rows5 != nil {
		for rows5.Next() {
			var id, hits, autoAdded, enabled int64
			var typ, value, note string
			rows5.Scan(&id, &typ, &value, &note, &hits, &autoAdded, &enabled)
			data.FilterBlacklist = append(data.FilterBlacklist, map[string]interface{}{
				"id": id, "type": typ, "value": value, "note": note,
				"hits": hits, "auto_added": autoAdded, "enabled": enabled,
			})
		}
		rows5.Close()
	}
	// 白名单
	rows6, _ := db.DB.Query(`SELECT id,type,value,note,enabled FROM filter_whitelist ORDER BY id`)
	if rows6 != nil {
		for rows6.Next() {
			var id, enabled int64
			var typ, value, note string
			rows6.Scan(&id, &typ, &value, &note, &enabled)
			data.FilterWhitelist = append(data.FilterWhitelist, map[string]interface{}{
				"id": id, "type": typ, "value": value, "note": note, "enabled": enabled,
			})
		}
		rows6.Close()
	}

	b, _ := json.Marshal(data)
	encrypted, err := encryptBackup(b)
	if err != nil {
		util.Fail(c, 500, "加密失败: "+err.Error())
		return
	}
	filename := fmt.Sprintf("ankye-backup-%s.bak", time.Now().Format("2006-01-02"))
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Data(200, "application/octet-stream", encrypted)
}

func TestEmail(c *gin.Context) {
	err := engine.SendNotify("", "AnkerYe - 流量管理 测试邮件", "这是一封来自 AnkerYe - 流量管理 的测试邮件，说明您的 SMTP 配置正确！")
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	util.OK(c, nil)
}

func Restore(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		util.Fail(c, 400, "请上传备份文件")
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(file)
	if err != nil {
		util.Fail(c, 400, "读取文件失败")
		return
	}
	plain, err := decryptBackup(raw)
	if err != nil {
		util.Fail(c, 400, "解密失败，备份文件不匹配或已损坏")
		return
	}
	var data backupData
	if err := json.Unmarshal(plain, &data); err != nil {
		util.Fail(c, 400, "备份格式无效: "+err.Error())
		return
	}

	tx, err := db.DB.Begin()
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	defer tx.Rollback()

	// 清空旧数据
	for _, tbl := range []string{"upstream_servers", "rules", "ssl_certs", "system_settings", "filter_blacklist", "filter_whitelist"} {
		tx.Exec("DELETE FROM " + tbl)
	}

	// 恢复规则
	for _, m := range data.Rules {
		tx.Exec(`INSERT OR IGNORE INTO rules(id,name,protocol,listen_port,listen_stack,https_enabled,https_port,
			server_name,lb_method,ssl_cert_id,ssl_redirect,hc_enabled,hc_interval,hc_timeout,hc_path,
			hc_rise,hc_fall,log_max_size,custom_config,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			int64v(m["id"]), m["name"], m["protocol"], int64v(m["listen_port"]),
			m["listen_stack"], int64v(m["https_enabled"]), int64v(m["https_port"]),
			m["server_name"], m["lb_method"], m["ssl_cert_id"], int64v(m["ssl_redirect"]),
			int64v(m["hc_enabled"]), int64v(m["hc_interval"]), int64v(m["hc_timeout"]),
			m["hc_path"], int64v(m["hc_rise"]), int64v(m["hc_fall"]),
			m["log_max_size"], m["custom_config"], int64v(m["status"]))
	}
	// 恢复节点
	for _, m := range data.Servers {
		tx.Exec(`INSERT OR IGNORE INTO upstream_servers(id,rule_id,address,port,weight,state) VALUES(?,?,?,?,?,?)`,
			int64v(m["id"]), int64v(m["rule_id"]), m["address"], int64v(m["port"]), int64v(m["weight"]), m["state"])
	}
	// 恢复证书
	for _, m := range data.Certs {
		tx.Exec(`INSERT OR IGNORE INTO ssl_certs(id,domain,cert_pem,key_pem,expire_at,auto_renew) VALUES(?,?,?,?,?,?)`,
			int64v(m["id"]), m["domain"], m["cert_pem"], m["key_pem"], m["expire_at"], int64v(m["auto_renew"]))
	}
	// 恢复设置
	for k, v := range data.Settings {
		tx.Exec(`INSERT OR REPLACE INTO system_settings(k,v) VALUES(?,?)`, k, v)
	}

	// 恢复黑名单
	for _, m := range data.FilterBlacklist {
		tx.Exec(`INSERT OR IGNORE INTO filter_blacklist(id,type,value,note,hits,auto_added,enabled) VALUES(?,?,?,?,?,?,?)`,
			int64v(m["id"]), m["type"], m["value"], m["note"],
			int64v(m["hits"]), int64v(m["auto_added"]), int64v(m["enabled"]))
	}
	// 恢复白名单
	for _, m := range data.FilterWhitelist {
		tx.Exec(`INSERT OR IGNORE INTO filter_whitelist(id,type,value,note,enabled) VALUES(?,?,?,?,?)`,
			int64v(m["id"]), m["type"], m["value"], m["note"], int64v(m["enabled"]))
	}

	if err := tx.Commit(); err != nil {
		util.Fail(c, 500, "恢复失败: "+err.Error())
		return
	}
	// 将证书文件写入磁盘（备份恢复时 DB 有内容但磁盘无文件）
	for _, m := range data.Certs {
		domain, _ := m["domain"].(string)
		certPEM, _ := m["cert_pem"].(string)
		keyPEM, _ := m["key_pem"].(string)
		if domain != "" && certPEM != "" && keyPEM != "" {
			engine.WriteCert(domain, certPEM, keyPEM)
		}
	}
	go engine.ApplyAll()
	go engine.ApplyFilter()
	util.OK(c, nil)
}

func int64v(v interface{}) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	}
	return 0
}
