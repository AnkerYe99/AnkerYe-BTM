package handler

import (
	"encoding/json"

	"github.com/gin-gonic/gin"

	"nginxflow/db"
	"nginxflow/engine"
	"nginxflow/util"
)

func GetSettings(c *gin.Context) {
	rows, _ := db.DB.Query(`SELECT k,v FROM system_settings`)
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		// 敏感字段仅返回是否已配置
		if k == "tencent_secret_key" || k == "sync_token" {
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
	Rules    []map[string]interface{} `json:"rules"`
	Servers  []map[string]interface{} `json:"servers"`
	Certs    []map[string]interface{} `json:"certs"`
	Settings map[string]string        `json:"settings"`
}

func Backup(c *gin.Context) {
	data := backupData{Settings: map[string]string{}}
	// Rules
	rows, _ := db.DB.Query(`SELECT id,name,protocol,listen_port,server_name,lb_method,
		ssl_cert_id,ssl_redirect,hc_enabled,hc_interval,hc_timeout,hc_path,hc_rise,hc_fall,
		log_max_size,custom_config,status FROM rules ORDER BY id`)
	for rows.Next() {
		var id int64
		var name, proto, srvName, lbm, hcPath, logSize, custom string
		var port, sslRed, hcEn, hcInt, hcTo, hcRise, hcFall, status int
		var sslCert interface{}
		rows.Scan(&id, &name, &proto, &port, &srvName, &lbm, &sslCert, &sslRed, &hcEn, &hcInt, &hcTo, &hcPath, &hcRise, &hcFall, &logSize, &custom, &status)
		data.Rules = append(data.Rules, map[string]interface{}{
			"id": id, "name": name, "protocol": proto, "listen_port": port,
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

	b, _ := json.MarshalIndent(data, "", "  ")
	c.Header("Content-Disposition", "attachment; filename=nginxflow-backup.json")
	c.Data(200, "application/json", b)
}

func Restore(c *gin.Context) {
	// TODO: 导入逻辑（删除旧数据 → 插入新数据 → ApplyAll）
	util.OK(c, gin.H{"msg": "暂未实现"})
}
