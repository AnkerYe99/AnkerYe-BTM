package handler

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"strconv"

	"github.com/gin-gonic/gin"

	"nginxflow/db"
	"nginxflow/engine"
	"nginxflow/util"
)

func ListCerts(c *gin.Context) {
	rows, err := db.DB.Query(`SELECT id,domain,expire_at,auto_renew,IFNULL(tencent_cert_id,''),
		renew_status,IFNULL(renew_log,''),IFNULL(last_renew_at,''),created_at,updated_at
		FROM ssl_certs ORDER BY id DESC`)
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	defer rows.Close()
	list := []gin.H{}
	for rows.Next() {
		var id int64
		var domain, expireAt, tcid, rStatus, rLog, lastRenew, createdAt, updatedAt string
		var autoRenew int
		rows.Scan(&id, &domain, &expireAt, &autoRenew, &tcid, &rStatus, &rLog, &lastRenew, &createdAt, &updatedAt)
		list = append(list, gin.H{
			"id": id, "domain": domain, "expire_at": expireAt, "auto_renew": autoRenew,
			"tencent_cert_id": tcid, "renew_status": rStatus, "renew_log": rLog,
			"last_renew_at": lastRenew, "created_at": createdAt, "updated_at": updatedAt,
		})
	}
	util.OK(c, list)
}

func GetCert(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var domain, certPEM, keyPEM, expireAt, rStatus string
	var autoRenew int
	err := db.DB.QueryRow(`SELECT domain,cert_pem,key_pem,expire_at,auto_renew,renew_status
		FROM ssl_certs WHERE id=?`, id).Scan(&domain, &certPEM, &keyPEM, &expireAt, &autoRenew, &rStatus)
	if err != nil {
		util.Fail(c, 404, "证书不存在")
		return
	}
	util.OK(c, gin.H{
		"id": id, "domain": domain, "cert_pem": certPEM, "key_pem": keyPEM,
		"expire_at": expireAt, "auto_renew": autoRenew, "renew_status": rStatus,
	})
}

func UploadCert(c *gin.Context) {
	var req struct {
		CertPEM   string `json:"cert_pem" binding:"required"`
		KeyPEM    string `json:"key_pem" binding:"required"`
		AutoRenew int    `json:"auto_renew"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		util.Fail(c, 400, "参数错误")
		return
	}

	// 验证证书与私钥是否匹配
	if _, err := tls.X509KeyPair([]byte(req.CertPEM), []byte(req.KeyPEM)); err != nil {
		util.Fail(c, 400, "证书与私钥不匹配: "+err.Error())
		return
	}

	// 解析证书
	block, _ := pem.Decode([]byte(req.CertPEM))
	if block == nil {
		util.Fail(c, 400, "证书 PEM 解析失败")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		util.Fail(c, 400, "证书解析失败: "+err.Error())
		return
	}
	expireAt := cert.NotAfter.Format("2006-01-02 15:04:05")

	// 自动从证书中提取域名：优先 SAN，其次 CN
	domain := cert.Subject.CommonName
	if len(cert.DNSNames) > 0 {
		domain = cert.DNSNames[0]
	}
	if domain == "" {
		util.Fail(c, 400, "无法从证书中提取域名（缺少 CN/SAN）")
		return
	}

	// 写数据库（重复域名则更新）
	_, err = db.DB.Exec(`INSERT INTO ssl_certs(domain,cert_pem,key_pem,expire_at,auto_renew) VALUES(?,?,?,?,?)
		ON CONFLICT(domain) DO UPDATE SET cert_pem=excluded.cert_pem, key_pem=excluded.key_pem,
		expire_at=excluded.expire_at, auto_renew=excluded.auto_renew,
		updated_at=datetime('now','localtime')`,
		domain, req.CertPEM, req.KeyPEM, expireAt, req.AutoRenew)
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	// 写入磁盘
	if err := engine.WriteCert(domain, req.CertPEM, req.KeyPEM); err != nil {
		util.Fail(c, 500, "写证书文件失败: "+err.Error())
		return
	}
	var id int64
	db.DB.QueryRow(`SELECT id FROM ssl_certs WHERE domain=?`, domain).Scan(&id)
	util.OK(c, gin.H{"id": id, "domain": domain, "expire_at": expireAt})
}

func DeleteCert(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	// 检查是否被规则占用
	var count int
	db.DB.QueryRow(`SELECT COUNT(*) FROM rules WHERE ssl_cert_id=?`, id).Scan(&count)
	if count > 0 {
		util.Fail(c, 400, "证书被规则占用，无法删除")
		return
	}
	db.DB.Exec(`DELETE FROM ssl_certs WHERE id=?`, id)
	util.OK(c, nil)
}

func ToggleAutoRenew(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		AutoRenew int `json:"auto_renew"`
	}
	c.ShouldBindJSON(&req)
	db.DB.Exec(`UPDATE ssl_certs SET auto_renew=? WHERE id=?`, req.AutoRenew, id)
	util.OK(c, nil)
}

func ManualRenew(c *gin.Context) {
	// 腾讯云续签需要 API 密钥，这里先返回占位响应
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	// TODO: 调用 cert.Renew()
	util.OK(c, gin.H{"id": id, "status": "scheduled", "msg": "已加入续签队列"})
}
