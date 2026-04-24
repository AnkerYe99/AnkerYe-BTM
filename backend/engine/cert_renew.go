package engine

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"github.com/go-acme/lego/v4/registration"

	"nginxflow/db"
)

// legoUser 实现 lego registration.User 接口
type legoUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *legoUser) GetEmail() string                        { return u.Email }
func (u *legoUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *legoUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// getACMEClient 初始化 lego client，使用 DNSPod (腾讯云) DNS-01 验证
func getACMEClient(domain string) (*lego.Client, *legoUser, error) {
	var sid, skey, email, accountJSON, accountKeyPEM string
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='tencent_secret_id'`).Scan(&sid)
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='tencent_secret_key'`).Scan(&skey)
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='acme_email'`).Scan(&email)
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='acme_account_json'`).Scan(&accountJSON)
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='acme_account_key'`).Scan(&accountKeyPEM)

	if sid == "" || skey == "" {
		return nil, nil, fmt.Errorf("未配置腾讯云 API 密钥（SecretId / SecretKey），请在系统设置中填写")
	}
	if email == "" {
		return nil, nil, fmt.Errorf("未配置 ACME 邮箱，请在系统设置「腾讯云 SSL 续签」中填写邮箱")
	}

	// 加载或生成账号私钥
	var accountKey crypto.PrivateKey
	if accountKeyPEM != "" {
		block, _ := pem.Decode([]byte(accountKeyPEM))
		if block != nil {
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				accountKey = key
			}
		}
	}
	if accountKey == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("生成 ACME 私钥失败: %v", err)
		}
		accountKey = key
		// 保存私钥
		keyBytes, _ := x509.MarshalECPrivateKey(key)
		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
		db.DB.Exec(`INSERT INTO system_settings(k,v) VALUES('acme_account_key',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, string(pemBlock))
	}

	user := &legoUser{Email: email, key: accountKey}

	// 加载已有注册信息
	if accountJSON != "" {
		var reg registration.Resource
		if err := json.Unmarshal([]byte(accountJSON), &reg); err == nil {
			user.Registration = &reg
		}
	}

	// 设置 lego client（Let's Encrypt 生产环境）
	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = lego.LEDirectoryProduction
	legoConfig.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("初始化 ACME 客户端失败: %v", err)
	}

	// 配置腾讯云 DNSPod DNS-01 provider
	tcConfig := tencentcloud.NewDefaultConfig()
	tcConfig.SecretID = sid
	tcConfig.SecretKey = skey
	provider, err := tencentcloud.NewDNSProviderConfig(tcConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("初始化腾讯云 DNS 提供者失败: %v", err)
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, nil, fmt.Errorf("设置 DNS-01 失败: %v", err)
	}

	// 如果未注册，先注册 Let's Encrypt 账号
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, nil, fmt.Errorf("注册 Let's Encrypt 账号失败: %v", err)
		}
		user.Registration = reg
		regJSON, _ := json.Marshal(reg)
		db.DB.Exec(`INSERT INTO system_settings(k,v) VALUES('acme_account_json',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, string(regJSON))
		log.Printf("[lego] Let's Encrypt 账号注册成功: %s", email)
	}

	return client, user, nil
}

func tsNow() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func appendRenewLog(certID int64, msg string) {
	line := "[" + tsNow() + "] " + msg
	db.DB.Exec(`UPDATE ssl_certs SET renew_log = CASE
		WHEN renew_log IS NULL OR renew_log='' THEN ?
		ELSE renew_log || char(10) || ?
	END WHERE id=?`, line, line, certID)
}

func setRenewStatus(certID int64, status, tcCertID, msg string) {
	db.DB.Exec(`UPDATE ssl_certs SET renew_status=?, tencent_cert_id=?,
		last_renew_at=datetime('now','localtime') WHERE id=?`, status, tcCertID, certID)
	appendRenewLog(certID, msg)
}

// RenewCert 用 Let's Encrypt + DNSPod DNS-01 申请证书（异步执行）
func RenewCert(certID int64, domain string) error {
	db.DB.Exec(`UPDATE ssl_certs SET renew_log='', renew_status='pending' WHERE id=?`, certID)
	appendRenewLog(certID, "开始向 Let's Encrypt 申请证书，DNS-01 验证方式（腾讯云 DNSPod），域名: "+domain)

	go func() {
		if err := doRenew(certID, domain); err != nil {
			setRenewStatus(certID, "failed", "", err.Error())
			SendNotify("notify_cert_fail", "证书续签失败 - "+domain,
				fmt.Sprintf("域名: %s\n失败原因: %s", domain, err.Error()))
			log.Printf("[lego] %s 续签失败: %v", domain, err)
		}
	}()
	return nil
}

func doRenew(certID int64, domain string) error {
	appendRenewLog(certID, "初始化 ACME 客户端（Let's Encrypt）...")
	client, _, err := getACMEClient(domain)
	if err != nil {
		return err
	}

	appendRenewLog(certID, "向 DNSPod 添加 DNS TXT 验证记录，等待 DNS 传播（约 1-3 分钟）...")

	req := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	certs, err := client.Certificate.Obtain(req)
	if err != nil {
		return fmt.Errorf("申请证书失败: %v", err)
	}

	appendRenewLog(certID, "DNS 验证通过，证书已签发，正在解析证书信息...")

	// 解析到期时间
	certPEM := string(certs.Certificate)
	keyPEM := string(certs.PrivateKey)
	expireAt := parseCertExpiry(certPEM)

	appendRenewLog(certID, fmt.Sprintf("证书到期时间: %s，正在写入数据库和磁盘...", expireAt))

	db.DB.Exec(`UPDATE ssl_certs SET cert_pem=?, key_pem=?, expire_at=?,
		renew_status='success',
		last_renew_at=datetime('now','localtime'), updated_at=datetime('now','localtime')
		WHERE id=?`, certPEM, keyPEM, expireAt, certID)

	if err := WriteCert(domain, certPEM, keyPEM); err != nil {
		return fmt.Errorf("写入证书文件失败: %v", err)
	}

	appendRenewLog(certID, "证书文件已写入磁盘，正在重载 nginx...")
	Reload()

	db.DB.Exec(`UPDATE ssl_certs SET renew_status='success' WHERE id=?`, certID)
	appendRenewLog(certID, "续签完成！nginx 已重载，新证书已生效。CA: Let's Encrypt")

	SendNotify("notify_cert_success", "证书续签成功 - "+domain,
		fmt.Sprintf("域名: %s\n证书到期时间: %s\nCA: Let's Encrypt", domain, expireAt))
	log.Printf("[lego] %s 续签成功，到期 %s", domain, expireAt)
	return nil
}

func parseCertExpiry(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return cert.NotAfter.Format("2006-01-02 15:04:05")
}

// AutoRenewCheck 检查所有开启自动续签的证书，到期前 10 天自动续签
func AutoRenewCheck() {
	rows, _ := db.DB.Query(`SELECT id, domain, expire_at, renew_status FROM ssl_certs WHERE auto_renew=1`)
	defer rows.Close()
	for rows.Next() {
		var id int64
		var domain, expireAt, renewStatus string
		rows.Scan(&id, &domain, &expireAt, &renewStatus)
		if renewStatus == "pending" {
			continue
		}
		expire, err := time.Parse("2006-01-02 15:04:05", expireAt)
		if err != nil {
			continue
		}
		daysLeft := int(time.Until(expire).Hours() / 24)
		if daysLeft <= 10 {
			log.Printf("[auto-renew] %s 剩余 %d 天，开始续签...", domain, daysLeft)
			if err := RenewCert(id, domain); err != nil {
				log.Printf("[auto-renew] %s 失败: %v", domain, err)
			}
		}
	}
}
