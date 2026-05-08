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
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/dnspod"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"github.com/go-acme/lego/v4/registration"

	"ankerye-flow/db"
)

type legoUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *legoUser) GetEmail() string                        { return u.Email }
func (u *legoUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *legoUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

func loadACMESettings() (dpID, dpKey, sid, skey, email, accountJSON, accountKeyPEM string) {
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='dnspod_id'`).Scan(&dpID)
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='dnspod_key'`).Scan(&dpKey)
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='tencent_secret_id'`).Scan(&sid)
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='tencent_secret_key'`).Scan(&skey)
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='acme_email'`).Scan(&email)
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='acme_account_json'`).Scan(&accountJSON)
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='acme_account_key'`).Scan(&accountKeyPEM)
	return
}

func buildLegoClient(providerName string, dpID, dpKey, sid, skey, email, accountJSON, accountKeyPEM string) (*lego.Client, error) {
	// 加载或生成账号私钥
	var accountKey crypto.PrivateKey
	if accountKeyPEM != "" {
		block, _ := pem.Decode([]byte(accountKeyPEM))
		if block != nil {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				accountKey = key
			}
		}
	}
	if accountKey == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("生成 ACME 私钥失败: %v", err)
		}
		accountKey = key
		keyBytes, _ := x509.MarshalECPrivateKey(key)
		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
		db.DB.Exec(`INSERT INTO system_settings(k,v) VALUES('acme_account_key',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, string(pemBlock))
	}

	user := &legoUser{Email: email, key: accountKey}
	if accountJSON != "" {
		var reg registration.Resource
		if err := json.Unmarshal([]byte(accountJSON), &reg); err == nil {
			user.Registration = &reg
		}
	}

	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = lego.LEDirectoryProduction
	legoConfig.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, fmt.Errorf("初始化 ACME 客户端失败: %v", err)
	}

	// 跳过 lego 的权威 DNS 预检（DNSPod 内部同步有延迟），让 LE 直接验证
	skipPropCheck := dns01.DisableCompletePropagationRequirement()
	switch providerName {
	case "dnspod":
		cfg := dnspod.NewDefaultConfig()
		cfg.LoginToken = dpID + "," + dpKey
		cfg.PropagationTimeout = 5 * time.Minute
		cfg.PollingInterval = 10 * time.Second
		p, err := dnspod.NewDNSProviderConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("初始化 DNSPod 失败: %v", err)
		}
		client.Challenge.SetDNS01Provider(p, skipPropCheck)
	case "tencentcloud":
		cfg := tencentcloud.NewDefaultConfig()
		cfg.SecretID = sid
		cfg.SecretKey = skey
		cfg.PropagationTimeout = 5 * time.Minute
		cfg.PollingInterval = 10 * time.Second
		p, err := tencentcloud.NewDNSProviderConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("初始化腾讯云 DNS 失败: %v", err)
		}
		client.Challenge.SetDNS01Provider(p, skipPropCheck)
	}

	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("注册 Let's Encrypt 账号失败: %v", err)
		}
		user.Registration = reg
		regJSON, _ := json.Marshal(reg)
		db.DB.Exec(`INSERT INTO system_settings(k,v) VALUES('acme_account_json',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, string(regJSON))
	}
	return client, nil
}

func obtainCert(client *lego.Client, domain string) (*certificate.Resource, error) {
	return client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	})
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

func setRenewStatus(certID int64, status, msg string) {
	db.DB.Exec(`UPDATE ssl_certs SET renew_status=?,
		last_renew_at=datetime('now','localtime') WHERE id=?`, status, certID)
	appendRenewLog(certID, msg)
}

// RenewCert 异步续签：优先 DNSPod Token API，失败后 fallback 到腾讯云 CAM
func RenewCert(certID int64, domain string) error {
	db.DB.Exec(`UPDATE ssl_certs SET renew_log='', renew_status='pending' WHERE id=?`, certID)
	appendRenewLog(certID, "开始续签，域名: "+domain)

	go func() {
		if err := doRenew(certID, domain); err != nil {
			setRenewStatus(certID, "failed", "续签最终失败: "+err.Error())
			SendNotify("notify_cert_fail", "证书续签失败 - "+domain,
				fmt.Sprintf("域名: %s\n失败原因: %s", domain, err.Error()))
			log.Printf("[renew] %s 最终失败: %v", domain, err)
		}
	}()
	return nil
}

func doRenew(certID int64, domain string) error {
	dpID, dpKey, sid, skey, email, accountJSON, accountKeyPEM := loadACMESettings()

	if email == "" {
		return fmt.Errorf("未配置 ACME 邮箱，请在系统设置中填写")
	}

	// 第一步：DNSPod Token API
	if dpID != "" && dpKey != "" {
		appendRenewLog(certID, "[方式1] 尝试 DNSPod Token API（ID: "+dpID+"）...")
		client, err := buildLegoClient("dnspod", dpID, dpKey, sid, skey, email, accountJSON, accountKeyPEM)
		if err != nil {
			appendRenewLog(certID, "[方式1] 初始化失败: "+err.Error()+"，切换方式2...")
		} else {
			appendRenewLog(certID, "[方式1] 向 DNSPod 添加 TXT 验证记录...")
			certs, err := obtainCert(client, domain)
			if err == nil {
				return installCert(certID, domain, certs, "DNSPod Token API")
			}
			appendRenewLog(certID, "[方式1] DNSPod 申请失败: "+err.Error()+"，切换方式2...")
			log.Printf("[renew] %s DNSPod 失败，尝试腾讯云 CAM: %v", domain, err)
		}
	}

	// 第二步：腾讯云 CAM API fallback
	if sid != "" && skey != "" {
		appendRenewLog(certID, "[方式2] 尝试腾讯云 CAM API（SecretId: "+sid[:min(8, len(sid))]+"...）...")
		client, err := buildLegoClient("tencentcloud", dpID, dpKey, sid, skey, email, accountJSON, accountKeyPEM)
		if err != nil {
			return fmt.Errorf("方式2 初始化失败: %v", err)
		}
		appendRenewLog(certID, "[方式2] 向腾讯云 DNSPod 添加 TXT 验证记录...")
		certs, err := obtainCert(client, domain)
		if err != nil {
			return fmt.Errorf("方式2 申请失败: %v", err)
		}
		return installCert(certID, domain, certs, "腾讯云 CAM API")
	}

	return fmt.Errorf("未配置任何 DNS API（请填写 DNSPod ID/Token 或腾讯云 SecretId/Key）")
}

func installCert(certID int64, domain string, certs *certificate.Resource, provider string) error {
	appendRenewLog(certID, "DNS 验证通过，证书已签发，正在解析证书信息...")
	certPEM := string(certs.Certificate)
	keyPEM := string(certs.PrivateKey)
	expireAt := parseCertExpiry(certPEM)

	appendRenewLog(certID, fmt.Sprintf("证书到期时间: %s，写入数据库和磁盘...", expireAt))
	db.DB.Exec(`UPDATE ssl_certs SET cert_pem=?, key_pem=?, expire_at=?, renew_status='success',
		last_renew_at=datetime('now','localtime'), updated_at=datetime('now','localtime')
		WHERE id=?`, certPEM, keyPEM, expireAt, certID)

	if err := WriteCert(domain, certPEM, keyPEM); err != nil {
		return fmt.Errorf("写入证书文件失败: %v", err)
	}

	appendRenewLog(certID, "证书文件已写入，重载 nginx...")
	Reload()
	appendRenewLog(certID, fmt.Sprintf("续签完成！CA: Let's Encrypt，服务商: %s", provider))

	SendNotify("notify_cert_success", "证书续签成功 - "+domain,
		fmt.Sprintf("域名: %s\n到期时间: %s\n服务商: %s", domain, expireAt, provider))
	log.Printf("[renew] %s 续签成功（%s），到期 %s", domain, provider, expireAt)
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

func AutoRenewCheck() {
	// 全局禁用续签（从节点模式：证书由主节点续签后同步过来）
	var disabled string
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='cert_renew_disabled'`).Scan(&disabled)
	if disabled == "1" {
		log.Println("[auto-renew] 已禁用本机自动续签（从节点模式）")
		return
	}
	rows, err := db.DB.Query(`SELECT id, domain, expire_at, renew_status FROM ssl_certs WHERE auto_renew=1`)
	if err != nil {
		log.Printf("[auto-renew] query failed: %v", err)
		return
	}
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
		if int(time.Until(expire).Hours()/24) <= 10 {
			log.Printf("[auto-renew] %s 剩余不足10天，开始续签...", domain)
			RenewCert(id, domain)
		}
	}
}
