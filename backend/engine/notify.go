package engine

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"ankerye-flow/db"
)

type smtpCfg struct {
	host     string
	port     int
	user     string
	password string
	from     string
	to       string
	useTLS   bool
}

func loadSMTPCfg() (smtpCfg, error) {
	keys := []string{"smtp_host", "smtp_port", "smtp_user", "smtp_password", "smtp_from", "notify_email_to", "smtp_tls"}
	vals := map[string]string{}
	rows, _ := db.DB.Query(`SELECT k,v FROM system_settings WHERE k IN ('smtp_host','smtp_port','smtp_user','smtp_password','smtp_from','notify_email_to','smtp_tls')`)
	defer rows.Close()
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		vals[k] = v
	}
	_ = keys
	if vals["smtp_host"] == "" || vals["notify_email_to"] == "" {
		return smtpCfg{}, fmt.Errorf("SMTP 未配置")
	}
	port, _ := strconv.Atoi(vals["smtp_port"])
	if port == 0 {
		port = 465
	}
	return smtpCfg{
		host:     vals["smtp_host"],
		port:     port,
		user:     vals["smtp_user"],
		password: vals["smtp_password"],
		from:     vals["smtp_from"],
		to:       vals["notify_email_to"],
		useTLS:   vals["smtp_tls"] != "0",
	}, nil
}

func isNotifyEnabled(key string) bool {
	var v string
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k=?`, key).Scan(&v)
	return v == "1"
}

// SendNotify 发送通知邮件，notifyKey 为空时强制发送
func SendNotify(notifyKey, subject, body string) error {
	if notifyKey != "" && !isNotifyEnabled(notifyKey) {
		return nil
	}
	cfg, err := loadSMTPCfg()
	if err != nil {
		return err
	}

	// 信封发件人（MAIL FROM）必须和登录账号一致，163/126 等服务商强制要求
	envelopeFrom := extractAddr(cfg.user)

	// From 头只影响显示名称，用配置的 smtp_from；没填则直接用账号
	displayFrom := cfg.from
	if displayFrom == "" {
		displayFrom = cfg.user
	}

	msg := "From: " + displayFrom + "\r\n" +
		"To: " + cfg.to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" + body

	addr := fmt.Sprintf("%s:%d", cfg.host, cfg.port)

	if cfg.useTLS {
		return sendTLS(addr, cfg, envelopeFrom, msg)
	}
	return sendSTARTTLS(addr, cfg, envelopeFrom, msg)
}

func sendTLS(addr string, cfg smtpCfg, from, msg string) error {
	tlsCfg := &tls.Config{ServerName: cfg.host}
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("TLS 连接失败: %v", err)
	}
	client, err := smtp.NewClient(conn, cfg.host)
	if err != nil {
		return fmt.Errorf("SMTP 客户端失败: %v", err)
	}
	defer client.Close()
	if cfg.user != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.user, cfg.password, cfg.host)); err != nil {
			return fmt.Errorf("SMTP 认证失败: %v", err)
		}
	}
	return sendMail(client, from, cfg.to, msg)
}

func sendSTARTTLS(addr string, cfg smtpCfg, from, msg string) error {
	host, _, _ := net.SplitHostPort(addr)
	auth := smtp.PlainAuth("", cfg.user, cfg.password, host)
	_ = &tls.Config{ServerName: host}
	return smtp.SendMail(addr, auth, from, strings.Split(cfg.to, ","), []byte(msg))
}

// extractAddr 从 "Name <addr>" 中提取纯地址，没有尖括号则原样返回
func extractAddr(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "<"); i >= 0 {
		if j := strings.Index(s[i:], ">"); j >= 0 {
			return strings.TrimSpace(s[i+1 : i+j])
		}
	}
	return s
}

func sendMail(client *smtp.Client, from, to, msg string) error {
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, addr := range strings.Split(to, ",") {
		if err := client.Rcpt(strings.TrimSpace(addr)); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(w, msg)
	if err != nil {
		return err
	}
	return w.Close()
}
