package model

import "database/sql"

type Rule struct {
	ID           int64          `json:"id"`
	Name         string         `json:"name"`
	Protocol     string         `json:"protocol"` // http / tcp / udp
	ListenPort   int            `json:"listen_port"` // HTTP port for http; proxy port for tcp/udp
	ListenStack  string         `json:"listen_stack"`
	HTTPSEnabled int            `json:"https_enabled"`
	HTTPSPort    *int           `json:"https_port"`
	ServerName   string         `json:"server_name"`
	LBMethod     string         `json:"lb_method"`
	SSLCertID    sql.NullInt64  `json:"-"`
	SSLCertIDVal *int64         `json:"ssl_cert_id"`
	SSLRedirect  int            `json:"ssl_redirect"`
	HCEnabled    int            `json:"hc_enabled"`
	HCInterval   int            `json:"hc_interval"`
	HCTimeout    int            `json:"hc_timeout"`
	HCPath       string         `json:"hc_path"`
	HCRise       int            `json:"hc_rise"`
	HCFall       int            `json:"hc_fall"`
	LogMaxSize      string         `json:"log_max_size"`
	CaptureMaxSize  string         `json:"capture_max_size"`
	CustomConfig    string         `json:"custom_config"`
	CaptureBody     int            `json:"capture_body"`
	Status       int            `json:"status"`
	CreatedAt    string         `json:"created_at"`
	UpdatedAt    string         `json:"updated_at"`
	Servers      []Server       `json:"servers,omitempty"`
	Domain       string         `json:"-"` // cert domain for nginx rendering
}

type Server struct {
	ID           int64  `json:"id"`
	RuleID       int64  `json:"rule_id"`
	Address      string `json:"address"`
	Port         int    `json:"port"`
	Weight       int    `json:"weight"`
	State        string `json:"state"`
	FailCount    int    `json:"fail_count"`
	SuccessCount int    `json:"success_count"`
	LastCheckAt  string `json:"last_check_at"`
	LastErr      string `json:"last_err"`
	CreatedAt    string `json:"created_at"`
}

type Cert struct {
	ID            int64  `json:"id"`
	Domain        string `json:"domain"`
	CertPEM       string `json:"cert_pem"`
	KeyPEM        string `json:"key_pem"`
	ExpireAt      string `json:"expire_at"`
	AutoRenew     int    `json:"auto_renew"`
	TencentCertID string `json:"tencent_cert_id"`
	RenewStatus   string `json:"renew_status"`
	RenewLog      string `json:"renew_log"`
	LastRenewAt   string `json:"last_renew_at"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type HealthCheckLog struct {
	ID        int64  `json:"id"`
	ServerID  int64  `json:"server_id"`
	RuleID    int64  `json:"rule_id"`
	State     string `json:"state"`
	LatencyMs int    `json:"latency_ms"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
}

type SyncNode struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Address     string `json:"address"`
	LastSyncAt  string `json:"last_sync_at"`
	LastVersion string `json:"last_version"`
	Status      string `json:"status"`
	LastErr     string `json:"last_err"`
	CreatedAt   string `json:"created_at"`
}
