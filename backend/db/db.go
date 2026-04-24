package db

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func Init(path string) error {
	dsn := fmt.Sprintf("file:%s?_journal=WAL&_busy_timeout=5000&_fk=on", path)
	var err error
	DB, err = sql.Open("sqlite3", dsn)
	if err != nil {
		return err
	}
	DB.SetMaxOpenConns(1) // SQLite 单写避免锁冲突
	if err := DB.Ping(); err != nil {
		return err
	}
	if err := migrate(); err != nil {
		return err
	}
	log.Println("[db] ready:", path)
	return nil
}

func migrate() error {
	schemas := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT DEFAULT 'admin',
			created_at DATETIME DEFAULT (datetime('now','localtime'))
		)`,
		`CREATE TABLE IF NOT EXISTS rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			protocol TEXT NOT NULL CHECK(protocol IN ('http','tcp','udp')),
			listen_port INTEGER NOT NULL,
			listen_stack TEXT DEFAULT 'both' CHECK(listen_stack IN ('v4','v6','both')),
			https_enabled INTEGER DEFAULT 0,
			https_port INTEGER DEFAULT NULL,
			server_name TEXT DEFAULT '',
			lb_method TEXT DEFAULT 'round_robin',
			ssl_cert_id INTEGER DEFAULT NULL,
			ssl_redirect INTEGER DEFAULT 0,
			hc_enabled INTEGER DEFAULT 1,
			hc_interval INTEGER DEFAULT 10,
			hc_timeout INTEGER DEFAULT 3,
			hc_path TEXT DEFAULT '/health',
			hc_rise INTEGER DEFAULT 2,
			hc_fall INTEGER DEFAULT 3,
			log_max_size TEXT DEFAULT '5M',
			custom_config TEXT DEFAULT '',
			status INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT (datetime('now','localtime')),
			updated_at DATETIME DEFAULT (datetime('now','localtime'))
		)`,
		// 迁移：忽略已存在字段的错误
		`ALTER TABLE rules ADD COLUMN listen_stack TEXT DEFAULT 'both'`,
		`ALTER TABLE rules ADD COLUMN https_enabled INTEGER DEFAULT 0`,
		`ALTER TABLE rules ADD COLUMN https_port INTEGER DEFAULT NULL`,
		`CREATE TABLE IF NOT EXISTS upstream_servers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
			address TEXT NOT NULL,
			port INTEGER NOT NULL,
			weight INTEGER DEFAULT 1,
			state TEXT DEFAULT 'up' CHECK(state IN ('up','down','disabled')),
			fail_count INTEGER DEFAULT 0,
			success_count INTEGER DEFAULT 0,
			last_check_at DATETIME DEFAULT NULL,
			last_err TEXT DEFAULT NULL,
			created_at DATETIME DEFAULT (datetime('now','localtime'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_servers_rule_id ON upstream_servers(rule_id)`,
		`CREATE TABLE IF NOT EXISTS ssl_certs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain TEXT NOT NULL UNIQUE,
			cert_pem TEXT NOT NULL,
			key_pem TEXT NOT NULL,
			expire_at DATETIME NOT NULL,
			auto_renew INTEGER DEFAULT 1,
			tencent_cert_id TEXT DEFAULT NULL,
			renew_status TEXT DEFAULT 'idle',
			renew_log TEXT DEFAULT NULL,
			last_renew_at DATETIME DEFAULT NULL,
			created_at DATETIME DEFAULT (datetime('now','localtime')),
			updated_at DATETIME DEFAULT (datetime('now','localtime'))
		)`,
		`CREATE TABLE IF NOT EXISTS health_check_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			server_id INTEGER NOT NULL,
			rule_id INTEGER NOT NULL,
			state TEXT NOT NULL CHECK(state IN ('up','down')),
			latency_ms INTEGER DEFAULT 0,
			message TEXT DEFAULT NULL,
			created_at DATETIME DEFAULT (datetime('now','localtime'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_hclog_server ON health_check_logs(server_id, created_at)`,
		`CREATE TRIGGER IF NOT EXISTS trim_hc_logs AFTER INSERT ON health_check_logs
			BEGIN
				DELETE FROM health_check_logs WHERE id <=
				(SELECT id FROM health_check_logs ORDER BY id DESC LIMIT 1 OFFSET 10000);
			END`,
		`CREATE TABLE IF NOT EXISTS system_settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS sync_nodes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			address TEXT NOT NULL,
			last_sync_at DATETIME DEFAULT NULL,
			last_version TEXT DEFAULT NULL,
			status TEXT DEFAULT 'unknown',
			last_err TEXT DEFAULT NULL,
			created_at DATETIME DEFAULT (datetime('now','localtime'))
		)`,
	}
	for _, s := range schemas {
		if _, err := DB.Exec(s); err != nil {
			// ALTER TABLE 会因字段已存在而报错，忽略迁移类错误
			if len(s) > 12 && s[:12] == "ALTER TABLE " {
				continue
			}
			return fmt.Errorf("migrate failed on %q: %w", s[:60], err)
		}
	}

	// 默认系统设置
	defaults := map[string]string{
		"nginx_worker_processes":     "auto",
		"nginx_worker_connections":   "1024",
		"nginx_keepalive_timeout":    "65",
		"nginx_client_max_body_size": "64m",
		"tencent_secret_id":          "",
		"tencent_secret_key":         "",
		"tencent_dns_region":         "ap-guangzhou",
		"sync_token":                 "",
		"notify_mm_webhook":          "",
		"default_log_max_size":       "5M",
	}
	for k, v := range defaults {
		DB.Exec(`INSERT OR IGNORE INTO system_settings(k,v) VALUES(?,?)`, k, v)
	}
	return nil
}
