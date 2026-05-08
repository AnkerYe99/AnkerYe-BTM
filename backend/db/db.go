package db

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

// DB 用于同步读写（用户操作、规则 CRUD 等需要立即返回结果的场景）
var DB *sql.DB

// asyncCh 是异步写队列，健康检查/统计等高频写入投入此 channel，
// 由单个 writer goroutine 串行消费，无论多少 worker 并发都不会阻塞调用方。
// 缓冲 100000 足以应对数千 worker 的突发。
var asyncCh = make(chan asyncOp, 100000)

type asyncOp struct {
	query string
	args  []interface{}
}

// AsyncExec 火且忘：写入 channel 立即返回，不阻塞调用方。
// 适用于健康检查状态更新、统计累积等允许丢失单次的场景。
func AsyncExec(query string, args ...interface{}) {
	select {
	case asyncCh <- asyncOp{query, args}:
	default:
		// channel 满时静默丢弃（正常情况不会发生）
		log.Printf("[db] async queue full, write dropped")
	}
}

func startAsyncWriter() {
	go func() {
		for op := range asyncCh {
			if _, err := DB.Exec(op.query, op.args...); err != nil {
				log.Printf("[db] async exec error: %v", err)
			}
		}
	}()
}

func Init(path string) error {
	// 读连接池：WAL 模式允许多个并发读，不限制连接数
	dsn := fmt.Sprintf("file:%s?_journal=WAL&_busy_timeout=5000&_fk=on", path)
	var err error
	DB, err = sql.Open("sqlite3", dsn)
	if err != nil {
		return err
	}
	// 读操作允许并发；写操作通过 AsyncExec channel 串行化，
	// 不再依赖连接数来限制并发写，彻底解决高并发下的连接排队问题。
	DB.SetMaxOpenConns(16)
	DB.SetMaxIdleConns(16)
	if err := DB.Ping(); err != nil {
		return err
	}
	if err := migrate(); err != nil {
		return err
	}
	startAsyncWriter()
	log.Println("[db] ready:", path)
	return nil
}

// versionedMigrations 是有序的增量迁移列表。
// 规则：
//   - version 从 1 开始严格递增，不可删除或修改已有记录
//   - sql 中每条语句独立执行，ALTER TABLE 失败会被忽略（字段已存在）
//   - 新增表结构变更在此追加，不要修改已有条目
var versionedMigrations = []struct {
	version int
	name    string
	sql     []string
}{
	{1, "initial_schema", []string{
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
			protocol TEXT NOT NULL CHECK(protocol IN ('http','tcp','udp','tcpudp')),
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
		`CREATE TABLE IF NOT EXISTS rule_stats (
			rule_id  INTEGER NOT NULL,
			date     TEXT NOT NULL,
			requests INTEGER DEFAULT 0,
			bytes_out INTEGER DEFAULT 0,
			s1xx INTEGER DEFAULT 0,
			s2xx INTEGER DEFAULT 0,
			s3xx INTEGER DEFAULT 0,
			s4xx INTEGER DEFAULT 0,
			s5xx INTEGER DEFAULT 0,
			PRIMARY KEY (rule_id, date)
		)`,
		`CREATE TABLE IF NOT EXISTS log_parse_state (
			log_file TEXT PRIMARY KEY,
			inode    INTEGER DEFAULT 0,
			offset   INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS server_stats (
			server_id INTEGER NOT NULL,
			date      TEXT NOT NULL,
			requests  INTEGER DEFAULT 0,
			bytes_out INTEGER DEFAULT 0,
			s1xx INTEGER DEFAULT 0,
			s2xx INTEGER DEFAULT 0,
			s3xx INTEGER DEFAULT 0,
			s4xx INTEGER DEFAULT 0,
			s5xx INTEGER DEFAULT 0,
			PRIMARY KEY (server_id, date)
		)`,
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
	}},
	{2, "add_filter_tables", []string{
		`CREATE TABLE IF NOT EXISTS filter_blacklist (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			type       TEXT    NOT NULL CHECK(type IN ('ip','cidr','path','ua','method')),
			value      TEXT    NOT NULL,
			note       TEXT    DEFAULT '',
			hits       INTEGER DEFAULT 0,
			auto_added INTEGER DEFAULT 0,
			enabled    INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT (datetime('now','localtime'))
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_filter_bl ON filter_blacklist(type,value)`,
		`CREATE TABLE IF NOT EXISTS filter_whitelist (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			type       TEXT    NOT NULL CHECK(type IN ('ip','cidr')),
			value      TEXT    NOT NULL,
			note       TEXT    DEFAULT '',
			enabled    INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT (datetime('now','localtime'))
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_filter_wl ON filter_whitelist(type,value)`,
		`INSERT OR IGNORE INTO filter_blacklist(type,value,note) VALUES
			('path','~*/wp-login.php','WordPress 登录爆破'),
			('path','~*/.env','环境变量探测'),
			('path','~*/.git/','Git 仓库探测'),
			('path','~*/phpmyadmin','phpMyAdmin 探测'),
			('path','~*/adminer','Adminer 探测'),
			('path','~*/phpinfo','PHP 信息探测'),
			('path','~*/shell.php','Webshell 探测'),
			('path','~*/eval-stdin.php','PHP 代码注入'),
			('path','~*/.aws/credentials','AWS 密钥探测'),
			('path','~*/config.php','配置文件探测'),
			('path','~*/backup.sql','备份文件探测'),
			('path','~*/db.sql','数据库文件探测'),
			('path','~*/xmlrpc.php','WordPress XML-RPC 攻击'),
			('path','~*/actuator/env','Spring Boot 信息泄露')`,
		`INSERT OR IGNORE INTO filter_blacklist(type,value,note) VALUES
			('ua','~*sqlmap','SQLMap 注入扫描'),
			('ua','~*nikto','Nikto 漏洞扫描'),
			('ua','~*nmap','Nmap 端口扫描'),
			('ua','~*masscan','Masscan 扫描'),
			('ua','~*nuclei','Nuclei 漏洞利用'),
			('ua','~*shodan','Shodan 爬虫'),
			('ua','~*censys','Censys 扫描'),
			('ua','~*zgrab','ZGrab 扫描'),
			('ua','~*nessus','Nessus 漏洞扫描'),
			('ua','~*acunetix','Acunetix 扫描'),
			('ua','~*w3af','W3AF 扫描'),
			('ua','~*burpsuite','Burp Suite 代理'),
			('ua','~*dirsearch','Dirsearch 目录扫描')`,
	}},
	{3, "add_method_filter", []string{
		// 重建 filter_blacklist，将 CHECK 约束扩展支持 method 类型
		`ALTER TABLE filter_blacklist RENAME TO _filter_blacklist_v2`,
		`CREATE TABLE filter_blacklist (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			type       TEXT    NOT NULL CHECK(type IN ('ip','cidr','path','ua','method')),
			value      TEXT    NOT NULL,
			note       TEXT    DEFAULT '',
			hits       INTEGER DEFAULT 0,
			auto_added INTEGER DEFAULT 0,
			enabled    INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT (datetime('now','localtime'))
		)`,
		`INSERT INTO filter_blacklist SELECT * FROM _filter_blacklist_v2`,
		`DROP TABLE _filter_blacklist_v2`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_filter_bl ON filter_blacklist(type,value)`,
		// 内置方法黑名单：非标准/危险 HTTP 方法
		`INSERT OR IGNORE INTO filter_blacklist(type,value,note) VALUES
			('method','PRI','HTTP/2 预连接探测，常见于扫描器'),
			('method','PROPFIND','WebDAV 目录枚举，用于探测文件结构'),
			('method','MGLNDD','自动化扫描工具私有标识，无正常业务用途'),
			('method','CONNECT','代理穿透尝试'),
			('method','TRACE','HTTP TRACE 方法，可用于 XST 攻击')`,
	}},
	{4, "sync_incremental", []string{
		// 修复 sync_nodes 重复行：保留每个 address 中 id 最小的那一条
		`DELETE FROM sync_nodes WHERE id NOT IN (
			SELECT MIN(id) FROM sync_nodes GROUP BY address
		)`,
		// 添加 UNIQUE 约束，后续 ON CONFLICT(address) 才能正确 upsert
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_sync_nodes_addr ON sync_nodes(address)`,
		// 每种数据类型独立记录最后同步时间，主节点 UI 可按类型显示从节点状态
		`ALTER TABLE sync_nodes ADD COLUMN last_rules_sync_at DATETIME DEFAULT NULL`,
		`ALTER TABLE sync_nodes ADD COLUMN last_certs_sync_at DATETIME DEFAULT NULL`,
		`ALTER TABLE sync_nodes ADD COLUMN last_filter_sync_at DATETIME DEFAULT NULL`,
		// 过滤表加 updated_at，支持增量同步（与 rules/ssl_certs 保持一致）
		`ALTER TABLE filter_blacklist ADD COLUMN updated_at DATETIME DEFAULT (datetime('now','localtime'))`,
		`ALTER TABLE filter_whitelist ADD COLUMN updated_at DATETIME DEFAULT (datetime('now','localtime'))`,
		// tombstone 表：记录主节点删除事件，供从节点增量同步时清理本地数据
		`CREATE TABLE IF NOT EXISTS sync_tombstones (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			table_name TEXT    NOT NULL,
			record_key TEXT    NOT NULL,
			deleted_at DATETIME DEFAULT (datetime('now','localtime'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tombstones ON sync_tombstones(table_name, deleted_at)`,
		// 自动清理 30 天以上的 tombstone
		`CREATE TRIGGER IF NOT EXISTS trim_tombstones AFTER INSERT ON sync_tombstones
			BEGIN
				DELETE FROM sync_tombstones
				WHERE deleted_at < datetime('now', '-30 days', 'localtime');
			END`,
	}},
	{5, "add_request_capture", []string{
		// 规则级开关：是否记录请求体（POST body）到独立 capture log，用于回放/测试数据
		`ALTER TABLE rules ADD COLUMN capture_body INTEGER DEFAULT 0`,
	}},
	{6, "add_capture_max_size", []string{
		`ALTER TABLE rules ADD COLUMN capture_max_size TEXT DEFAULT '5M'`,
	}},
}

func migrate() error {
	// 创建迁移版本表
	if _, err := DB.Exec(`CREATE TABLE IF NOT EXISTS _schema_version (
		version    INTEGER NOT NULL PRIMARY KEY,
		name       TEXT    NOT NULL,
		applied_at TEXT    NOT NULL
	)`); err != nil {
		return fmt.Errorf("create _schema_version: %w", err)
	}

	// 查询当前已应用的最高版本
	var current int
	DB.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM _schema_version`).Scan(&current)

	// 若版本表为空但 rules 表已存在，说明是从旧版本升级上来的数据库，
	// 把所有现有迁移标记为已完成，不重复执行 DDL。
	if current == 0 {
		var tableCount int
		DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rules'`).Scan(&tableCount)
		if tableCount > 0 {
			now := "legacy"
			for _, m := range versionedMigrations {
				DB.Exec(`INSERT OR IGNORE INTO _schema_version(version,name,applied_at) VALUES(?,?,?)`,
					m.version, m.name, now)
			}
			log.Printf("[db] 检测到旧版数据库，已标记 %d 个迁移为已完成", len(versionedMigrations))
			current = versionedMigrations[len(versionedMigrations)-1].version
		}
	}

	// 依次执行尚未应用的迁移
	for _, m := range versionedMigrations {
		if m.version <= current {
			continue
		}
		log.Printf("[db] 应用迁移 v%d: %s", m.version, m.name)
		for _, stmt := range m.sql {
			if _, err := DB.Exec(stmt); err != nil {
				// ALTER TABLE 字段已存在时静默跳过
				if len(stmt) > 11 && stmt[:11] == "ALTER TABLE" {
					continue
				}
				return fmt.Errorf("迁移 v%d (%s) 执行失败: %w", m.version, m.name, err)
			}
		}
		if _, err := DB.Exec(
			`INSERT INTO _schema_version(version,name,applied_at) VALUES(?,?,datetime('now','localtime'))`,
			m.version, m.name,
		); err != nil {
			return fmt.Errorf("记录迁移版本失败: %w", err)
		}
		log.Printf("[db] 迁移 v%d 完成", m.version)
	}

	// 默认系统设置（INSERT OR IGNORE 保证不覆盖用户已有配置）
	defaults := map[string]string{
		"nginx_worker_processes":     "auto",
		"nginx_worker_connections":   "1024",
		"nginx_keepalive_timeout":    "65",
		"nginx_client_max_body_size": "64m",
		"tencent_secret_id":          "",
		"tencent_secret_key":         "",
		"tencent_dns_region":         "ap-guangzhou",
		"sync_token":                 "",
		"sync_rules_token":           "",
		"sync_certs_token":           "",
		"slave_rules_enabled":        "1",
		"slave_certs_enabled":        "1",
		"slave_filter_enabled":       "1",
		"site_title":                 "AnkerYe - 流量管理平台",
		"cert_renew_disabled":        "0",
		"notify_mm_webhook":          "",
		"notify_email_to":            "",
		"notify_cert_fail":           "1",
		"notify_cert_success":        "0",
		"notify_server_down":         "1",
		"notify_server_up":           "0",
		"default_log_max_size":       "5M",
		"update_gitea_url":           "",
	}
	for k, v := range defaults {
		DB.Exec(`INSERT OR IGNORE INTO system_settings(k,v) VALUES(?,?)`, k, v)
	}
	return nil
}
