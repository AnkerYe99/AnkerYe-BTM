package engine

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"ankerye-flow/config"
	"ankerye-flow/db"
	"ankerye-flow/model"
)

// formatBackend 给 upstream server 拼地址：IPv6 需要用中括号
func formatBackend(addr string, port int) string {
	// 判断是否为 IPv6 字面量（包含冒号且不是 host:port 形式）
	if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
		return fmt.Sprintf("[%s]:%d", addr, port)
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

// renderListen 根据 listen_stack 生成 listen 指令
// flags: 追加的修饰词（如 "ssl", "udp"）
func renderListen(stack string, port int, flags string) string {
	if stack == "" {
		stack = "both"
	}
	f := ""
	if flags != "" {
		f = " " + flags
	}
	switch stack {
	case "v4":
		return fmt.Sprintf("    listen 0.0.0.0:%d%s;\n", port, f)
	case "v6":
		return fmt.Sprintf("    listen [::]:%d%s;\n", port, f)
	default: // both
		return fmt.Sprintf("    listen 0.0.0.0:%d%s;\n    listen [::]:%d%s;\n", port, f, port, f)
	}
}

// 读取规则（含节点和证书域名）
func LoadRule(ruleID int64) (*model.Rule, error) {
	r := &model.Rule{}
	var certID sql.NullInt64
	var stack sql.NullString
	var httpsPort sql.NullInt64
	row := db.DB.QueryRow(`SELECT id,name,protocol,listen_port,IFNULL(listen_stack,'both'),
		https_enabled,https_port,server_name,lb_method,ssl_cert_id,ssl_redirect,
		hc_enabled,hc_interval,hc_timeout,hc_path,IFNULL(hc_host,''),hc_rise,hc_fall,
		log_max_size,IFNULL(capture_max_size,'5M'),custom_config,IFNULL(capture_body,0),status,created_at,updated_at
		FROM rules WHERE id=?`, ruleID)
	err := row.Scan(&r.ID, &r.Name, &r.Protocol, &r.ListenPort, &stack,
		&r.HTTPSEnabled, &httpsPort, &r.ServerName, &r.LBMethod,
		&certID, &r.SSLRedirect, &r.HCEnabled, &r.HCInterval, &r.HCTimeout, &r.HCPath, &r.HCHost,
		&r.HCRise, &r.HCFall, &r.LogMaxSize, &r.CaptureMaxSize, &r.CustomConfig, &r.CaptureBody, &r.Status, &r.CreatedAt, &r.UpdatedAt)
	if stack.Valid {
		r.ListenStack = stack.String
	}
	if r.ListenStack == "" {
		r.ListenStack = "both"
	}
	if httpsPort.Valid {
		v := int(httpsPort.Int64)
		r.HTTPSPort = &v
	}
	if err != nil {
		return nil, err
	}
	if certID.Valid {
		r.SSLCertID = certID
		v := certID.Int64
		r.SSLCertIDVal = &v
		// 加载证书域名（用于nginx配置文件路径）
		var domain string
		db.DB.QueryRow(`SELECT domain FROM ssl_certs WHERE id=?`, certID.Int64).Scan(&domain)
		r.Domain = domain
	}
	// 加载节点
	rows, err := db.DB.Query(`SELECT id,rule_id,address,port,weight,state,fail_count,success_count,
		IFNULL(last_check_at,''),IFNULL(last_err,''),created_at FROM upstream_servers
		WHERE rule_id=? ORDER BY id`, ruleID)
	if err != nil {
		return r, err
	}
	for rows.Next() {
		var s model.Server
		rows.Scan(&s.ID, &s.RuleID, &s.Address, &s.Port, &s.Weight, &s.State,
			&s.FailCount, &s.SuccessCount, &s.LastCheckAt, &s.LastErr, &s.CreatedAt)
		r.Servers = append(r.Servers, s)
	}
	rows.Close()
	return r, nil
}

// 渲染 nginx 配置文本
func RenderRule(r *model.Rule) (string, error) {
	upServers := []model.Server{}
	for _, s := range r.Servers {
		if s.State == "up" {
			upServers = append(upServers, s)
		}
	}
	// 全部 down：保留最后一个作 fallback
	if len(upServers) == 0 && len(r.Servers) > 0 {
		upServers = []model.Server{r.Servers[len(r.Servers)-1]}
	}

	switch r.Protocol {
	case "http":
		return renderHTTP(r, upServers), nil
	case "tcp", "udp", "tcpudp":
		return renderStream(r, upServers), nil
	}
	return "", fmt.Errorf("unknown protocol: %s", r.Protocol)
}

func filterCheckBlock() string {
	return `    # AnkerYe - Flow 全局过滤（白名单优先级高于黑名单）
    set $__nf_block 0;
    if ($__nf_bl_ip)     { set $__nf_block 1; }
    if ($__nf_bl_path)   { set $__nf_block 1; }
    if ($__nf_bl_ua)     { set $__nf_block 1; }
    if ($__nf_bl_method) { set $__nf_block 1; }
    if ($__nf_wl)        { set $__nf_block 0; }
`
}

func proxyBlock(id int64) string {
	return fmt.Sprintf(`    location / {
        if ($__nf_block) {
            return 444;
        }
        proxy_pass http://nf_%d;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 5s;
        proxy_read_timeout 60s;
    }
`, id)
}

func renderHTTP(r *model.Rule, servers []model.Server) string {
	var sb strings.Builder
	sn := strings.ToLower(strings.TrimSpace(r.ServerName))
	if sn == "" {
		sn = "_"
	}

	sb.WriteString(fmt.Sprintf("# AnkerYe - 流量管理 rule %d: %s (stack=%s)\n", r.ID, r.Name, r.ListenStack))

	// upstream block
	sb.WriteString(fmt.Sprintf("upstream nf_%d {\n", r.ID))
	if r.LBMethod == "ip_hash" {
		sb.WriteString("    ip_hash;\n")
	} else if r.LBMethod == "least_conn" {
		sb.WriteString("    least_conn;\n")
	}
	for _, s := range servers {
		sb.WriteString(fmt.Sprintf("    server %s weight=%d;\n", formatBackend(s.Address, s.Port), s.Weight))
	}
	sb.WriteString("    keepalive 32;\n}\n\n")

	// HTTP server block（listen_port=0 表示纯 HTTPS 模式，跳过 HTTP 块）
	if r.ListenPort > 0 {
		sb.WriteString("server {\n")
		sb.WriteString(renderListen(r.ListenStack, r.ListenPort, ""))
		sb.WriteString(fmt.Sprintf("    server_name %s;\n", sn))
		sb.WriteString(fmt.Sprintf("    access_log %s/rule_%d_access.log ankerye_flow;\n", config.Global.Nginx.LogDir, r.ID))
		if r.CaptureBody == 1 {
			sb.WriteString(fmt.Sprintf("    access_log %s/rule_%d_capture.log ankerye_capture if=$__nf_do_capture;\n", config.Global.Nginx.LogDir, r.ID))
		}
		sb.WriteString(fmt.Sprintf("    error_log  %s/rule_%d_error.log warn;\n", config.Global.Nginx.LogDir, r.ID))

		sb.WriteString(filterCheckBlock())
		if r.HTTPSEnabled == 1 && r.SSLRedirect == 1 && r.HTTPSPort != nil {
			if *r.HTTPSPort == 443 {
				sb.WriteString("    return 301 https://$host$request_uri;\n")
			} else {
				sb.WriteString(fmt.Sprintf("    return 301 https://$host:%d$request_uri;\n", *r.HTTPSPort))
			}
		} else {
			sb.WriteString(proxyBlock(r.ID))
			if r.CustomConfig != "" {
				sb.WriteString("    " + r.CustomConfig + "\n")
			}
		}
		sb.WriteString("}\n")
	}

	// HTTPS server block（仅在启用时生成）
	if r.HTTPSEnabled == 1 && r.HTTPSPort != nil && r.Domain != "" {
		sb.WriteString("\nserver {\n")
		sb.WriteString(renderListen(r.ListenStack, *r.HTTPSPort, "ssl"))
		sb.WriteString(fmt.Sprintf("    server_name %s;\n", sn))
		sb.WriteString(fmt.Sprintf("    ssl_certificate     %s/%s/fullchain.pem;\n", config.Global.Nginx.CertDir, r.Domain))
		sb.WriteString(fmt.Sprintf("    ssl_certificate_key %s/%s/privkey.pem;\n", config.Global.Nginx.CertDir, r.Domain))
		sb.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n")
		sb.WriteString("    ssl_ciphers HIGH:!aNULL:!MD5;\n")
		sb.WriteString("    ssl_session_cache shared:SSL:10m;\n")
		sb.WriteString(fmt.Sprintf("    access_log %s/rule_%d_access.log ankerye_flow;\n", config.Global.Nginx.LogDir, r.ID))
		if r.CaptureBody == 1 {
			sb.WriteString(fmt.Sprintf("    access_log %s/rule_%d_capture.log ankerye_capture if=$__nf_do_capture;\n", config.Global.Nginx.LogDir, r.ID))
		}
		sb.WriteString(fmt.Sprintf("    error_log  %s/rule_%d_error.log warn;\n", config.Global.Nginx.LogDir, r.ID))
		sb.WriteString(filterCheckBlock())
		sb.WriteString(proxyBlock(r.ID))
		if r.CustomConfig != "" {
			sb.WriteString("    " + r.CustomConfig + "\n")
		}
		sb.WriteString("}\n")
	}

	return sb.String()
}

func renderStream(r *model.Rule, servers []model.Server) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# AnkerYe - 流量管理 rule %d: %s (stack=%s)\n", r.ID, r.Name, r.ListenStack))
	sb.WriteString(fmt.Sprintf("upstream nf_stream_%d {\n", r.ID))
	if r.LBMethod == "ip_hash" {
		sb.WriteString("    hash $remote_addr consistent;\n")
	} else if r.LBMethod == "least_conn" {
		sb.WriteString("    least_conn;\n")
	}
	for _, s := range servers {
		sb.WriteString(fmt.Sprintf("    server %s weight=%d;\n", formatBackend(s.Address, s.Port), s.Weight))
	}
	sb.WriteString("}\n")

	// TCP+UDP 模式：生成两个 server 块，共用同一个 upstream
	if r.Protocol == "tcpudp" {
		// TCP server block
		sb.WriteString("server {\n")
		sb.WriteString(renderListen(r.ListenStack, r.ListenPort, ""))
		sb.WriteString("    proxy_timeout 600s;\n")
		sb.WriteString("    proxy_connect_timeout 5s;\n")
		sb.WriteString(fmt.Sprintf("    proxy_pass nf_stream_%d;\n", r.ID))
		sb.WriteString(fmt.Sprintf("    access_log %s/rule_%d_stream.log basic;\n", config.Global.Nginx.LogDir, r.ID))
		sb.WriteString("}\n")
		// UDP server block
		sb.WriteString("server {\n")
		sb.WriteString(renderListen(r.ListenStack, r.ListenPort, "udp"))
		sb.WriteString("    proxy_timeout 1m;\n")
		sb.WriteString(fmt.Sprintf("    proxy_pass nf_stream_%d;\n", r.ID))
		sb.WriteString(fmt.Sprintf("    access_log %s/rule_%d_stream.log basic;\n", config.Global.Nginx.LogDir, r.ID))
		sb.WriteString("}\n")
		return sb.String()
	}

	sb.WriteString("server {\n")
	if r.Protocol == "udp" {
		sb.WriteString(renderListen(r.ListenStack, r.ListenPort, "udp"))
		sb.WriteString("    proxy_timeout 1m;\n")
	} else {
		sb.WriteString(renderListen(r.ListenStack, r.ListenPort, ""))
		sb.WriteString("    proxy_timeout 600s;\n")
		sb.WriteString("    proxy_connect_timeout 5s;\n")
	}
	sb.WriteString(fmt.Sprintf("    proxy_pass nf_stream_%d;\n", r.ID))
	sb.WriteString(fmt.Sprintf("    access_log %s/rule_%d_stream.log basic;\n", config.Global.Nginx.LogDir, r.ID))
	sb.WriteString("}\n")
	return sb.String()
}

// isNamedSN returns true if server_name contains real domain names (not just _ or empty).
func isNamedSN(sn string) bool {
	for _, d := range strings.Fields(sn) {
		if d != "_" && d != "" {
			return true
		}
	}
	return false
}

// SyncPortDefaults keeps catch-all default_server blocks up to date.
// For every HTTP port that has named-domain rules but no wildcard rule,
// it writes a default_server block returning 403 so unmatched Host headers are rejected.
// HTTPS ports are skipped — TLS handshake failure is the natural reject.
func SyncPortDefaults() {
	rows, err := db.DB.Query(`SELECT listen_port, listen_stack, https_enabled, https_port, server_name
		FROM rules WHERE protocol='http' AND status=1`)
	if err != nil {
		return
	}
	type portState struct {
		stack       string
		hasWildcard bool
		hasNamed    bool
		isHTTPS     bool
	}
	ports := map[int]*portState{}
	ensureHTTP := func(port int, stack string) *portState {
		if _, ok := ports[port]; !ok {
			ports[port] = &portState{stack: stack}
		}
		return ports[port]
	}
	for rows.Next() {
		var port, httpsEnabled int
		var stack, sn string
		var httpsPort sql.NullInt64
		rows.Scan(&port, &stack, &httpsEnabled, &httpsPort, &sn)
		if stack == "" {
			stack = "both"
		}
		if port == 0 {
			continue // 纯 HTTPS 模式，无 HTTP 端口，跳过
		}
		named := isNamedSN(sn)
		ps := ensureHTTP(port, stack)
		if named {
			ps.hasNamed = true
		} else {
			ps.hasWildcard = true
		}
		// Mark HTTPS port — we won't generate a catch-all for it
		if httpsEnabled == 1 && httpsPort.Valid {
			hp := int(httpsPort.Int64)
			if _, ok := ports[hp]; !ok {
				ports[hp] = &portState{stack: stack, isHTTPS: true}
			}
		}
	}
	rows.Close()

	for port, ps := range ports {
		path := filepath.Join(config.Global.Nginx.ConfDir, fmt.Sprintf("default-%d-http.conf", port))
		if !ps.isHTTPS && ps.hasNamed && !ps.hasWildcard {
			// Use default_server so nginx routes unmatched requests here
			content := fmt.Sprintf("# Auto catch-all: reject unmatched domains on port %d\nserver {\n", port)
			content += renderListen(ps.stack, port, "default_server")
			content += "    server_name _;\n"
			content += "    default_type text/html;\n"
			content += "    return 404 \"<!DOCTYPE html><html><head><meta charset=\\\"UTF-8\\\"><meta name=\\\"viewport\\\" content=\\\"width=device-width,initial-scale=1\\\"><title>网站不存在</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Hiragino Sans GB','Microsoft YaHei',sans-serif;background:#f0f2f5;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:16px}.card{background:#fff;border-radius:16px;padding:48px 40px;text-align:center;box-shadow:0 4px 24px rgba(0,0,0,.08);width:100%;max-width:400px}.icon{font-size:72px;line-height:1;margin-bottom:24px}.title{font-size:clamp(18px,4vw,22px);font-weight:600;color:#1a1a1a;margin-bottom:12px}.desc{font-size:clamp(13px,3.5vw,15px);color:#888;line-height:1.8}</style></head><body><div class=\\\"card\\\"><div class=\\\"icon\\\">🌐</div><div class=\\\"title\\\">网站不存在</div><div class=\\\"desc\\\">您访问的网站不存在<br>请确认域名是否正确</div></div></body></html>\";\n"
			content += "}\n"
			os.WriteFile(path, []byte(content), 0644)
		} else {
			os.Remove(path)
		}
	}

	// 清理已不存在端口的遗留文件
	existing, _ := filepath.Glob(filepath.Join(config.Global.Nginx.ConfDir, "default-*-http.conf"))
	for _, f := range existing {
		base := filepath.Base(f)
		var p int
		fmt.Sscanf(base, "default-%d-http.conf", &p)
		if _, ok := ports[p]; !ok {
			os.Remove(f)
		}
	}
}

// 写入 nginx 配置文件并 reload
func ApplyRule(ruleID int64) error {
	r, err := LoadRule(ruleID)
	if err != nil {
		return fmt.Errorf("加载规则失败: %w", err)
	}
	if r.Status != 1 {
		// 清理两种协议的 conf 文件（防止协议切换后残留）
		os.Remove(filepath.Join(config.Global.Nginx.ConfDir, fmt.Sprintf("%d-http.conf", r.ID)))
		os.Remove(filepath.Join(config.Global.Nginx.ConfDir, fmt.Sprintf("%d-stream.conf", r.ID)))
		SyncPortDefaults()
		return Reload()
	}
	text, err := RenderRule(r)
	if err != nil {
		return err
	}
	path := ruleFilePath(r.ID, r.Protocol)

	// 清理另一种协议的旧 conf 文件（处理 http↔tcp 协议切换）
	var oldPath string
	switch r.Protocol {
	case "http", "https":
		oldPath = filepath.Join(config.Global.Nginx.ConfDir, fmt.Sprintf("%d-stream.conf", r.ID))
	default:
		oldPath = filepath.Join(config.Global.Nginx.ConfDir, fmt.Sprintf("%d-http.conf", r.ID))
	}
	os.Remove(oldPath)

	// 原子写入
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0644); err != nil {
		return fmt.Errorf("写临时文件失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}

	// 同步端口默认拒绝块
	SyncPortDefaults()

	// 语法验证
	if out, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
		os.Remove(path)
		return fmt.Errorf("nginx 语法错误: %s", string(out))
	}
	// reload
	if err := smartReload(); err != nil {
		return err
	}

	WriteLogrotate(r)
	return nil
}

// 仅渲染不 reload（用于 preview）
func PreviewRule(ruleID int64) (string, error) {
	r, err := LoadRule(ruleID)
	if err != nil {
		return "", err
	}
	return RenderRule(r)
}

func DeleteRule(ruleID int64) error {
	removeRuleFiles(ruleID, "http")
	removeRuleFiles(ruleID, "tcp")
	os.Remove(filepath.Join(config.Global.Nginx.LogrotateDir, fmt.Sprintf("ankerye-flow-%d", ruleID)))
	logs, _ := filepath.Glob(filepath.Join(config.Global.Nginx.LogDir, fmt.Sprintf("rule_%d_*", ruleID)))
	for _, l := range logs {
		os.Remove(l)
	}
	SyncPortDefaults()
	return smartReload()
}

func removeRuleFiles(ruleID int64, protocol string) error {
	var suffix string
	switch protocol {
	case "http", "https":
		suffix = "http"
	case "tcp", "udp", "tcpudp":
		suffix = "stream"
	default:
		// 两种都删
		os.Remove(filepath.Join(config.Global.Nginx.ConfDir, fmt.Sprintf("%d-http.conf", ruleID)))
		os.Remove(filepath.Join(config.Global.Nginx.ConfDir, fmt.Sprintf("%d-stream.conf", ruleID)))
		return nil
	}
	return os.Remove(filepath.Join(config.Global.Nginx.ConfDir, fmt.Sprintf("%d-%s.conf", ruleID, suffix)))
}

func ruleFilePath(ruleID int64, protocol string) string {
	var suffix string
	switch protocol {
	case "http", "https":
		suffix = "http"
	default:
		suffix = "stream"
	}
	return filepath.Join(config.Global.Nginx.ConfDir, fmt.Sprintf("%d-%s.conf", ruleID, suffix))
}

// 测试当前所有 nginx 配置
func TestConfig() (string, error) {
	out, err := exec.Command("nginx", "-t").CombinedOutput()
	return string(out), err
}

// nginxRunning 检查 nginx 主进程是否存活
func nginxRunning() bool {
	data, err := os.ReadFile("/run/nginx.pid")
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

// smartReload 若 nginx 在跑则 reload，否则 start
func smartReload() error {
	var out []byte
	var err error
	if nginxRunning() {
		out, err = exec.Command("nginx", "-s", "reload").CombinedOutput()
		if err != nil {
			return fmt.Errorf("nginx reload 失败: %s", string(out))
		}
	} else {
		out, err = exec.Command("nginx").CombinedOutput()
		if err != nil {
			return fmt.Errorf("nginx 启动失败: %s", string(out))
		}
	}
	return nil
}

// reload 全部
func Reload() error {
	return smartReload()
}

// 应用所有启用的规则
func ApplyAll() error {
	// 清理 nginx 包安装时可能残留的默认 catch-all 配置，避免与 SyncPortDefaults 生成的冲突
	for _, f := range []string{
		"/etc/nginx/conf.d/default.conf",
		"/etc/nginx/sites-enabled/default",
	} {
		if _, err := os.Stat(f); err == nil {
			os.Remove(f)
		}
	}

	rows, err := db.DB.Query(`SELECT id FROM rules WHERE status=1 ORDER BY id`)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close() // 必须在调用 ApplyRule 之前关闭，避免 SQLite 单连接死锁
	for _, id := range ids {
		if err := ApplyRule(id); err != nil {
			return fmt.Errorf("rule %d: %w", id, err)
		}
	}
	return nil
}

// 导出所有规则 nginx 配置（主从同步用）
func ExportAll() (map[string]string, string, error) {
	result := map[string]string{}
	rows, err := db.DB.Query(`SELECT id,protocol FROM rules WHERE status=1 ORDER BY id`)
	if err != nil {
		return nil, "", err
	}
	var items []struct {
		id    int64
		proto string
	}
	for rows.Next() {
		var id int64
		var proto string
		rows.Scan(&id, &proto)
		items = append(items, struct {
			id    int64
			proto string
		}{id, proto})
	}
	rows.Close()
	for _, it := range items {
		r, err := LoadRule(it.id)
		if err != nil {
			continue
		}
		text, err := RenderRule(r)
		if err != nil {
			continue
		}
		var suffix string
		if it.proto == "http" || it.proto == "https" {
			suffix = "http"
		} else {
			suffix = "stream"
		}
		result[fmt.Sprintf("%d-%s.conf", it.id, suffix)] = text
	}
	// 计算版本哈希
	keys := make([]string, 0, len(result))
	for k := range result {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte(result[k]))
	}
	version := "sha256:" + hex.EncodeToString(h.Sum(nil))
	return result, version, nil
}

// 将证书写入磁盘
func WriteCert(domain, certPEM, keyPEM string) error {
	dir := filepath.Join(config.Global.Nginx.CertDir, domain)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(dir, "fullchain.pem"), []byte(certPEM), 0644); err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(dir, "privkey.pem"), []byte(keyPEM), 0600); err != nil {
		return err
	}
	return nil
}
