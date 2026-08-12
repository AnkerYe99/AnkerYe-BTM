package engine

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"ankerye-flow/config"
	"ankerye-flow/db"
)

var logWatched sync.Map // logFile → bool，已启动 tail goroutine

// EnsureFilterConf 启动时写入过滤配置（不重载 nginx）
func EnsureFilterConf() {
	conf, err := buildFilterConf()
	if err != nil {
		log.Printf("[filter] build conf error: %v", err)
		return
	}
	path := filepath.Join(config.Global.Nginx.ConfDir, "00-filter-http.conf")
	if err := os.WriteFile(path, []byte(conf), 0644); err != nil {
		log.Printf("[filter] write conf error: %v", err)
		return
	}
	log.Println("[filter] conf written:", path)
}

// ApplyFilter 重建过滤配置并重载 nginx
func ApplyFilter() error {
	conf, err := buildFilterConf()
	if err != nil {
		return err
	}
	path := filepath.Join(config.Global.Nginx.ConfDir, "00-filter-http.conf")
	if err := os.WriteFile(path, []byte(conf), 0644); err != nil {
		return fmt.Errorf("write filter conf: %w", err)
	}
	if out, err := exec.Command("sh", "-c", config.Global.Nginx.TestCmd).CombinedOutput(); err != nil {
		return fmt.Errorf("nginx -t: %s", out)
	}
	if out, err := exec.Command("sh", "-c", config.Global.Nginx.ReloadCmd).CombinedOutput(); err != nil {
		return fmt.Errorf("nginx reload: %s", out)
	}
	log.Println("[filter] applied and reloaded")
	return nil
}

func buildFilterConf() (string, error) {
	var sb strings.Builder
	sb.WriteString("# AnkerYe - Flow 过滤配置（自动生成，勿手动修改）\n")

	// Real IP 穿透：信任所有 BTM 节点，让 $remote_addr 还原为真实客户端 IP
	sb.WriteString("# --- Real IP 穿透 ---\n")
	for _, s := range trustedSources {
		sb.WriteString(fmt.Sprintf("set_real_ip_from %s;  # %s\n", s.cidr, s.note))
	}
	sb.WriteString("real_ip_header    X-Real-IP;\n")
	sb.WriteString("real_ip_recursive on;\n\n")

	// 白名单 geo
	sb.WriteString("geo $__nf_wl {\n    default 0;\n")
	rows, _ := db.DB.Query(`SELECT value FROM filter_whitelist WHERE type IN ('ip','cidr') AND enabled=1`)
	if rows != nil {
		for rows.Next() {
			var v string
			rows.Scan(&v)
			sb.WriteString(fmt.Sprintf("    %s 1;\n", v))
		}
		rows.Close()
	}
	sb.WriteString("}\n\n")

	// 黑名单 IP/CIDR geo
	sb.WriteString("geo $__nf_bl_ip {\n    default 0;\n")
	rows, _ = db.DB.Query(`SELECT value FROM filter_blacklist WHERE type IN ('ip','cidr') AND enabled=1`)
	if rows != nil {
		for rows.Next() {
			var v string
			rows.Scan(&v)
			sb.WriteString(fmt.Sprintf("    %s 1;\n", v))
		}
		rows.Close()
	}
	sb.WriteString("}\n\n")

	// 黑名单路径 map
	sb.WriteString("map $request_uri $__nf_bl_path {\n    default 0;\n")
	rows, _ = db.DB.Query(`SELECT value FROM filter_blacklist WHERE type='path' AND enabled=1`)
	if rows != nil {
		for rows.Next() {
			var v string
			rows.Scan(&v)
			sb.WriteString(fmt.Sprintf("    %s 1;\n", v))
		}
		rows.Close()
	}
	sb.WriteString("}\n\n")

	// 黑名单 UA map
	sb.WriteString("map $http_user_agent $__nf_bl_ua {\n    default 0;\n")
	rows, _ = db.DB.Query(`SELECT value FROM filter_blacklist WHERE type='ua' AND enabled=1`)
	if rows != nil {
		for rows.Next() {
			var v string
			rows.Scan(&v)
			sb.WriteString(fmt.Sprintf("    %s 1;\n", v))
		}
		rows.Close()
	}
	sb.WriteString("}\n\n")

	// 黑名单方法 map（拦截非标准/危险 HTTP 方法）
	sb.WriteString("map $request_method $__nf_bl_method {\n    default 0;\n")
	rows, _ = db.DB.Query(`SELECT value FROM filter_blacklist WHERE type='method' AND enabled=1`)
	if rows != nil {
		for rows.Next() {
			var v string
			rows.Scan(&v)
			sb.WriteString(fmt.Sprintf("    \"%s\" 1;\n", v))
		}
		rows.Close()
	}
	sb.WriteString("}\n\n")

	// 被拦截时不写 capture log（$__nf_block=1 → 空字符串，access_log if= 不写入）
	// $__nf_block 由各 http server 块内的 set 指令定义；无任何启用的 http 规则时
	// 该变量不存在，nginx 会以 unknown "__nf_block" variable 拒绝启动 —— 故条件生成
	var httpRuleCnt int
	db.DB.QueryRow(`SELECT COUNT(*) FROM rules WHERE protocol='http' AND status=1`).Scan(&httpRuleCnt)
	if httpRuleCnt > 0 {
		sb.WriteString("map $__nf_block $__nf_do_capture {\n    1  \"\";\n    default \"1\";\n}\n")
	}

	return sb.String(), nil
}

// StartAutoBlockWorker 实时 tail 访问日志，将触发 444 的 IP 立即写入黑名单
func StartAutoBlockWorker() {
	scanAndWatch := func() {
		pattern := filepath.Join(config.Global.Nginx.LogDir, "rule_*_access.log")
		files, _ := filepath.Glob(pattern)
		for _, f := range files {
			if _, loaded := logWatched.LoadOrStore(f, true); !loaded {
				log.Printf("[filter] tailing log: %s", f)
				go tailLog(f)
			}
		}
	}
	scanAndWatch()
	// 每 5 分钟检查是否有新增规则日志文件
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		scanAndWatch()
	}
}

func tailLog(logFile string) {
	var offset int64
	stateKey := "filter::" + logFile
	// 从 DB 恢复上次读取位置，避免服务重启后重新处理历史日志
	db.DB.QueryRow(`SELECT offset FROM log_parse_state WHERE log_file=?`, stateKey).Scan(&offset)

	for {
		f, err := os.Open(logFile)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		info, statErr := f.Stat()
		if statErr != nil {
			f.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		if info.Size() < offset {
			offset = 0 // 日志轮转，从头读
		}
		f.Seek(offset, 0)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			processAutoBlock(scanner.Text())
		}
		newOffset, _ := f.Seek(0, 1)
		f.Close()
		if newOffset != offset {
			offset = newOffset
			db.DB.Exec(`INSERT INTO log_parse_state(log_file,inode,offset) VALUES(?,0,?)
				ON CONFLICT(log_file) DO UPDATE SET offset=excluded.offset`,
				stateKey, offset)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func processAutoBlock(line string) {
	if !strings.Contains(line, " 444 ") {
		return
	}
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}
	ip := parts[0]
	if net.ParseIP(ip) == nil {
		return
	}
	// #3: 白名单 / 可信来源（set_real_ip_from 信任的 BTM 节点、内网代理）不自动封锁
	if isIPWhitelisted(ip) || isIPTrusted(ip) {
		return
	}
	reason := parseTriggerReason(line)
	// #14: 只有命中具体 path/ua/method/cidr 规则才自动封锁。
	// "触发：ip"（该 IP 已在黑名单、这次 444 是本地拦截自身造成）与泛化"触发过滤规则"（无具体命中）
	// 一律不再封——否则已封 IP 的每个被 444 的请求都会重复刷新封锁，形成永不过期的自反馈死循环。
	if !isSpecificRuleReason(reason) {
		return
	}
	note := "自动封锁（" + reason + "）"
	// #4: 自动封锁默认 6 小时 TTL，到期由 StartExpiryWorker 自动解封
	res, err := db.DB.Exec(
		`INSERT OR IGNORE INTO filter_blacklist(type,value,note,auto_added,expires_at)
		 VALUES(?,?,?,1,datetime('now','localtime','+6 hours'))`,
		"ip", ip, note,
	)
	if err != nil {
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("[filter] auto-blocked IP: %s | %s（6h TTL）", ip, note)
		go ApplyFilter()
	}
}

func isIPWhitelisted(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	var count int
	db.DB.QueryRow(`SELECT COUNT(*) FROM filter_whitelist WHERE type='ip' AND value=? AND enabled=1`, ip).Scan(&count)
	if count > 0 {
		return true
	}
	rows, _ := db.DB.Query(`SELECT value FROM filter_whitelist WHERE type='cidr' AND enabled=1`)
	if rows == nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		rows.Scan(&v)
		_, cidr, err := net.ParseCIDR(v)
		if err == nil && cidr.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// isSpecificRuleReason 判断触发原因是否命中了具体的 path/ua/method/cidr 规则。
// 仅这些才应触发自动封锁；"触发：ip"（已封 IP 自身被 444）与泛化"触发过滤规则"（无具体命中）不封，防自反馈循环(#14)。
func isSpecificRuleReason(reason string) bool {
	return strings.HasPrefix(reason, "触发：path") ||
		strings.HasPrefix(reason, "触发：ua") ||
		strings.HasPrefix(reason, "触发：method") ||
		strings.HasPrefix(reason, "触发：cidr")
}

// trustedSources 是所有 BTM 节点与内网代理的唯一来源清单，两处共用：
//  1. nginx 的 set_real_ip_from —— 还原 $remote_addr 为访客真实 IP
//  2. isIPTrusted —— 可信来源不自动封锁(#3)
//
// ⚠️ 这两处以前是两份各自维护的列表，结果 1107 换 IP 后只改了一份，
// 另一份留着作废的 42.2.33.138，导致判断认错来源。现已合并，改这一处即可。
// 这些来源是基础设施（背后可能承载大量真实用户），绝不应因某个用户的请求被整段封掉。
var trustedSources = []struct{ cidr, note string }{
	{"10.0.0.0/8", "内网"},
	{"172.16.0.0/12", "Docker/内网"},
	{"61.92.38.202/32", "1107（原 42.2.33.138 已作废）"},
	{"47.239.137.202/32", "ALHK"},
	{"8.159.153.184/32", "ALSH"},
	{"81.69.185.252/32", "TXSH"},
	{"161.153.89.153/32", "甲骨文1"},
	{"141.147.179.9/32", "甲骨文2"},
	{"158.101.89.59/32", "甲骨文3"},
	{"129.146.250.212/32", "甲骨文4"},
	{"161.118.230.77/32", "甲骨文5/SG1"},
	{"168.138.161.90/32", "甲骨文6/SG2"},
}

// isIPTrusted 判断 IP 是否为可信来源（BTM 节点/内网代理），可信来源不自动封锁(#3)。
func isIPTrusted(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, s := range trustedSources {
		if _, cidr, err := net.ParseCIDR(s.cidr); err == nil && cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// StartExpiryWorker 定期清理过期的自动封锁（#4 TTL）：每 5 分钟删除 expires_at 已过期的 auto_added 条目并重载。
// 手动条目（expires_at 为 NULL）永不过期。
func StartExpiryWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		res, err := db.DB.Exec(
			`DELETE FROM filter_blacklist WHERE auto_added=1 AND expires_at IS NOT NULL AND expires_at < datetime('now','localtime')`)
		if err != nil {
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("[filter] TTL 到期自动解封 %d 个 IP", n)
			ApplyFilter()
		}
	}
}

// parseLogFields 从 nginx 日志行中解析 method、path、ua
// 格式: IP - user [time] "METHOD PATH PROTO" status bytes "referer" "ua" upstream
func parseLogFields(line string) (method, path, ua string) {
	parts := strings.SplitN(line, `"`, -1)
	if len(parts) >= 2 {
		req := strings.Fields(parts[1])
		if len(req) >= 1 {
			method = req[0]
		}
		if len(req) >= 2 {
			path = req[1]
		}
	}
	if len(parts) >= 6 {
		ua = parts[5]
	}
	return
}

// matchNginxPattern 匹配 nginx map 指令的模式（~* 不区分大小写正则，~ 正则，其余精确）
func matchNginxPattern(pattern, value string) bool {
	if strings.HasPrefix(pattern, "~*") {
		re, err := regexp.Compile(`(?i)` + pattern[2:])
		if err != nil {
			return false
		}
		return re.MatchString(value)
	}
	if strings.HasPrefix(pattern, "~") {
		re, err := regexp.Compile(pattern[1:])
		if err != nil {
			return false
		}
		return re.MatchString(value)
	}
	return strings.EqualFold(pattern, value)
}

// parseTriggerReason 查询黑名单规则，返回触发原因描述
func parseTriggerReason(line string) string {
	parts := strings.Fields(line)
	var srcIP string
	if len(parts) > 0 {
		srcIP = parts[0]
	}
	method, path, ua := parseLogFields(line)

	// 检查 IP 精确匹配
	if srcIP != "" {
		rows, _ := db.DB.Query(`SELECT value FROM filter_blacklist WHERE type='ip' AND enabled=1`)
		if rows != nil {
			for rows.Next() {
				var v string
				rows.Scan(&v)
				if v == srcIP {
					rows.Close()
					return fmt.Sprintf("触发：ip %s", v)
				}
			}
			rows.Close()
		}
	}

	// 检查 CIDR 包含
	if srcIP != "" {
		ip := net.ParseIP(srcIP)
		if ip != nil {
			rows, _ := db.DB.Query(`SELECT value FROM filter_blacklist WHERE type='cidr' AND enabled=1`)
			if rows != nil {
				for rows.Next() {
					var v string
					rows.Scan(&v)
					_, cidr, err := net.ParseCIDR(v)
					if err == nil && cidr.Contains(ip) {
						rows.Close()
						return fmt.Sprintf("触发：cidr %s", v)
					}
				}
				rows.Close()
			}
		}
	}

	// 检查 method
	if method != "" {
		rows, _ := db.DB.Query(`SELECT value FROM filter_blacklist WHERE type='method' AND enabled=1`)
		if rows != nil {
			for rows.Next() {
				var v string
				rows.Scan(&v)
				if strings.EqualFold(v, method) {
					rows.Close()
					return fmt.Sprintf("触发：method %s", method)
				}
			}
			rows.Close()
		}
	}

	// 检查 path
	if path != "" {
		rows, _ := db.DB.Query(`SELECT value FROM filter_blacklist WHERE type='path' AND enabled=1`)
		if rows != nil {
			for rows.Next() {
				var v string
				rows.Scan(&v)
				if matchNginxPattern(v, path) {
					rows.Close()
					return fmt.Sprintf("触发：path %s", v)
				}
			}
			rows.Close()
		}
	}

	// 检查 ua
	if ua != "" {
		rows, _ := db.DB.Query(`SELECT value FROM filter_blacklist WHERE type='ua' AND enabled=1`)
		if rows != nil {
			for rows.Next() {
				var v string
				rows.Scan(&v)
				if matchNginxPattern(v, ua) {
					rows.Close()
					return fmt.Sprintf("触发：ua %s", v)
				}
			}
			rows.Close()
		}
	}

	// fallback：显示请求信息
	if method != "" && path != "" {
		return fmt.Sprintf("触发过滤规则 [%s %s]", method, path)
	}
	return "触发过滤规则"
}
