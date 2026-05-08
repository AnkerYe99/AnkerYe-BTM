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
	for _, cidr := range []string{
		"10.0.0.0/8",        // 内网
		"172.16.0.0/12",     // Docker/内网
		"42.2.33.138",       // 1107
		"47.239.137.202",    // ALHK
		"8.159.153.184",     // ALSH
		"81.69.185.252",     // TXSH
		"161.153.89.153",    // 甲骨文1
		"141.147.179.9",     // 甲骨文2
		"158.101.89.59",     // 甲骨文3
		"129.146.250.212",   // 甲骨文4
		"161.118.230.77",    // 甲骨文5/SG1
		"168.138.161.90",    // 甲骨文6/SG2
	} {
		sb.WriteString(fmt.Sprintf("set_real_ip_from %s;\n", cidr))
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
	sb.WriteString("map $__nf_block $__nf_do_capture {\n    1  \"\";\n    default \"1\";\n}\n")

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
		info, _ := f.Stat()
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
	// 白名单 IP 不自动封锁
	if isIPWhitelisted(ip) {
		return
	}
	note := "自动封锁（" + parseTriggerReason(line) + "）"
	res, err := db.DB.Exec(
		`INSERT OR IGNORE INTO filter_blacklist(type,value,note,auto_added) VALUES(?,?,?,1)`,
		"ip", ip, note,
	)
	if err != nil {
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("[filter] auto-blocked IP: %s | %s", ip, note)
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
