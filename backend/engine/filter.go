package engine

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ankerye-flow/config"
	"ankerye-flow/db"
)

var logOffsets sync.Map // logFile → int64 offset

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
	sb.WriteString("}\n")

	return sb.String(), nil
}

// StartAutoBlockWorker 每 60 秒扫描访问日志，将触发 444 的 IP 自动加黑名单
func StartAutoBlockWorker() {
	ticker := time.NewTicker(60 * time.Second)
	for range ticker.C {
		pattern := filepath.Join(config.Global.Nginx.LogDir, "rule_*_access.log")
		files, _ := filepath.Glob(pattern)
		changed := false
		for _, f := range files {
			n := scanLogFor444(f)
			if n > 0 {
				changed = true
			}
		}
		if changed {
			if err := ApplyFilter(); err != nil {
				log.Printf("[filter] auto-apply error: %v", err)
			}
		}
	}
}

func scanLogFor444(logFile string) int {
	f, err := os.Open(logFile)
	if err != nil {
		return 0
	}
	defer f.Close()

	var offset int64
	if v, ok := logOffsets.Load(logFile); ok {
		offset = v.(int64)
	}
	info, err := f.Stat()
	if err != nil {
		return 0
	}
	// 日志轮转：文件变小则从头开始
	if info.Size() < offset {
		offset = 0
	}
	f.Seek(offset, 0)

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, " 444 ") {
			continue
		}
		// 第一个字段是 $remote_addr
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		ip := parts[0]
		_, err := db.DB.Exec(
			`INSERT OR IGNORE INTO filter_blacklist(type,value,note,auto_added) VALUES(?,?,?,1)`,
			"ip", ip, "自动封锁（触发过滤规则）",
		)
		if err == nil {
			log.Printf("[filter] auto-blocked IP: %s", ip)
			count++
		}
	}

	newOffset, _ := f.Seek(0, 1)
	logOffsets.Store(logFile, newOffset)
	return count
}
